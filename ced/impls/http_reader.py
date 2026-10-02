"""可配置的 HTTP/1.1 消息分帧读取器 —— 参照实现的核心。

它**只**精确建模【消息分帧】相关行为：请求行、头部终止、
Content-Length / Transfer-Encoding 的解析与优先级、分块语法。

不追求覆盖 HTTP 全部语义 —— 耦合误差恰恰出在分帧上，
而分帧上"两个实现读出不同的字节数"就是请求走私原语。

每个 :class:`FramingPolicy` 对应一组真实世界中出现过的解析策略组合。
参照实现用于**内部基准**（自证平台有效）；真实产品通过 probe 协议接入。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

CRLF = b"\r\n"
_WS = b" \t"

#: Content-Length 的两种语法接受度
CL_CANONICAL = re.compile(rb"^(?:0|[1-9][0-9]*)$")
CL_LENIENT = re.compile(rb"^[ \t]*[+]?[0-9]+[ \t]*$")

#: 已知的 Transfer-Encoding 编码名
_KNOWN_TE = frozenset({"chunked", "identity", "gzip", "deflate", "compress"})


@dataclass(frozen=True)
class FramingPolicy:
    """一组分帧策略开关。每一项都是一个真实存在的实现差异点。"""

    name: str = "default"

    # CL 与 TE 同时出现时听谁的
    dual_policy: str = "cl"          # cl | te | reject
    # Content-Length 语法宽松度
    cl_syntax: str = "canonical"     # canonical | lenient
    # CL 重复且值不同时
    cl_duplicates: str = "reject"    # reject | first | last
    # TE 中未知 token 的处理
    te_unknown: str = "ignore"       # chunked | ignore
    # TE 编码名匹配是否大小写不敏感
    te_case: str = "fold"            # fold | sensitive
    # 行终止符
    line_terminator: str = "strict"  # strict | lenient
    # 头名与冒号之间出现空白（"Content-Length : 5"）
    header_name_ws: str = "trim"     # trim | reject
    # obs-fold 折行头
    obs_fold: str = "accept"         # accept | reject
    # 请求行解析
    request_line: str = "relaxed"    # strict | relaxed
    # 分块的分隔符
    chunk_terminator: str = "strict"  # strict | lenient


@dataclass
class ParseResult:
    """一次分帧解析的完整结果 —— 就是"这个实现对这段字节的理解"。"""

    ok: bool = True
    status: int = 200
    reason: str = "OK"
    consumed: int = 0                # 它认为这条请求占用了多少字节（最关键）
    body_len: int = 0                # 它认为的请求体长度（chunked 为解码后长度）
    cl: int | None = None            # 解析出的 Content-Length
    te: list[str] = field(default_factory=list)   # 解析出的 Transfer-Encoding 编码名
    framing_source: str = "none"     # cl | te | none | reject
    leftover: bytes = b""            # 它认为不属于本请求的剩余字节
    notes: list[str] = field(default_factory=list)

    def to_fields(self) -> dict:
        return {
            "accepted": self.ok,
            "status": self.status,
            "framing_source": self.framing_source,
            "cl": self.cl,
            "te": list(self.te),
            "body_len": self.body_len,
            "consumed": self.consumed,
            "leftover_len": len(self.leftover),
        }


# --------------------------------------------------------------------------- 内部工具

def _next_line(data: bytes, pos: int, strict: bool):
    """返回 (行内容, 下一行起点, 错误)。strict 下拒绝裸 LF。"""
    crlf = data.find(CRLF, pos)
    lf = data.find(b"\n", pos)
    if strict:
        if crlf == -1:
            return None, pos, "incomplete"
        if lf != -1 and lf < crlf:
            return None, pos, "bare_lf"
        return data[pos:crlf], crlf + 2, None
    if crlf != -1 and (lf == -1 or crlf <= lf):
        return data[pos:crlf], crlf + 2, None
    if lf != -1:
        return data[pos:lf], lf + 1, None
    return None, pos, "incomplete"


def _split_head(data: bytes, policy: FramingPolicy):
    """切出请求行 + 头字段。返回 (head_end, lines, error)。"""
    strict = policy.line_terminator == "strict"
    pos = 0
    lines: list[bytes] = []
    while True:
        line, nxt, err = _next_line(data, pos, strict)
        if err:
            return None, lines, err
        if line == b"":
            return nxt, lines, None
        lines.append(line)
        pos = nxt


def _parse_request_line(line: bytes, policy: FramingPolicy) -> str | None:
    """返回错误码；None 表示通过。"""
    if policy.request_line == "strict":
        parts = line.split(b" ")
        if len(parts) != 3:
            return "bad_request_line"
        method, target, version = parts
        if not method.isalpha() or method != method.upper():
            return "bad_method"
        if not version.startswith(b"HTTP/"):
            return "bad_version"
        if target.startswith(b"http://") or target.startswith(b"https://"):
            return "absolute_uri"
        return None
    parts = line.split()
    if len(parts) < 3:
        return "bad_request_line"
    if not parts[-1].startswith(b"HTTP/"):
        return "bad_version"
    return None


def _parse_chunked(data: bytes, pos: int, policy: FramingPolicy):
    """解析分块体。返回 (结束偏移, 解码长度, 错误)。"""
    lenient = policy.chunk_terminator == "lenient"
    decoded = 0
    while True:
        line, nxt, err = _next_line(data, pos, not lenient)
        if err:
            return pos, decoded, err
        size_part = line.split(b";", 1)[0].strip()
        try:
            size = int(size_part, 16)
        except ValueError:
            return pos, decoded, "bad_chunk_size"
        pos = nxt
        if size == 0:
            # 尾部字段：读到空行为止
            while True:
                trailer, tnxt, terr = _next_line(data, pos, not lenient)
                if terr:
                    return pos, decoded, terr
                pos = tnxt
                if trailer == b"":
                    return pos, decoded, None
        if len(data) < pos + size:
            return pos, decoded, "incomplete"
        pos += size
        decoded += size
        if lenient:
            if data[pos:pos + 2] == CRLF:
                pos += 2
            elif data[pos:pos + 1] == b"\n":
                pos += 1
            else:
                return pos, decoded, "bad_chunk_terminator"
        else:
            if data[pos:pos + 2] != CRLF:
                return pos, decoded, "bad_chunk_terminator"
            pos += 2


def _fail(reason: str, status: int = 400, consumed: int = 0,
          notes: list[str] | None = None) -> ParseResult:
    return ParseResult(ok=False, status=status, reason=reason, consumed=consumed,
                       framing_source="reject", notes=list(notes or []))


# --------------------------------------------------------------------------- 主入口

def parse_request(data: bytes, policy: FramingPolicy) -> ParseResult:
    """按 ``policy`` 解析一段字节流，返回该实现"理解"到的结果。"""
    notes: list[str] = []

    head_end, lines, err = _split_head(data, policy)
    if err:
        return _fail(err, notes=notes)
    if not lines:
        return _fail("empty_request", notes=notes)

    rl_err = _parse_request_line(lines[0], policy)
    if rl_err:
        return _fail(rl_err, notes=notes)

    # ---------------------------------------------------------------- 头字段
    headers: list[tuple[bytes, bytes]] = []
    for raw in lines[1:]:
        if raw[:1] in (b" ", b"\t"):
            if policy.obs_fold == "accept" and headers:
                name, value = headers[-1]
                headers[-1] = (name, value + b" " + raw.strip(_WS))
                continue
            return _fail("obs_fold", notes=notes)
        idx = raw.find(b":")
        if idx == -1:
            return _fail("bad_header", notes=notes)
        name, value = raw[:idx], raw[idx + 1:]
        if name != name.strip(_WS):
            if policy.header_name_ws == "reject":
                return _fail("bad_header_name", notes=notes)
            name = name.strip(_WS)
        if not name:
            return _fail("bad_header_name", notes=notes)
        headers.append((name.lower(), value.strip(_WS)))

    # ---------------------------------------------------------------- Content-Length
    cl: int | None = None
    cl_raw_values = [v for k, v in headers if k == b"content-length"]
    if cl_raw_values:
        pattern = CL_CANONICAL if policy.cl_syntax == "canonical" else CL_LENIENT
        parsed: list[int] = []
        for value in cl_raw_values:
            if not pattern.match(value):
                notes.append("unparsable-cl")
                continue
            parsed.append(int(value.strip(_WS).lstrip(b"+")))
        if parsed:
            if len(set(parsed)) > 1:
                if policy.cl_duplicates == "reject":
                    notes.append("conflicting-cl")
                    return _fail("conflicting_cl", notes=notes)
                cl = parsed[0] if policy.cl_duplicates == "first" else parsed[-1]
                notes.append("conflicting-cl-resolved")
            else:
                cl = parsed[0]

    # ---------------------------------------------------------------- Transfer-Encoding
    te_tokens: list[str] = []
    for key, value in headers:
        if key != b"transfer-encoding":
            continue
        for token in value.split(b","):
            token = token.strip(_WS)
            if token:
                te_tokens.append(token.decode("latin-1"))

    def _norm(token: str) -> str:
        return token.lower() if policy.te_case == "fold" else token

    has_chunked = any(_norm(t) == "chunked" for t in te_tokens)
    has_unknown = any(_norm(t) not in _KNOWN_TE for t in te_tokens)
    if has_unknown and policy.te_unknown == "chunked":
        has_chunked = True

    # ---------------------------------------------------------------- 决定分帧来源
    if cl is not None and te_tokens:
        if policy.dual_policy == "reject":
            return _fail("dual_cl_te", notes=notes)
        source = policy.dual_policy
    elif te_tokens:
        source = "te"
    elif cl is not None:
        source = "cl"
    else:
        source = "none"

    if source == "te" and not has_chunked:
        source = "none"

    if source == "reject":
        return _fail("dual_cl_te", notes=notes)

    # ---------------------------------------------------------------- 计算 consumed
    if source == "cl":
        assert cl is not None
        end = head_end + cl
        if len(data) < end:
            return ParseResult(ok=False, status=0, reason="incomplete_body",
                               consumed=0, cl=cl, te=te_tokens,
                               framing_source="cl", notes=notes + ["incomplete"])
        return ParseResult(ok=True, status=200, reason="OK", consumed=end,
                           body_len=cl, cl=cl, te=te_tokens,
                           framing_source="cl", leftover=data[end:], notes=notes)

    if source == "te":
        end, decoded, cerr = _parse_chunked(data, head_end, policy)
        if cerr:
            return ParseResult(ok=False, status=400, reason=cerr, consumed=0,
                               cl=cl, te=te_tokens, framing_source="te",
                               notes=notes + ["chunk:" + cerr])
        return ParseResult(ok=True, status=200, reason="OK", consumed=end,
                           body_len=decoded, cl=cl, te=te_tokens,
                           framing_source="te", leftover=data[end:], notes=notes)

    return ParseResult(ok=True, status=200, reason="OK", consumed=head_end,
                       body_len=0, cl=cl, te=te_tokens,
                       framing_source="none", leftover=data[head_end:], notes=notes)
