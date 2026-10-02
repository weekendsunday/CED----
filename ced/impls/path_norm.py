"""可配置的 URL 路径归一化读取器 —— 第二领域的参照实现内核。

与 ``http_reader.py`` 同构、只建模一件事：**同一段 target 字节，两个实现认为
它指向哪个资源**。

不追求覆盖 URL 全部语义 —— 耦合误差恰恰出在归一化上，而
"前置按 p1 判鉴权、后端按 p2 路由、p1 ≠ p2" 就是**鉴权绕过**原语。

每个 :class:`NormPolicy` 对应一组真实世界中出现过的归一化策略组合。
参照实现用于**内部基准**（自证平台有效）；真实产品通过 probe 协议接入。

归一化顺序（**刻意固定**：先解码、再做结构归一化）——
反过来的话 ``%2e%2e`` 就永远不会被当成 ``..`` 解算，双重编码类分歧也就消失了。
顺序本身不是策略开关，是这份内核的口径；写在这里以免被误当成实现细节。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

#: 十六进制数字（RFC 3986 §2.1：规范形式要求大写）
_HEX_UPPER = frozenset("0123456789ABCDEF")
_HEX_BOTH = _HEX_UPPER | frozenset("abcdef")

_DECODE_LAYERS = {"never": 0, "once": 1, "twice": 2}


@dataclass(frozen=True)
class NormPolicy:
    """一组路径归一化策略开关。每一项都是一个真实存在的实现差异点。"""

    name: str = "default"

    # `..` 段怎么处理（RFC 3986 §5.2.4 remove_dot_segments）
    dot_segments: str = "resolve"        # resolve | keep | reject
    # 百分号解码层数
    percent_decode: str = "never"        # never | once | twice
    # 百分号里十六进制的大小写接受度（RFC 3986 §2.1 只承认大写）
    percent_case: str = "strict"         # strict | lenient
    # 反斜杠：普通字符，还是路径分隔符
    backslash: str = "literal"           # literal | separator
    # 连续斜杠
    duplicate_slash: str = "keep"        # keep | collapse
    # 段尾的点与空格（Windows 文件系统会去掉）
    trailing_dot_space: str = "keep"     # keep | strip
    # 路径参数（Tomcat 等把 `;` 之后当矩阵参数）
    semicolon_params: str = "keep"       # keep | strip
    # 路径大小写
    case_fold: str = "sensitive"         # sensitive | insensitive
    #: 前置实际转发出去的形式。**只影响链路模型**，不影响单侧归一化。
    forward_form: str = "raw"            # raw | normalized


@dataclass
class NormResult:
    """一次路径归一化的完整结果 —— 就是"这个实现认为这段字节指向哪个资源"。"""

    ok: bool = True
    status: int = 200
    reason: str = "OK"
    #: 归一化后的路径（最关键）
    norm_path: str = "/"
    #: 原样保留的查询串（本内核不归一化查询）
    query: str = ""
    #: 归一化过程中是否真的吃掉了 `..`（即发生了跨目录）
    traversal: bool = False
    #: 归一化后的段数
    segments: int = 0
    #: 实际发生的解码层数（只数真正改变了字符串的那几层）
    decoded: int = 0
    notes: list[str] = field(default_factory=list)

    def to_fields(self) -> dict:
        return {
            "accepted": self.ok,
            "status": self.status,
            "norm_path": self.norm_path,
            "traversal": self.traversal,
            "segments": self.segments,
            "decoded": self.decoded,
        }


# --------------------------------------------------------------------------- 工具

def _is_hex(ch: str, case: str) -> bool:
    return ch in (_HEX_UPPER if case == "strict" else _HEX_BOTH)


def _decode_once(text: str, case: str) -> tuple[str, bool]:
    """解一层百分号编码。返回 (结果, 是否发生变化)。不合法/残缺的 % 原样保留。"""
    out: list[str] = []
    changed = False
    i = 0
    n = len(text)
    while i < n:
        # 需要 "%" + 两位十六进制，即 i+3 <= n
        if (text[i] == "%" and i + 3 <= n
                and _is_hex(text[i + 1], case) and _is_hex(text[i + 2], case)):
            out.append(chr(int(text[i + 1:i + 3], 16)))
            i += 3
            changed = True
        else:
            out.append(text[i])
            i += 1
    return "".join(out), changed


def _decode(text: str, layers: int, case: str) -> tuple[str, int]:
    """按层数解码，返回 (结果, 真正生效的层数)。"""
    done = 0
    for _ in range(layers):
        text, changed = _decode_once(text, case)
        if not changed:
            break
        done += 1
    return text, done


def _remove_dot_segments(path: str) -> tuple[str, bool]:
    """RFC 3986 §5.2.4。返回 (结果, 是否**真的**往上走了一层)。

    `traversal` 只在真的弹掉了一个**非根**段时才为真：
    根目录下的 `..`（如 `/..`）是空操作，不构成跨目录 ——
    否则会凭空造出一批"字符串不同、资源相同"的安全级发现（有测试守着这条）。
    """
    out: list[str] = []
    traversal = False
    for segment in path.split("/"):
        if segment == ".":
            continue
        if segment == "..":
            if out and out[-1] != "":       # 有真实段可弹，才算往上走
                out.pop()
                traversal = True
            continue
        out.append(segment)
    # path 以 "/" 开头时，split 的首元素是空串 —— 它代表根，必须留下
    joined = "/".join(out)
    return joined, traversal


def _strip_semicolon_params(path: str) -> str:
    """去掉每个段里 `;` 之后的部分（矩阵参数）。"""
    return "/".join(seg.split(";", 1)[0] for seg in path.split("/"))


def _strip_trailing_dot_space(path: str) -> str:
    """去掉每个段尾部的点与空格（Windows 文件系统的行为）。

    **只作用于普通段**：`.` 与 `..` 是点段本身，不是"尾部有点的段"。
    对它们做 rstrip 会把 `..` 变成空段 —— 那不是这个开关的语义，
    还会凭空造出一个假的遍历分歧（有测试守着这条）。
    """
    out: list[str] = []
    for seg in path.split("/"):
        out.append(seg if seg in (".", "..") else seg.rstrip(". "))
    return "/".join(out)


_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")


def lower_preserving_escapes(path: str) -> str:
    """小写化，但 `%XX` 转义原样保留。

    真实的路径大小写归一化（大小写不敏感的文件系统 / 路由表）不会改写转义本身；
    把 `%2E` 小写成 `%2e` 只会制造不真实的噪声。

    消融实验也用它：把「大小写」这个承载者抹掉时，不该顺手改变解码行为。
    """
    out: list[str] = []
    pos = 0
    for match in _ESCAPE.finditer(path):
        out.append(path[pos:match.start()].lower())
        out.append(match.group(0))
        pos = match.end()
    out.append(path[pos:].lower())
    return "".join(out)


def _collapse_slashes(path: str) -> str:
    return re.sub(r"/{2,}", "/", path)


def _segments_of(path: str) -> int:
    return len([s for s in path.split("/") if s])


# --------------------------------------------------------------------------- 主入口

def normalize_target(raw_target: bytes, policy: NormPolicy) -> NormResult:
    """按 ``policy`` 归一化一个请求目标（origin-form / absolute-form 均可）。

    ``raw_target`` 是请求行里 method 与 version 之间那段字节的**原样**内容。
    """
    text = raw_target.decode("latin-1")
    path, sep, query = text.partition("?")

    notes: list[str] = []

    # ① 先解码（顺序刻意固定，见模块 docstring）
    layers = _DECODE_LAYERS.get(policy.percent_decode, 0)
    path, decoded = _decode(path, layers, policy.percent_case)

    # ② 结构归一化
    if policy.backslash == "separator":
        path = path.replace("\\", "/")
    if policy.duplicate_slash == "collapse":
        path = _collapse_slashes(path)
    if policy.semicolon_params == "strip":
        path = _strip_semicolon_params(path)
    if policy.trailing_dot_space == "strip":
        path = _strip_trailing_dot_space(path)

    traversal = False
    if policy.dot_segments == "reject" and ".." in path.split("/"):
        return NormResult(ok=False, status=400, reason="dot_segment",
                          norm_path=path, query=query, traversal=False,
                          segments=_segments_of(path), decoded=decoded,
                          notes=["含 .. 段，按策略拒绝"])
    if policy.dot_segments == "resolve":
        path, traversal = _remove_dot_segments(path)

    if policy.case_fold == "insensitive":
        path = lower_preserving_escapes(path)

    if not path.startswith("/"):
        # absolute-form（http://host/path）或畸形形态：取 path 部分
        slash = path.find("/", path.find("://") + 3) if "://" in path else -1
        path = path[slash:] if slash != -1 else "/"
        notes.append("非 origin-form，已取 path 部分")

    if path == "":
        path = "/"

    return NormResult(ok=True, status=200, reason="OK", norm_path=path,
                      query=query, traversal=traversal,
                      segments=_segments_of(path), decoded=decoded, notes=notes)


__all__ = ["NormPolicy", "NormResult", "normalize_target",
           "lower_preserving_escapes"]
