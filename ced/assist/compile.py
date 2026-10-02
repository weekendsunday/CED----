"""两道机械门槛 —— 提案能不能进语料，只由这里决定。

① 语法/白名单编译 ``framing_relevant`` / ``compile_specs``：
   请求先要能被 ``httpmsg.split`` 拆成一条消息，且必须落在"有分歧历史的
   分帧语法点"上（CL/TE 写法与优先级、chunk 语法、头语法、请求行形式），
   而且必须是**非规范写法** —— 规范请求两侧必然一致，没有差分价值。

② 差分 oracle 准入实验 ``admit``：
   把候选字节真的喂给已声明、且两侧都是本地实现的对照对，只有真的逼出结构
   分歧才算"命中"。没命中的提案进不了结果 —— 幻觉在类型上就无法表达。

裁决权唯一属于确定性内核（``compare`` / ``judge``），本模块只是把候选送上去。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from ..contracts import ORIGIN_LLM, Proposal, Rejected
from ..differ.comparator import compare
from ..httpmsg import Message, split
from ..pipeline import case_id_of
from .schema import ProposalSpec

#: 规范 Content-Length：恰好一个空格 + 无前导零的十进制
_CANON_CL = re.compile(rb" (0|[1-9][0-9]*)\Z")
_CANON_METHOD = re.compile(rb"[A-Z][A-Z0-9_-]*\Z")
_CANON_VERSION = re.compile(rb"HTTP/1\.[01]\Z")
_CHUNK_SIZE = re.compile(rb"[0-9a-f]+\Z")

#: 分块体语法非规范的判定上限（防止畸形输入把循环拖长）
_CHUNK_STEPS = 512


@dataclass(frozen=True)
class Admission:
    """一条提案的准入实验结果。``admitted`` 只由差分 oracle 给出。"""

    proposal: Proposal
    admitted: bool
    fields: tuple[str, ...] = ()
    detail: str = ""


# --------------------------------------------------------------------- 门槛①

def framing_relevant(raw: bytes) -> str | None:
    """落在分帧分歧轴上返回 None，否则返回拒绝原因。

    只有两种拒绝原因：不是一条消息，或虽然成消息但没打在任何已知语法点上。
    """
    msg = split(raw)
    if msg is None:
        return "不是一条 HTTP 消息"
    if (_request_line_odd(msg) or _header_syntax_odd(msg, raw)
            or _framing_headers_odd(msg) or _chunk_syntax_odd(msg)):
        return None
    return "没有落在分帧分歧轴上"


def compile_specs(specs: Iterable[ProposalSpec],
                  *, model: str = "") -> tuple[list[Proposal], list[Rejected]]:
    """把合规规格变成 ``Proposal``；未过门槛的进 ``Rejected``（带原因）。

    同一批内 payload 去重：后出现的丢弃，原因 ``与本批重复``。
    """
    proposals: list[Proposal] = []
    rejected: list[Rejected] = []
    seen: set[bytes] = set()

    for spec in specs:
        raw = spec.to_bytes()
        reason = framing_relevant(raw)
        if reason is not None:
            rejected.append(Rejected(spec.axis, reason))
            continue
        if raw in seen:
            rejected.append(Rejected(spec.axis, "与本批重复"))
            continue
        seen.add(raw)
        proposals.append(Proposal(axis=spec.axis, payload=raw, origin=ORIGIN_LLM,
                                  rationale=spec.rationale, model=model))
    return proposals, rejected


# --------------------------------------------------------------------- 门槛②

def admit(proposals: Iterable[Proposal], adapter, evaluator,
          *, sample: int = 8) -> list[Admission]:
    """差分 oracle 准入实验：逐条提案在本地对照对上跑一次。

    只保留两侧 runner 都是 ``local`` 的对照；没有任何可用本地对照时保守判
    ``admitted=False``（宁可漏报，不假装命中）。每个提案只跑一遍对照。
    """
    pairs = _local_pairs(adapter, evaluator, sample)
    out: list[Admission] = []

    for proposal in proposals:
        if not pairs:
            out.append(Admission(proposal, False, (),
                                 "无本地对照可用，无法完成准入实验"))
            continue
        try:
            hit = _first_divergence(proposal, pairs, adapter, evaluator)
        except Exception as exc:       # 探针异常如实记，绝不伪装成命中
            out.append(Admission(proposal, False, (),
                                 f"准入实验异常：{type(exc).__name__}: {exc}"))
            continue
        if hit is None:
            out.append(Admission(proposal, False, (),
                                 "差分 oracle 未命中：所有对照在结构字段上理解一致"))
        else:
            left_id, right_id, fields = hit
            out.append(Admission(
                proposal, True, fields,
                f"{left_id} ↔ {right_id}：命中字段 {', '.join(fields)}"))
    return out


def _local_pairs(adapter, evaluator, sample: int) -> list[tuple[str, str]]:
    specs = getattr(evaluator, "specs", {})
    out: list[tuple[str, str]] = []
    for left_id, right_id in adapter.pairs().values():
        left, right = specs.get(left_id), specs.get(right_id)
        if left is None or right is None:
            continue
        if left.runner != "local" or right.runner != "local":
            continue
        if (left_id, right_id) not in out:
            out.append((left_id, right_id))
        if len(out) >= sample:
            break
    return out


def _first_divergence(proposal: Proposal, pairs, adapter, evaluator):
    for left_id, right_id in pairs:
        left = evaluator(left_id, proposal.payload)
        right = evaluator(right_id, proposal.payload)
        div = compare(case_id_of(proposal.payload), proposal.axis,
                      proposal.payload, left, right, adapter.compare_keys)
        if div is not None:
            return left_id, right_id, tuple(div.keys)
    return None


# ------------------------------------------------------------- 语法点判定

def _request_line_odd(msg: Message) -> bool:
    if not msg.lines:
        return False
    parts = msg.lines[0].split(b" ")
    if len(parts) != 3:
        return True                                  # 多余空白 / 形状不对
    method, target, version = parts
    if not _CANON_METHOD.fullmatch(method):
        return True                                  # 方法非大写 / 非 token
    if not target.startswith(b"/"):
        return True                                  # 绝对 URI / 非 origin-form
    if not _CANON_VERSION.fullmatch(version):
        return True
    return False


def _header_syntax_odd(msg: Message, raw: bytes) -> bool:
    if _has_bare_lf(raw):
        return True                                  # 行尾不是 CRLF
    for _, line in msg.header_lines():
        if line[:1] in (b" ", b"\t"):
            return True                              # obs-fold 折行
        idx = line.find(b":")
        if idx <= 0:
            return True                              # 无冒号 / 空头名
        name = line[:idx]
        if name != name.rstrip():
            return True                              # 冒号前空白
        if b" " in name or b"\t" in name:
            return True                              # 头名内含空白
    return False


def _framing_headers_odd(msg: Message) -> bool:
    cl: list[bytes] = []
    te: list[bytes] = []
    for name, value in _header_fields(msg):
        if name == b"content-length":
            cl.append(value)
        elif name == b"transfer-encoding":
            te.append(value)

    if cl and te:
        return True                                  # CL/TE 并存
    if cl:
        if len(cl) > 1:
            return True                              # 重复 CL
        if not _CANON_CL.fullmatch(cl[0]):
            return True                              # 前导零/符号/空白/非数字
    if te:
        if len(te) > 1:
            return True                              # 重复 TE
        if te[0] != b" chunked":
            return True                              # 大小写/多编码/非标准 token
    return False


def _header_fields(msg: Message) -> list[tuple[bytes, bytes]]:
    """(小写头名, 冒号后原样值)；解析不出头名的行原样产出，交给语法检查。"""
    out: list[tuple[bytes, bytes]] = []
    for _, line in msg.header_lines():
        idx = line.find(b":")
        if idx <= 0:
            out.append((b"", line))
            continue
        out.append((line[:idx].strip().lower(), line[idx + 1:]))
    return out


def _chunk_syntax_odd(msg: Message) -> bool:
    chunked = any(name == b"transfer-encoding" and b"chunked" in value.lower()
                  for name, value in _header_fields(msg))
    if not chunked:
        return False
    body = msg.tail
    if not body or _has_bare_lf(body):
        return True                                  # 空体 / 裸 LF 行尾
    return _chunk_body_odd(body)


def _chunk_body_odd(body: bytes) -> bool:
    """按分块语法走一遍：扩展、十六进制大小写、终止块写法非规范即返回 True。"""
    pos, n = 0, len(body)
    for _ in range(_CHUNK_STEPS):
        idx = body.find(b"\r\n", pos)
        if idx == -1:
            return True                              # 缺行终结符
        size_line = body[pos:idx]
        if b";" in size_line:
            return True                              # chunk 扩展
        if not _CHUNK_SIZE.fullmatch(size_line):
            return True
        if size_line != size_line.lower() or (
                len(size_line) > 1 and size_line.startswith(b"0")):
            return True                              # 十六进制大小写 / 前导零
        size = int(size_line, 16)
        pos = idx + 2
        if size == 0:
            return body[pos:] != b"\r\n"             # 终止块写法
        if body[pos + size:pos + size + 2] != b"\r\n":
            return True
        pos += size + 2
    return True                                      # 步数超限：按非规范处理


def _has_bare_lf(raw: bytes) -> bool:
    """存在不被 CR 前导的 LF（即行尾不是 CRLF）。"""
    i = raw.find(b"\n")
    while i != -1:
        if i == 0 or raw[i - 1:i] != b"\r":
            return True
        i = raw.find(b"\n", i + 1)
    return False
