"""可升级性判定器 —— 平台的知识资产。

核心公式：

    漏洞 ⇔ 语义分歧 ∧ 分歧点攻击者可控 ∧ 存在安全后果

其中**攻击者可控性**用**消融实验**机械地判定，而不是靠规则猜测：

    逐条移除请求头 → 重新对两侧求观测 → 若分歧消失，
    则该头承载了这个分歧；而请求头是攻击者可以直接发送的 → 可控。

这一步是抑制"兼容性噪声"的唯一有效过滤器，也是本平台与
"SAST 拿规则命中当结论"的根本区别。
"""
from __future__ import annotations

from typing import Callable

from ..contracts import (LEVEL_COMPAT, LEVEL_SECURITY, LEVEL_UNKNOWN,
                         Divergence, Observation, Verdict)
from ..differ.comparator import diff_keys
from .. import httpmsg

#: 评估器签名：(impl_id, payload) -> Observation
Evaluator = Callable[[str, bytes], Observation]


def _still_diverges(candidate: bytes, div: Divergence,
                    evaluate: Evaluator, compare_keys: tuple[str, ...]) -> bool:
    left = evaluate(div.left.impl_id, candidate)
    right = evaluate(div.right.impl_id, candidate)
    return bool(diff_keys(left, right, compare_keys))


def ablate(payload: bytes, div: Divergence, evaluate: Evaluator,
           compare_keys: tuple[str, ...]) -> list[bytes]:
    """逐条移除请求头，返回"移除后分歧消失"的那些头行。"""
    msg = httpmsg.split(payload)
    if msg is None:
        return []
    carriers: list[bytes] = []
    for index, line in msg.header_lines():
        candidate = httpmsg.drop_line(msg, index).build()
        if candidate == payload:
            continue
        if not _still_diverges(candidate, div, evaluate, compare_keys):
            carriers.append(line)
    return carriers


def judge(div: Divergence, kind: str, adapter, evaluate: Evaluator) -> Verdict:
    """判定一个分歧能否升级为安全影响。"""
    compare_keys = adapter.compare_keys
    boundary_kinds = adapter.boundary_kinds
    meta = adapter.meta(kind)
    keys = [d.key for d in div.diffs]

    # 只有"可能被升级"的类型才跑消融实验 —— 它要对每条请求头重放两侧，不便宜
    carriers: list[bytes] = []
    if kind in boundary_kinds or kind == adapter.kind_acceptance:
        carriers = ablate(div.payload, div, evaluate, compare_keys)
    controllable = bool(carriers)
    ablation = None
    if carriers:
        shown = ", ".join(f"`{c.decode('latin-1')}`" for c in carriers[:3])
        more = f" 等 {len(carriers)} 条" if len(carriers) > 3 else ""
        ablation = (f"移除请求头 {shown}{more} 后分歧消失 → "
                    f"该分歧由攻击者可直接发送的头部承载")

    if kind in boundary_kinds and controllable:
        level, reason = LEVEL_SECURITY, (
            f"消息边界解释分歧（字段 {keys}），且由攻击者可直接发送的请求头承载 "
            f"→ 具备请求走私的结构性前提"
        )
    elif kind in boundary_kinds:
        level, reason = LEVEL_UNKNOWN, (
            f"消息边界解释分歧（字段 {keys}），但消融实验无法定位到单条可控头 "
            f"→ 需人工复核"
        )
    elif kind == adapter.kind_acceptance and controllable:
        level, reason = LEVEL_UNKNOWN, (
            f"接受性分歧且由可控请求头承载 → 防护绕过候选，需人工复核（保守不升级）"
        )
    else:
        level, reason = LEVEL_COMPAT, (
            f"仅诊断字段不同（{keys}），观测到的消息结构一致，无安全后果"
        )

    return Verdict(level=level, kind=kind, reason=reason,
                   cwe=meta["cwe"], scenario=meta["scenario"],
                   controllable=controllable, ablation=ablation,
                   effect=meta["effect"], fix=meta["fix"])
