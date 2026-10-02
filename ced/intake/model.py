"""验证层的数据契约 —— 「待验证的假设」与「验证结论」。

外部扫描器（nuclei / Burp / HAR / curl / 普通清单）产出的是**线索**，
不是结论。这里把它们统一成 :class:`Hypothesis`，再经同一条差分 oracle 链
得到三态的 :class:`Verification`（已证实 / 已证伪 / 证不了）。

与 ``contracts.Proposal`` 同一个哲学：扫描器的命中率是它的卖点，
是否成立必须由**确定性差分**重新判定，而不是采信扫描器自己的 severity。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Hypothesis:
    """一条「待验证的假设」—— 外部扫描器说这里可能有问题。"""

    source: str          # nuclei | burp | har | curl | list | manual
    target: str          # 一条 URL 或一个裸目标
    raw: str = ""        # 原始素材（可能含完整请求字节）
    note: str = ""


@dataclass(frozen=True)
class Verification:
    """一条假设喂进 oracle 链之后的结论。"""

    hypothesis: Hypothesis
    verdict: str         # confirmed | refuted | unverifiable
    domain: str = ""     # 在哪个领域验证的
    left: str = ""       # 该领域的左实现
    right: str = ""
    level: str = ""      # security | unknown | compatibility
    kind: str = ""
    reason: str = ""
    evidence: str = ""   # 消融证据
    minimized_b64: str | None = None
    detail: str = ""     # 人话说明（尤其是 unverifiable/refuted 的原因）


__all__ = ["Hypothesis", "Verification"]
