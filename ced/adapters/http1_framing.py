"""HTTP/1.1 消息分帧领域适配器。"""
from __future__ import annotations

import random

from ..contracts import DEFAULT_COMPARE_KEYS, ImplSpec
from ..impls import reference
from ..mutate import axes, engine

# ---- 分歧类型（判定器按此升级/降级）----
KIND_FRAMING_BOUNDARY = "framing_boundary"          # 消费字节数不同 —— 走私的结构性前提
KIND_FRAMING_INTERP = "framing_interpretation"      # 定帧来源/体长解释不同
KIND_ACCEPTANCE = "acceptance"                      # 一侧接受一侧拒绝
KIND_SYNTAX_DETAIL = "syntax_detail"                # 仅诊断信息不同

#: 只有这两类具备"分歧落在消息边界上"的结构性前提
BOUNDARY_KINDS = (KIND_FRAMING_BOUNDARY, KIND_FRAMING_INTERP)

_KIND_MAP = {
    KIND_FRAMING_BOUNDARY: {
        "effect": "两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）",
        "cwe": "CWE-444",
        "scenario": "desync",
        "fix": "对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式",
    },
    KIND_FRAMING_INTERP: {
        "effect": "定帧来源或请求体长度解释不同 → 边界可能错位（是否可升级取决于字节能否被夹带）",
        "cwe": "CWE-444",
        "scenario": "desync",
        "fix": "统一 CL/TE 优先级与语法接受度；两侧对齐同一份定帧规范",
    },
    KIND_ACCEPTANCE: {
        "effect": "一侧接受、一侧拒绝 → 上游放行下游拒绝（或反之），可造成防护绕过或拒绝服务",
        "cwe": "CWE-436",
        "scenario": "bypass",
        "fix": "统一对畸形语法的拒绝策略，避免一侧宽容一侧严格",
    },
    KIND_SYNTAX_DETAIL: {
        "effect": "仅诊断信息（告警/备注）不同，观测到的消息结构一致 → 无直接安全后果",
        "cwe": None,
        "scenario": None,
        "fix": "无需修复；可作为兼容性记录",
    },
}


def meta_of(kind: str) -> dict:
    return _KIND_MAP.get(kind, _KIND_MAP[KIND_SYNTAX_DETAIL])


class Http1FramingAdapter:
    """HTTP/1.1 分帧领域。"""

    name = "http1-framing"
    compare_keys: tuple[str, ...] = DEFAULT_COMPARE_KEYS
    #: 具备"分歧落在消息边界上"结构性前提的类型（判定器据此决定能否升级）
    boundary_kinds: tuple[str, ...] = BOUNDARY_KINDS
    #: 接受性分歧的类型
    kind_acceptance: str = KIND_ACCEPTANCE

    def meta(self, kind: str) -> dict:
        """分歧类型 → 安全后果 / CWE / 场景 / 修复建议。"""
        return meta_of(kind)

    def __init__(self, variants_per_case: int = 6) -> None:
        self._mutator = engine.Mutator(variants_per_case=variants_per_case)

    # ---------------------------------------------------------------- 实现与语料

    def specs(self) -> list[ImplSpec]:
        return reference.specs()

    def pairs(self) -> dict[str, tuple[str, str]]:
        return dict(reference.AXIS_PAIRS)

    def corpus(self) -> list[tuple[str, bytes]]:
        return axes.corpus()

    def expand(self, cases: list[tuple[str, bytes]],
               rng: random.Random) -> list[tuple[str, bytes]]:
        return self._mutator.expand(cases, rng)

    # ---------------------------------------------------------------- 分类

    def classify(self, diff_keys: list[str]) -> str:
        """按**精确字段名**分类。

        刻意不用子串匹配：任何诊断字段（诊断信息）都不应被误升级为边界分歧。
        """
        keys = set(diff_keys)
        if "consumed" in keys:
            return KIND_FRAMING_BOUNDARY
        if keys & {"framing_source", "leftover_len", "body_len", "cl", "te"}:
            return KIND_FRAMING_INTERP
        if keys & {"accepted", "status"}:
            return KIND_ACCEPTANCE
        return KIND_SYNTAX_DETAIL
