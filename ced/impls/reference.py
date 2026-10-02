"""参照实现：一组"只在一个分帧策略上不同"的实现。

用途是**内部基准**——用它们证明差分引擎真的能定位到分歧轴，
而不是让任何一条结论依赖对某个真实产品行为的断言。

命名只描述行为（cl-first / te-first / …），不声称等价于任何具体产品版本。
真实产品通过 probe 协议接入（见 orchestrate/probe）。
"""
from __future__ import annotations

from ..contracts import ImplSpec
from .http_reader import FramingPolicy

#: 基线策略：严格、按 CL 定界、头语法不宽容
BASE: dict = dict(
    dual_policy="cl",
    cl_syntax="canonical",
    cl_duplicates="reject",
    te_unknown="ignore",
    te_case="fold",
    line_terminator="strict",
    header_name_ws="reject",
    obs_fold="reject",
    request_line="strict",
    chunk_terminator="strict",
)


def _p(name: str, **over) -> FramingPolicy:
    return FramingPolicy(name=name, **{**BASE, **over})


#: 每个条目只偏离基线一个策略点 —— 分歧轴可归因
REFERENCES: dict[str, FramingPolicy] = {
    "ref-cl-first": _p("ref-cl-first"),
    "ref-te-first": _p("ref-te-first", dual_policy="te"),
    "ref-reject-dual": _p("ref-reject-dual", dual_policy="reject"),
    "ref-lenient-cl": _p("ref-lenient-cl", cl_syntax="lenient", cl_duplicates="first"),
    "ref-loose-headers": _p("ref-loose-headers", header_name_ws="trim", obs_fold="accept"),
    "ref-loose-request-line": _p("ref-loose-request-line", request_line="relaxed"),
    "ref-te-any-token": _p("ref-te-any-token", te_unknown="chunked"),
    "ref-te-case-sensitive": _p("ref-te-case-sensitive", te_case="sensitive"),
    "ref-lenient-chunks": _p("ref-lenient-chunks", chunk_terminator="lenient"),
}

#: 分歧轴 → 该轴上"两个策略名"的对照（用于按轴定向差分）
AXIS_PAIRS: dict[str, tuple[str, str]] = {
    "cl_te_conflict": ("ref-cl-first", "ref-te-first"),
    "cl_te_reject": ("ref-cl-first", "ref-reject-dual"),
    "cl_value": ("ref-cl-first", "ref-lenient-cl"),
    "header_syntax": ("ref-cl-first", "ref-loose-headers"),
    "request_line": ("ref-cl-first", "ref-loose-request-line"),
    "te_value": ("ref-cl-first", "ref-te-any-token"),
    "te_case": ("ref-cl-first", "ref-te-case-sensitive"),
    "chunk_syntax": ("ref-cl-first", "ref-lenient-chunks"),
}


def specs() -> list[ImplSpec]:
    """全部参照实现（runner=local）。"""
    return [
        ImplSpec(impl_id=name, name=name, version="ref", role="solo",
                 runner="local", policy=name)
        for name in REFERENCES
    ]


def policy_of(impl_id: str) -> FramingPolicy:
    try:
        return REFERENCES[impl_id]
    except KeyError as exc:
        raise KeyError(f"未知参照实现: {impl_id}（可选：{', '.join(REFERENCES)}）") from exc
