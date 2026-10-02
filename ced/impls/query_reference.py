"""查询串解析的参照实现：一组"只在一个解析策略上不同"的实现。

用途与 ``url_reference.py`` 完全对称 —— **内部基准**：用一个解析口径做基线，
每个参照实现只偏离**一个**策略点，于是每个分歧都能归因到具体的解析决策。

命名只描述行为（query-gateway / query-last-wins / …），**不声称等价于任何具体产品版本**。
真实产品通过 probe 协议接入（runner=socket / chain）。

基线口径（``query-gateway``）是"常见前置网关的解析口径"，不是某条规范本身：
    只认 `&` 分隔 · 重复参数取首 · 解码一次 · `+` 当空格 · 保留空值 ·
    不剥括号 · 参数名大小写敏感 · 不排序
真实实现的行为写在已知案例的 ``reference`` 字段里，作为**独立手写的期望值来源**。
"""
from __future__ import annotations

from ..contracts import ImplSpec
from .query_norm import QueryPolicy

#: 基线：常见前置网关的解析口径
BASE: dict = dict(
    separators="amp",
    duplicate="first",
    percent_decode="once",
    plus_space=True,
    keep_empty=True,
    bracket="keep",
    case_sensitive=True,
    sort_params=False,
)


def _p(name: str, **over) -> QueryPolicy:
    return QueryPolicy(name=name, **{**BASE, **over})


#: 每个条目只偏离基线一个策略点 —— 分歧轴可归因
QUERY_REFERENCES: dict[str, QueryPolicy] = {
    "query-gateway": _p("query-gateway"),
    "query-semicolon-sep": _p("query-semicolon-sep", separators="amp_semicolon"),
    "query-last-wins": _p("query-last-wins", duplicate="last"),
    "query-all-wins": _p("query-all-wins", duplicate="all"),
    "query-no-decode": _p("query-no-decode", percent_decode="never"),
    "query-double-decode": _p("query-double-decode", percent_decode="twice"),
    "query-plus-literal": _p("query-plus-literal", plus_space=False),
    "query-drop-empty": _p("query-drop-empty", keep_empty=False),
    "query-bracket-strip": _p("query-bracket-strip", bracket="strip"),
    "query-case-insensitive": _p("query-case-insensitive", case_sensitive=False),
    "query-sorted": _p("query-sorted", sort_params=True),
}

#: 分歧轴 → 该轴上"两个策略名"的对照（用于按轴定向差分）
AXIS_PAIRS: dict[str, tuple[str, str]] = {
    "query_separators": ("query-gateway", "query-semicolon-sep"),
    "query_duplicate": ("query-gateway", "query-last-wins"),
    "query_dup_multi": ("query-gateway", "query-all-wins"),
    "query_decoding": ("query-gateway", "query-no-decode"),
    "query_double_decode": ("query-gateway", "query-double-decode"),
    "query_plus": ("query-gateway", "query-plus-literal"),
    "query_empty": ("query-gateway", "query-drop-empty"),
    "query_bracket": ("query-gateway", "query-bracket-strip"),
    "query_case": ("query-gateway", "query-case-insensitive"),
    "query_sort": ("query-gateway", "query-sorted"),
}


def specs() -> list[ImplSpec]:
    """全部参照实现（runner=local，domain=query-norm）。"""
    return [
        ImplSpec(impl_id=name, name=name, version="ref", role="solo",
                 runner="local", policy=name, domain="query-norm")
        for name in QUERY_REFERENCES
    ]


def policy_of(impl_id: str) -> QueryPolicy:
    try:
        return QUERY_REFERENCES[impl_id]
    except KeyError as exc:
        raise KeyError(
            f"未知查询解析参照实现: {impl_id}"
            f"（可选：{', '.join(QUERY_REFERENCES)}）") from exc


__all__ = ["BASE", "QUERY_REFERENCES", "AXIS_PAIRS", "specs", "policy_of"]
