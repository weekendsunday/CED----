"""URL 路径归一化的参照实现：一组"只在一个归一化策略上不同"的实现。

用途与 ``reference.py`` 完全对称 —— **内部基准**：用一个归一化口径做基线，
每个参照实现只偏离**一个**策略点，于是每个分歧都能归因到具体的归一化决策。

命名只描述行为（url-gateway / url-keep-dots / …），**不声称等价于任何具体产品版本**。
真实产品通过 probe 协议接入（runner=socket / chain）。

基线口径（``url-gateway``）是"常见前置网关的归一化口径"，不是 RFC 本身：
    解码一次 · 百分号大小写宽松 · 反斜杠当普通字符 · 不折叠斜杠 ·
    不剥矩阵参数 · 保留尾随点 · 路径大小写敏感 · `..` 解算
RFC 3986 的规范行为写在已知案例的 ``reference`` 字段里，作为**独立手写的期望值来源**。
"""
from __future__ import annotations

from ..contracts import ImplSpec
from .path_norm import NormPolicy

#: 基线：常见前置网关的归一化口径
BASE: dict = dict(
    dot_segments="resolve",
    percent_decode="once",
    percent_case="lenient",
    overlong_utf8="reject",
    null_byte="keep",
    backslash="literal",
    duplicate_slash="keep",
    trailing_dot_space="keep",
    semicolon_params="keep",
    case_fold="sensitive",
    forward_form="raw",
)


def _p(name: str, **over) -> NormPolicy:
    return NormPolicy(name=name, **{**BASE, **over})


#: 每个条目只偏离基线一个策略点 —— 分歧轴可归因
NORM_REFERENCES: dict[str, NormPolicy] = {
    "url-gateway": _p("url-gateway"),
    "url-keep-dots": _p("url-keep-dots", dot_segments="keep"),
    "url-decode-never": _p("url-decode-never", percent_decode="never"),
    "url-decode-twice": _p("url-decode-twice", percent_decode="twice"),
    "url-percent-strict": _p("url-percent-strict", percent_case="strict"),
    "url-backslash-sep": _p("url-backslash-sep", backslash="separator"),
    "url-collapse-slash": _p("url-collapse-slash", duplicate_slash="collapse"),
    "url-strip-trailing": _p("url-strip-trailing", trailing_dot_space="strip"),
    "url-strip-semicolon": _p("url-strip-semicolon", semicolon_params="strip"),
    "url-case-insensitive": _p("url-case-insensitive", case_fold="insensitive"),
    "url-overlong-accept": _p("url-overlong-accept", overlong_utf8="accept"),
    "url-null-truncate": _p("url-null-truncate", null_byte="truncate"),
}

#: 分歧轴 → 该轴上"两个策略名"的对照（用于按轴定向差分）
AXIS_PAIRS: dict[str, tuple[str, str]] = {
    "path_dot_segments": ("url-gateway", "url-keep-dots"),
    "path_decoding": ("url-gateway", "url-decode-never"),
    "path_double_decode": ("url-gateway", "url-decode-twice"),
    "path_percent_case": ("url-gateway", "url-percent-strict"),
    "path_backslash": ("url-gateway", "url-backslash-sep"),
    "path_slash_collapse": ("url-gateway", "url-collapse-slash"),
    "path_trailing_dot": ("url-gateway", "url-strip-trailing"),
    "path_semicolon": ("url-gateway", "url-strip-semicolon"),
    "path_case_fold": ("url-gateway", "url-case-insensitive"),
    "path_overlong_utf8": ("url-gateway", "url-overlong-accept"),
    "path_null_byte": ("url-gateway", "url-null-truncate"),
}


def specs() -> list[ImplSpec]:
    """全部参照实现（runner=local，domain=url-norm）。"""
    return [
        ImplSpec(impl_id=name, name=name, version="ref", role="solo",
                 runner="local", policy=name, domain="url-norm")
        for name in NORM_REFERENCES
    ]


def policy_of(impl_id: str) -> NormPolicy:
    try:
        return NORM_REFERENCES[impl_id]
    except KeyError as exc:
        raise KeyError(
            f"未知归一化参照实现: {impl_id}"
            f"（可选：{', '.join(NORM_REFERENCES)}）") from exc


__all__ = ["BASE", "NORM_REFERENCES", "AXIS_PAIRS", "specs", "policy_of"]
