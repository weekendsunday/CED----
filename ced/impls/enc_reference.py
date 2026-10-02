"""编码 / Unicode 归一化的参照实现：一组"只在一个解释策略上不同"的实现。

用途与 ``url_reference.py`` 完全对称 —— **内部基准**：用一个解释口径做基线，
每个参照实现只偏离**一个**策略点，于是每个分歧都能归因到具体的解释决策。

命名只描述行为（enc-strict / enc-overlong-accept / …），**不声称等价于任何
具体产品版本**。真实产品通过 probe 协议接入（runner=socket / chain）。

基线口径（``enc-strict``）是"严格检查侧的口径"：
    拒绝过长 UTF-8 · 不做 Unicode 规范化 · 不折叠全角 · 不认 `%uXXXX` ·
    大小写敏感（不做 Unicode casefold）· 按 UTF-8 解释 · 拒绝孤立代理项 · 不截断 NUL
真实标准/实现的口径写在各参照实现的 docstring 与 ``mutate/enc_axes`` 的语料注释里，
作为**独立手写的期望值来源**。
"""
from __future__ import annotations

from ..contracts import ImplSpec
from .enc_norm import EncPolicy

#: 基线：严格检查侧的解释口径
BASE: dict = dict(
    overlong_utf8="reject",
    unicode_form="none",
    fullwidth_fold="keep",
    percent_u="reject",
    case_fold_unicode="sensitive",
    byte_encoding="utf-8",
    lone_surrogate="reject",
    nul_truncate="keep",
)


def _p(name: str, **over) -> EncPolicy:
    return EncPolicy(name=name, **{**BASE, **over})


#: 每个条目只偏离基线一个策略点 —— 分歧轴可归因
ENC_REFERENCES: dict[str, EncPolicy] = {
    "enc-strict": _p("enc-strict"),
    "enc-overlong-accept": _p("enc-overlong-accept", overlong_utf8="accept"),
    "enc-nfc": _p("enc-nfc", unicode_form="nfc"),
    "enc-nfd": _p("enc-nfd", unicode_form="nfd"),
    "enc-fold-width": _p("enc-fold-width", fullwidth_fold="fold"),
    "enc-percent-u": _p("enc-percent-u", percent_u="decode"),
    "enc-fold-case": _p("enc-fold-case", case_fold_unicode="fold"),
    "enc-latin1": _p("enc-latin1", byte_encoding="latin-1"),
    "enc-surrogate-keep": _p("enc-surrogate-keep", lone_surrogate="keep"),
    "enc-nul-truncate": _p("enc-nul-truncate", nul_truncate="truncate"),
}

#: 分歧轴 → 该轴上"两个策略名"的对照（用于按轴定向差分）
AXIS_PAIRS: dict[str, tuple[str, str]] = {
    "enc_overlong_utf8": ("enc-strict", "enc-overlong-accept"),
    "enc_unicode_nfc": ("enc-strict", "enc-nfc"),
    "enc_unicode_nfd": ("enc-strict", "enc-nfd"),
    "enc_fullwidth": ("enc-strict", "enc-fold-width"),
    "enc_percent_u": ("enc-strict", "enc-percent-u"),
    "enc_case_fold": ("enc-strict", "enc-fold-case"),
    "enc_byte_encoding": ("enc-strict", "enc-latin1"),
    "enc_lone_surrogate": ("enc-strict", "enc-surrogate-keep"),
    "enc_nul": ("enc-strict", "enc-nul-truncate"),
    # 良性对照轴：完全规范的输入，两侧都必须零分歧（防假阳性）
    "enc_benign": ("enc-strict", "enc-overlong-accept"),
}


def specs() -> list[ImplSpec]:
    """全部参照实现（runner=local，domain=enc-norm）。"""
    return [
        ImplSpec(impl_id=name, name=name, version="ref", role="solo",
                 runner="local", policy=name, domain="enc-norm")
        for name in ENC_REFERENCES
    ]


def policy_of(impl_id: str) -> EncPolicy:
    try:
        return ENC_REFERENCES[impl_id]
    except KeyError as exc:
        raise KeyError(
            f"未知解释参照实现: {impl_id}"
            f"（可选：{', '.join(ENC_REFERENCES)}）") from exc


__all__ = ["BASE", "ENC_REFERENCES", "AXIS_PAIRS", "specs", "policy_of"]
