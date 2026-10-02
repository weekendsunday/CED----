"""Host / 路由归一化的参照实现：一组"只在一个归一化策略上不同"的实现。

用途与 ``url_reference.py`` 完全对称 —— **内部基准**：用一个归一化口径做基线，
每个参照实现只偏离**一个**策略点，于是每个分歧都能归因到具体的归一化决策。

命名只描述行为（host-literal / host-strip-dot / …），**不声称等价于任何具体产品版本**。
真实产品通过 probe 协议接入（runner=socket / chain）。

基线口径（``host-literal``）是"朴素 Host 处理器"的口径：把 Host 头当成一段
近乎原样的字符串，只在最后结构性拆出端口 —— 不大小写折叠、不剥尾随点、
不剥 userinfo、不折叠空标签、不做 IDN、不规范化 IPv6、不解码百分号。
真实产品（浏览器 / WHATWG URL / nginx / 各类缓存）各自在这 8 个点上偏离，
写在已知案例的 ``reference`` 字段里，作为**独立手写的期望值来源**。
"""
from __future__ import annotations

from ..contracts import ImplSpec
from .host_norm import HostPolicy

#: 基线：朴素 Host 处理器（几乎原样保留，只拆端口）
BASE: dict = dict(
    trailing_dot="keep",
    case_fold="sensitive",
    default_port="keep",
    userinfo="keep",
    duplicate_dot="keep",
    idn="raw",
    ipv6="keep",
    percent_host="keep",
    forward_form="raw",
)


def _p(name: str, **over) -> HostPolicy:
    return HostPolicy(name=name, **{**BASE, **over})


#: 每个条目只偏离基线一个策略点 —— 分歧轴可归因
NORM_REFERENCES: dict[str, HostPolicy] = {
    "host-literal": _p("host-literal"),
    # nginx `server_name example.com` 匹配不上 `example.com.`；浏览器/curl 剥尾随点
    "host-strip-dot": _p("host-strip-dot", trailing_dot="strip"),
    # DNS 大小写不敏感；基于原始字节的 vhost 表 / 缓存键却大小写敏感
    "host-lowercase": _p("host-lowercase", case_fold="insensitive"),
    # RFC 7230 只在非默认端口带端口；缓存/路由键常常归一掉 `:80` / `:443`
    "host-strip-default-port": _p("host-strip-default-port", default_port="strip"),
    # WHATWG URL 剥 userinfo；朴素处理器让 `evil.com@victim.com` 成为主机名
    "host-strip-userinfo": _p("host-strip-userinfo", userinfo="strip"),
    # 部分归一化折叠空标签（`example..com` → `example.com`）
    "host-collapse-dots": _p("host-collapse-dots", duplicate_dot="collapse"),
    # 浏览器按 IDNA 转 punycode；只看原始字节的服务器拿 Unicode 比对 vhost
    "host-idna": _p("host-idna", idn="idna"),
    # WHATWG URL 把 IPv6 归一化为 RFC 5952 规范形式
    "host-ipv6-canonical": _p("host-ipv6-canonical", ipv6="canonical"),
    # 有的反向代理会解码 Host 里的百分号编码
    "host-percent-decode": _p("host-percent-decode", percent_host="decode"),
}

#: 分歧轴 → 该轴上"两个策略名"的对照（用于按轴定向差分）
AXIS_PAIRS: dict[str, tuple[str, str]] = {
    "host_trailing_dot": ("host-literal", "host-strip-dot"),
    "host_case_fold": ("host-literal", "host-lowercase"),
    "host_default_port": ("host-literal", "host-strip-default-port"),
    "host_userinfo": ("host-literal", "host-strip-userinfo"),
    "host_duplicate_dot": ("host-literal", "host-collapse-dots"),
    "host_idn": ("host-literal", "host-idna"),
    "host_ipv6": ("host-literal", "host-ipv6-canonical"),
    "host_percent": ("host-literal", "host-percent-decode"),
}


def specs() -> list[ImplSpec]:
    """全部参照实现（runner=local，domain=host-norm）。"""
    return [
        ImplSpec(impl_id=name, name=name, version="ref", role="solo",
                 runner="local", policy=name, domain="host-norm")
        for name in NORM_REFERENCES
    ]


def policy_of(impl_id: str) -> HostPolicy:
    try:
        return NORM_REFERENCES[impl_id]
    except KeyError as exc:
        raise KeyError(
            f"未知归一化参照实现: {impl_id}"
            f"（可选：{', '.join(NORM_REFERENCES)}）") from exc


__all__ = ["BASE", "NORM_REFERENCES", "AXIS_PAIRS", "specs", "policy_of"]
