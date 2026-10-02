"""参照实现层：按**领域**提供「策略 → 观测」的本地实现。

领域只在适配器里声明一次（``@register``），这里按需从适配器注册表补齐 ——
**不再手工同步三张表**，那是必然漂的来源。

任何本地解析器都要满足同一份鸭子契约：
    parse(payload: bytes, policy) -> 结果对象（有 ``ok`` / ``reason`` / ``to_fields()``）
"""
from . import reference, url_reference
from .http_reader import FramingPolicy, ParseResult, parse_request
from .path_norm import NormPolicy, NormResult, normalize_target

#: 领域 → (取策略函数, 解析函数)
LOCAL_PARSERS: dict[str, tuple] = {}
#: 领域 → 取全部参照实现的函数
LOCAL_SPECS: dict[str, object] = {}
#: 领域 → 定向对照表（轴名 → (左, 右)）
LOCAL_AXIS_PAIRS: dict[str, dict] = {}


def _ensure(domain: str) -> None:
    """按需从适配器注册表补齐本领域的三个查找表（幂等）。"""
    if domain in LOCAL_PARSERS:
        return
    # 延迟导入：adapters 会 import impls，模块级导入会成环
    from ..adapters.registry import ADAPTERS
    cls = ADAPTERS.get(domain)
    if cls is None:
        raise KeyError(
            f"未知领域：{domain}（可选：{', '.join(sorted(ADAPTERS))}）")
    instance = cls()
    LOCAL_PARSERS[domain] = instance.local_parser()
    LOCAL_SPECS[domain] = instance.specs
    LOCAL_AXIS_PAIRS[domain] = instance.pairs()


def domains() -> list[str]:
    """已注册的领域名（来自适配器注册表，单一真源）。"""
    from ..adapters.registry import ADAPTERS
    return sorted(ADAPTERS)


def local_parser(domain: str) -> tuple:
    """取某个领域的 ``(policy_of, parse)``。未知领域直接报错，不静默退回默认。"""
    _ensure(domain)
    return LOCAL_PARSERS[domain]


def local_specs(domain: str) -> list:
    """取某个领域的全部参照实现。"""
    _ensure(domain)
    return LOCAL_SPECS[domain]()


def axis_pairs(domain: str) -> dict:
    """取某个领域的定向对照表。"""
    _ensure(domain)
    return LOCAL_AXIS_PAIRS[domain]


def policy_for(domain: str, impl_id: str):
    """取某个领域里某个参照实现的策略。"""
    policy_of, _ = local_parser(domain)
    return policy_of(impl_id)


__all__ = ["FramingPolicy", "ParseResult", "NormPolicy", "NormResult",
           "parse_request", "normalize_target", "local_parser", "local_specs",
           "axis_pairs", "policy_for", "domains", "LOCAL_PARSERS", "LOCAL_SPECS",
           "LOCAL_AXIS_PAIRS", "reference", "url_reference"]
