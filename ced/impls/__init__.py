"""参照实现层：按**领域**提供「策略 → 观测」的本地实现。

加一个新领域 = 在 ``LOCAL_PARSERS`` 里加一行（多领域只在注册表里体现），
引擎（差分 / 判定 / 最小化 / PoC / 报告）一行都不用改。

任何本地解析器都要满足同一份鸭子契约：
    parse(payload: bytes, policy) -> 结果对象
结果对象必须有 ``ok`` / ``reason`` / ``to_fields()``。
"""
from . import reference, url_reference
from .http_reader import FramingPolicy, ParseResult, parse_request
from .path_norm import NormPolicy, NormResult, normalize_target

#: 领域 → (取策略函数, 解析函数)
LOCAL_PARSERS: dict[str, tuple] = {
    "http1-framing": (reference.policy_of, parse_request),
    "url-norm": (url_reference.policy_of, normalize_target),
}

#: 领域 → 取全部参照实现的函数
LOCAL_SPECS: dict[str, object] = {
    "http1-framing": reference.specs,
    "url-norm": url_reference.specs,
}

#: 领域 → 定向对照表（轴名 → (左, 右)）
LOCAL_AXIS_PAIRS: dict[str, dict] = {
    "http1-framing": reference.AXIS_PAIRS,
    "url-norm": url_reference.AXIS_PAIRS,
}


def local_parser(domain: str) -> tuple:
    """取某个领域的 (policy_of, parse)。未知领域直接报错，不静默退回默认。"""
    try:
        return LOCAL_PARSERS[domain]
    except KeyError as exc:
        raise KeyError(
            f"未知领域：{domain}（可选：{', '.join(sorted(LOCAL_PARSERS))}）") from exc


def local_specs(domain: str) -> list:
    """取某个领域的全部参照实现。"""
    try:
        return LOCAL_SPECS[domain]()
    except KeyError as exc:
        raise KeyError(
            f"未知领域：{domain}（可选：{', '.join(sorted(LOCAL_SPECS))}）") from exc


def axis_pairs(domain: str) -> dict:
    """取某个领域的定向对照表。"""
    try:
        return LOCAL_AXIS_PAIRS[domain]
    except KeyError as exc:
        raise KeyError(
            f"未知领域：{domain}（可选：{', '.join(sorted(LOCAL_AXIS_PAIRS))}）") from exc


__all__ = ["FramingPolicy", "ParseResult", "NormPolicy", "NormResult",
           "parse_request", "normalize_target", "local_parser", "local_specs",
           "axis_pairs", "LOCAL_PARSERS", "LOCAL_SPECS", "LOCAL_AXIS_PAIRS",
           "reference", "url_reference"]
