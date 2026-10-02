"""领域适配器层：把"某个协议的分歧知识"与引擎解耦。

**新增一个领域** = 实现 `DomainAdapter` 协议，并在下面的 `ADAPTERS` 里登记。
引擎（差分 / 判定 / 最小化 / 报告 / 落库）一行都不用改。
"""

from .base import DomainAdapter
from .http1_framing import Http1FramingAdapter
from .url_norm import UrlNormAdapter

#: 领域注册表：名字 → 适配器类
ADAPTERS: dict[str, type] = {
    Http1FramingAdapter.name: Http1FramingAdapter,
    UrlNormAdapter.name: UrlNormAdapter,
}


def get(name: str) -> DomainAdapter:
    """按名字取一个适配器实例。"""
    try:
        return ADAPTERS[name]()
    except KeyError as exc:
        raise KeyError(f"未知领域: {name}（可选：{', '.join(sorted(ADAPTERS))}）") from exc


def names() -> list[str]:
    return sorted(ADAPTERS)


__all__ = ["DomainAdapter", "Http1FramingAdapter", "ADAPTERS", "get", "names"]
