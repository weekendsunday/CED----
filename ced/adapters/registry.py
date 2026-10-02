"""领域注册表 —— 新领域只需在自己模块里 ``@register``，不必改任何中央文件。

为什么要有这一层：领域数量是这套东西"攻击面宽度"的唯一来源，而每加一个领域
都要同步维护 ``impls.LOCAL_PARSERS`` / ``LOCAL_SPECS`` / ``LOCAL_AXIS_PAIRS``
三张表 + 适配器表，就必然会漂。注册表把"新增领域"压到**一行装饰器**。
"""

from __future__ import annotations

#: 领域名 → 适配器类
ADAPTERS: dict[str, type] = {}


def register(cls):
    """把适配器类登记进注册表（用作类装饰器）。"""
    name = getattr(cls, "name", None)
    if not name:
        raise ValueError(f"{cls!r} 没有 name，不能注册为领域")
    existing = ADAPTERS.get(name)
    if existing is not None and existing is not cls:
        raise ValueError(f"领域名冲突：{name} 已被 {existing!r} 占用")
    ADAPTERS[name] = cls
    return cls


def get(name: str):
    """按名字取一个适配器实例。"""
    try:
        return ADAPTERS[name]()
    except KeyError as exc:
        raise KeyError(
            f"未知领域: {name}（可选：{', '.join(sorted(ADAPTERS))}）") from exc


def names() -> list[str]:
    return sorted(ADAPTERS)


__all__ = ["ADAPTERS", "register", "get", "names"]
