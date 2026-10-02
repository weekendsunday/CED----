"""领域适配器协议。

接入一个新领域（HTTP/2 分帧、URL 归一化、序列化格式……）
= 实现一个 DomainAdapter，其余模块（差分/判定/最小化/报告）全部复用。
"""
from __future__ import annotations

import random
from typing import Protocol

from ..contracts import DEFAULT_COMPARE_KEYS, ImplSpec


class DomainAdapter(Protocol):
    """领域适配器。运行时按鸭子类型约束，不做 ABC 强制。"""

    name: str
    #: 参与差分比对的观测字段（其余字段视为诊断信息，不参与）
    compare_keys: tuple[str, ...]
    #: 具备"分歧落在消息边界上"结构性前提的类型
    boundary_kinds: tuple[str, ...]
    #: 接受性分歧的类型
    kind_acceptance: str

    def meta(self, kind: str) -> dict:
        """分歧类型 → {effect, cwe, scenario, fix}。"""
        ...

    def specs(self) -> list[ImplSpec]:
        """参与差分的实现清单。"""
        ...

    def corpus(self) -> list[tuple[str, bytes]]:
        """种子语料：(轴名, 原始字节)。"""
        ...

    def expand(self, cases: list[tuple[str, bytes]],
               rng: random.Random) -> list[tuple[str, bytes]]:
        """定向变异。"""
        ...

    def classify(self, diff_keys: list[str]) -> str:
        """分歧字段 → 分歧类型。"""
        ...


__all__ = ["DomainAdapter", "DEFAULT_COMPARE_KEYS"]
