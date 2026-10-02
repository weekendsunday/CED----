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

    def ablate(self, div, evaluate) -> list[str]:
        """承载分歧的可控字节 —— **该领域的消融实验**。

        逐条"抹掉一类承载者"重放两侧：分歧消失了，说明它由那一类字节承载；
        而那些字节由攻击者直接发送 → 可控。判定器据此把 boundary 类分歧升级为
        ``security``，把定位不到的保守判为 ``unknown``。

        消融的**设计**是领域知识（分帧是逐条请求头，路径归一化是逐类字节），
        所以它属于适配器；判定权仍然唯一属于 ``classify.upgradability.judge``。
        """
        ...

    def quantify(self, payload: bytes, left_id: str, right_id: str):
        """把"两侧理解不同"量化成"真的有东西错位了"（``Quantified`` 或 None）。

        各领域的量化指标不同：分帧是**被夹带的字节数**，路径归一化是**资源路径的错位**。
        两侧都是本地参照实现时才能算；含真实产品时返回 None，报告如实写"未量化"。
        """
        ...

    def minimize(self, payload: bytes, predicate) -> bytes:
        """在**该领域的语义单元**上压小样本，同时保持分歧仍在。

        最小化的粒度是领域知识：分帧是"请求头行"，路径归一化是"路径段"。
        ``predicate(candidate) -> bool`` 判断该候选是否仍然构成分歧。
        """
        ...


__all__ = ["DomainAdapter", "DEFAULT_COMPARE_KEYS", "axis_names"]


def axis_names(adapter) -> tuple[str, ...]:
    """适配器语料里出现的轴名（去重保序）。

    给模型提案时用它避开与手写轴重名 —— 用领域自己的名字空间，
    而不是像以前那样硬编码分帧领域的 ``axes.AXES``。
    """
    return tuple(dict.fromkeys(name for name, _ in adapter.corpus()))
