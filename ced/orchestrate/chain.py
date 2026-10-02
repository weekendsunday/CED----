"""链式复现：把"两个实现对同一段字节理解不同"变成"字节真的被夹带到下一条请求"。

模型（忠实于反向代理的实际行为，且不需要起真实代理）：

    1. 客户端把 payload 发给前置；
    2. 前置按自己的策略解析 → 认为这条请求占用 F 字节 → 把前 F 字节转发给后端；
    3. 后端按自己的策略再解析一次 → 只消费 B 字节；
    4. 转发过去的 F 字节里第 B 字节之后的部分，就是**后端眼里下一条请求的开头**。

    F > B  → 有 (F-B) 字节被"夹带"进后端缓冲，构成请求走私原语。
"""
from __future__ import annotations

from dataclasses import dataclass

from ..impls.http_reader import parse_request


@dataclass
class ChainEvidence:
    front: str
    back: str
    front_consumed: int
    forwarded: int
    back_consumed: int
    smuggled: bytes
    same_view: bool

    @property
    def smuggled_len(self) -> int:
        return len(self.smuggled)

    def describe(self) -> str:
        pair = f"**{self.front} → {self.back}**"
        if self.forwarded == 0:
            return (f"若 {pair} 串联：前置未转发任何字节（按自身策略拒绝）"
                    f"→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面")
        if self.same_view:
            return (f"若 {pair} 串联：两侧理解一致"
                    f"（前置转发 {self.forwarded} 字节，后端消费 {self.back_consumed} 字节）"
                    f"→ 无夹带")
        return (f"若 {pair} 串联：前置转发 {self.forwarded} 字节，"
                f"后端只消费 {self.back_consumed} 字节 → "
                f"**{self.smuggled_len} 字节被夹带**，将成为下一条请求的开头")


def chain_evidence(payload: bytes, front_policy, back_policy,
                   front: str = "front", back: str = "back") -> ChainEvidence:
    front_res = parse_request(payload, front_policy)
    forwarded_bytes = payload[:front_res.consumed] if front_res.consumed else b""
    back_res = parse_request(forwarded_bytes, back_policy)
    smuggled = forwarded_bytes[back_res.consumed:]

    same = (front_res.consumed == back_res.consumed and front_res.ok == back_res.ok)
    return ChainEvidence(front=front, back=back,
                         front_consumed=front_res.consumed,
                         forwarded=len(forwarded_bytes),
                         back_consumed=back_res.consumed,
                         smuggled=smuggled,
                         same_view=same)
