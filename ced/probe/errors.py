"""探针层的错误类型。

**关键语义**：链路探测失败必须抛错，绝不允许合成一个"看起来像观测"的结果。
合成出来的观测必然与基线不同，会把"探测失败"整片变成假阳性安全结论。
"""
from __future__ import annotations


class ProbeUnreachable(RuntimeError):
    """探针不可达、或前置没有把字节转发到探针。"""
