"""闭环 agent 层。

    tools.py   工具表（模型能做的每一件事，都必须是引擎已有的能力）
    loop.py    闭环编排（提案 → 两道门槛 → 执行 → 台账 → 下一轮）

不变式：**agent 不下判定。** 判定唯一来自 ``classify.upgradability.judge``；
本层只是让模型看着执行结果决定"下一步往哪里搜"，且预算（轮数 / 调用数）是硬的。
"""

from .loop import DEFAULT_MAX_ROUNDS, AgentRun, AgentStep, parse_action, run
from .tools import DEFAULT_MAX_CALLS, Tool, ToolBox

__all__ = ["AgentRun", "AgentStep", "DEFAULT_MAX_CALLS", "DEFAULT_MAX_ROUNDS",
           "Tool", "ToolBox", "parse_action", "run"]
