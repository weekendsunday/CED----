"""LLM 辅助提案层：把大模型限制在"提案者"位置。

包内职责：
  ``schema``   模型原始输出 → 严格校验的 ``ProposalSpec``（逐条失败逐条丢）
  ``client``   OpenAI 兼容 HTTP 客户端（纯 urllib；全包唯一的网络出口）
  ``compile``  两道机械门槛：语法/白名单编译 ①、差分 oracle 准入实验 ②
  ``ledger``   提案台账：命中率口径的唯一底座（只认"逼出分歧"）
  ``propose``  提示词组装、输出解析、无模型全链路降级

不变式：本包**不产出任何判定**，也不修改引擎。提案影响搜索方向的唯一路径是
"变成一条候选语料"，能不能升格成发现由确定性差分 oracle 说了算 ——
幻觉在类型上就写不出结论。
"""
from __future__ import annotations

from .client import LlmClient, LlmConfig, LlmUnavailable, config_from_env
from .compile import Admission, admit, compile_specs, framing_relevant
from .ledger import history, recent, record, record_many, record_rejected, summary
from .propose import SYSTEM_PROMPT, build_prompt, propose, spec_from_text
from .schema import ProposalSpec, extract_json, parse_specs

__all__ = [
    "Admission", "LlmClient", "LlmConfig", "LlmUnavailable", "ProposalSpec",
    "SYSTEM_PROMPT", "admit", "build_prompt", "compile_specs", "config_from_env",
    "extract_json", "framing_relevant", "history", "parse_specs", "propose",
    "recent", "record", "record_many", "record_rejected", "spec_from_text",
    "summary",
]
