"""提示词组装、输出解析、无模型降级。

模型只被允许"提出往哪里搜"：这里把领域现状（已有轴、历史命中）写成提示词，
把输出硬塞进 ``schema`` 的严格校验，再交给 ``compile`` 的两道机械门槛。
本模块**不做准入实验**（那需要 evaluator），也**不产出任何判定**。

没有配置模型（``client is None`` 或 ``not client.available``）时返回空提案，
绝不抛异常打断扫描 —— 降级路径和正常路径共用一个入口。
"""
from __future__ import annotations

from ..contracts import Proposal, Rejected
from .client import LlmClient, LlmUnavailable
from .compile import compile_specs
from .schema import ProposalSpec, parse_specs

SYSTEM_PROMPT = """你是 CED（语义差分漏洞挖掘引擎）的提案者，不是裁判。

1. 你只负责提出"往哪里搜"，不产出任何判定。你的每一条候选都会被一道确定性差分实验逐条验证：只有真的让两个实现产生结构分歧的提案才会被采纳，其余自动丢弃。所以不要解释、不要下结论、不要声称发现了漏洞。
2. 只输出一个 JSON 数组，不要任何解释文字或 Markdown 围栏。每个元素形如：
{"axis": "轴名（小写字母开头的 snake_case，2-48 个字符，不得与已有轴重名）", "request": "完整的 HTTP/1.1 请求原文；换行用 \\r\\n 表示", "expect_field": "预期会在哪个结构字段上产生分歧（可选）", "rationale": "一句话说明为什么这个写法可能让两个实现产生不同理解"}
3. 请求必须落在 HTTP/1.1 消息分帧语法点上（Content-Length / Transfer-Encoding 的写法与优先级、chunk 语法、头语法、请求行形式），而且必须是**非规范写法**。完全规范的请求不会产生任何分歧，会被直接丢弃。"""


def build_prompt(*, adapter_name: str, n: int, existing_axes, history: str = "",
                 extra_context: str = "") -> str:
    """user 侧提示词：已有轴、历史命中、补充上下文、条数要求。"""
    axes = "、".join(str(a) for a in existing_axes) or "（无）"
    parts = [
        f"领域适配器：{adapter_name}",
        f"已有的手写轴（新提案不得与它们重名）：{axes}",
        f"请提出 {n} 条**新的**非规范请求提案。",
    ]
    if history:
        parts.append(history)
    if extra_context:
        parts.append(f"补充上下文：{extra_context}")
    parts.append("只输出 JSON 数组，不要任何解释文字。")
    return "\n\n".join(parts)


def propose(client: LlmClient | None, *, adapter_name: str = "http1-framing",
            n: int = 8, existing_axes=(), history: str = "",
            extra_context: str = "",
            specs=None) -> tuple[list[Proposal], list[Rejected], str]:
    """让模型提一批候选并过语法门槛。

    返回 ``(通过的提案, 被拒的, 模型原文)``。

    ``specs`` 给了已解析的 ``ProposalSpec`` 列表时跳过模型调用，直接走编译门槛
    （离线/单测用的旁路）；否则必须有可用 client，不可用即降级为空提案。
    """
    model = _model_name(client)

    if specs is not None:
        proposals, rejected = compile_specs(list(specs), model=model)
        return proposals, rejected, ""

    if client is None or not client.available:
        return [], [], ""

    prompt = build_prompt(adapter_name=adapter_name, n=n,
                          existing_axes=existing_axes, history=history,
                          extra_context=extra_context)
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}]

    try:
        text = client.chat(messages)
    except LlmUnavailable as exc:
        return [], [Rejected("", "模型不可用", str(exc))], ""

    try:
        raw_specs, rejected = parse_specs(text)
    except ValueError as exc:
        detail = text[:500] if text else str(exc)
        return [], [Rejected("", "模型输出不是合法 JSON", detail)], text

    proposals, compile_rejected = compile_specs(raw_specs, model=model)
    return proposals, rejected + compile_rejected, text


def _model_name(client: LlmClient | None) -> str:
    config = getattr(client, "config", None)
    name = getattr(config, "model", "")
    return name if isinstance(name, str) else ""


def spec_from_text(axis: str, request: str, *, expect_field: str = "",
                   rationale: str = "") -> ProposalSpec:
    """便捷构造：给手写/外部来源的文本套上同一套规格（便于离线旁路）。"""
    return ProposalSpec(axis=axis, request=request,
                        expect_field=expect_field, rationale=rationale)
