"""闭环 agent 层：让模型看着**上一轮的执行结果**决定下一轮往哪里搜。

它补上的是 ``docs/漏洞挖掘步骤.md`` 里那句承诺：
「LLM 生成假设 + 执行反馈闭环筛选，让假设自动产生可验证探针」。

**这不是把内核换成 agent**，而是把 agent 加到内核外面：

    模型 → 选工具 → 确定性内核执行 → 结构化观测 → 回写台账 → 模型再选工具

模型的每一条结论都必须穿过两道机械门槛（语法/白名单 + 差分 oracle 准入实验）；
它没有任何工具能写出判定。预算（轮数 / 工具调用数）是硬的，跑飞了会被截断。
没配置模型时**全链路降级**为单轮确定性扫描，结果与不带 agent 完全一致。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

from ..assist.client import LlmUnavailable
from ..assist.schema import extract_json
from ..pipeline import ScanResult

#: 默认最多几轮（每轮一次工具调用）
DEFAULT_MAX_ROUNDS = 4

SYSTEM_PROMPT = """你是 CED（语义差分漏洞挖掘引擎）的调度者，不是裁判。

你可以调用工具来推进搜索。规则：
1. 你**不下任何判定**。每条发现的级别（security / unknown / compatibility）都由确定性内核
   用「差分 + 消融实验」给出。你说的任何结论都只是叙述，不进结果。
2. 每轮只输出**一个** JSON 对象，不要解释文字、不要 Markdown 围栏：
   {"tool": "工具名", "args": {...}, "why": "一句话说明为什么调它"}
3. 你的价值在于**决定往哪里搜**：看上一轮哪些轴命中了、哪些没中，再决定
   propose_axes（要新提案）还是 scan_corpus（换模式/换预算再跑），最后 finish。
4. 预算有限。工具返回 ok=false 时看 error 自己改正，别重复同样的错。
5. 不要重复调用参数完全相同的工具 —— 结果不会变。
"""


@dataclass
class AgentStep:
    """一次工具调用及其观测。整条轨迹就是 agent 的"思考过程"证据。"""

    round: int
    tool: str
    args: dict
    ok: bool
    observation: dict
    why: str = ""


@dataclass
class AgentRun:
    goal: str
    steps: list[AgentStep] = field(default_factory=list)
    results: list[Any] = field(default_factory=list)
    finished: bool = False
    summary: str = ""
    error: str | None = None

    @property
    def rounds(self) -> int:
        return max((s.round for s in self.steps), default=0)

    @property
    def findings(self) -> list:
        """全部轮次里**由内核判定**为安全级的发现（按 case_id 去重）。"""
        out, seen = [], set()
        for result in self.results:
            for finding in result.security:
                if finding.case_id not in seen:
                    seen.add(finding.case_id)
                    out.append(finding)
        return out

    @property
    def tool_names(self) -> list[str]:
        return [s.tool for s in self.steps]

    def merged(self) -> ScanResult:
        """把各轮结果并成一份 —— 报告 / 落库 / PoC 都吃这一份。

        去重键是 ``(case_id, 左实现, 右实现)``：同一份字节对不同实现对分叉，
        是不同的事实，不能按 case_id 一刀切掉。
        用例数按轮次累加（它衡量的是"总共跑了多少"，不是唯一用例数）。
        """
        merged = ScanResult()
        seen: set[tuple[str, str, str]] = set()
        for result in self.results:
            merged.total_cases += result.total_cases
            merged.jobs += result.jobs
            merged.proposed_cases += result.proposed_cases
            merged.rejected_cases += result.rejected_cases
            if not merged.compare_keys:
                merged.compare_keys = result.compare_keys
            if not merged.impl_ids:
                merged.impl_ids = list(result.impl_ids)
            for finding in result.findings:
                key = (finding.case_id, finding.divergence.left.impl_id,
                       finding.divergence.right.impl_id)
                if key in seen:
                    continue
                seen.add(key)
                merged.divergences.append(finding.divergence)
                merged.findings.append(finding)
        return merged


# --------------------------------------------------------------------- 动作解析

def parse_action(text: str) -> tuple[tuple[str, dict, str] | None, str | None]:
    """从模型输出里抠出一次工具调用。返回 ``(action, error)``。"""
    try:
        obj = extract_json(text or "")
    except ValueError as exc:
        return None, f"输出不是合法 JSON：{exc}"
    if isinstance(obj, list):
        obj = obj[0] if obj else None
    if not isinstance(obj, dict):
        return None, "输出必须是一个 JSON 对象"
    name = obj.get("tool")
    if not isinstance(name, str) or not name.strip():
        return None, "缺少 tool 字段"
    args = obj.get("args", {})
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return None, "args 必须是对象"
    why = obj.get("why") if isinstance(obj.get("why"), str) else ""
    return (name.strip(), args, why), None


# --------------------------------------------------------------------- 状态提示

def _digest(observation: dict, cap: int = 1600) -> str:
    text = json.dumps(observation, ensure_ascii=False)
    return text if len(text) <= cap else text[:cap] + "…(截断)"


def state_prompt(goal: str, toolbox, steps: list[AgentStep], round_no: int,
                 max_rounds: int) -> str:
    """每轮重建一次状态 —— 不累积历史，避免上下文被轨迹灌爆。"""
    parts = [
        f"总目标：{goal}",
        f"进度：第 {round_no}/{max_rounds} 轮；"
        f"已用工具调用 {toolbox.calls}/{toolbox.max_calls}；"
        f"已入池提案 {len(toolbox.proposals)} 条",
        "可用工具（JSON）：\n" + json.dumps(toolbox.spec(), ensure_ascii=False),
    ]
    if steps:
        lines = []
        for step in steps:
            mark = "ok" if step.ok else "FAILED"
            lines.append(f"- 第{step.round}轮 {step.tool} [{mark}] {_digest(step.observation)}")
        parts.append("已执行的动作与观测：\n" + "\n".join(lines))
    else:
        parts.append("还没有执行任何动作。建议先 scan_corpus 建立基线，再决定要不要提案。")
    parts.append("现在只输出一个 JSON 对象：{\"tool\": ..., \"args\": {...}, \"why\": ...}")
    return "\n\n".join(parts)


# --------------------------------------------------------------------- 主循环

def run(*, goal: str, toolbox, client=None, max_rounds: int = DEFAULT_MAX_ROUNDS,
        on_event: Callable[[dict], None] | None = None) -> AgentRun:
    """跑一次闭环。**永不抛异常** —— 模型挂了也保留已经收集到的结果。"""
    run_ = AgentRun(goal=goal)

    def emit(event: dict) -> None:
        if on_event is not None:
            on_event(event)

    if client is None or not getattr(client, "available", False):
        # 降级：没有模型就没有闭环 —— 单轮确定性扫描，结果与不带 agent 一致
        observation = toolbox.call("scan_corpus", {})
        run_.steps.append(AgentStep(1, "scan_corpus", {}, bool(observation.get("ok")),
                                    observation,
                                    why="未配置模型 —— 降级为单轮确定性扫描"))
        run_.results = list(toolbox.results)
        run_.finished = True
        run_.summary = "未配置模型：本次为单轮确定性扫描，结果与不带 agent 完全一致。"
        emit({"type": "agent", "round": 1, "tool": "scan_corpus",
              "ok": bool(observation.get("ok")), "note": run_.summary})
        return run_

    for round_no in range(1, max_rounds + 1):
        if toolbox.finished:
            break
        if toolbox.calls >= toolbox.max_calls:
            run_.summary = f"工具调用预算用尽（{toolbox.max_calls} 次）。"
            break

        prompt = state_prompt(goal, toolbox, run_.steps, round_no, max_rounds)
        try:
            text = client.chat([{"role": "system", "content": SYSTEM_PROMPT},
                                {"role": "user", "content": prompt}])
        except LlmUnavailable as exc:
            run_.error = f"模型不可用：{exc}"
            emit({"type": "agent", "round": round_no, "tool": "(模型不可用)",
                  "ok": False, "note": str(exc)})
            break

        action, error = parse_action(text)
        if action is None:
            run_.steps.append(AgentStep(round_no, "(解析失败)", {}, False,
                                        {"error": error, "raw": (text or "")[:400]}))
            emit({"type": "agent", "round": round_no, "tool": "(解析失败)",
                  "ok": False, "note": error or ""})
            continue

        name, args, why = action
        observation = toolbox.call(name, args)
        run_.steps.append(AgentStep(round_no, name, args,
                                    bool(observation.get("ok")), observation, why))
        emit({"type": "agent", "round": round_no, "tool": name,
              "ok": bool(observation.get("ok")),
              "note": why or observation.get("error", "")})

    run_.results = list(toolbox.results)
    run_.finished = toolbox.finished
    if toolbox.summary:
        run_.summary = toolbox.summary
    elif not run_.summary:
        run_.summary = ("预算用尽，已停止。结论以确定性内核给出的分级为准。")
    emit({"type": "agent_done", "rounds": run_.rounds,
          "security": len(run_.findings), "summary": run_.summary})
    return run_


__all__ = ["AgentRun", "AgentStep", "DEFAULT_MAX_ROUNDS", "SYSTEM_PROMPT",
           "parse_action", "run", "state_prompt"]
