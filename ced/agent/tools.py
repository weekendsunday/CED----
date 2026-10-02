"""Agent 的工具表 —— 模型能做的每一件事，都必须是引擎**已有**的能力。

不变式：**工具只返回数据，绝不返回判定。**
模型没有任何一个工具能写出 ``level`` / ``cwe`` / ``scenario`` ——
它拿到的每一条结论都来自 ``classify.upgradability.judge``。
它唯一能影响的是"接下来往哪里搜"（提案 / 换模式 / 看证据）。

工具的入参都要过一遍白名单校验：模型给错名字、错参数、越界值，
一律记成 ``ok=False`` 的观测喂回去让它自己改，而不是抛异常打断整个循环。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .. import store
from ..assist.compile import admit as admit_proposals
from ..assist.ledger import record_many, record_rejected
from ..assist.propose import propose as propose_axes
from ..contracts import Proposal
from ..mutate import axes
from ..pipeline import ScanResult, scan
from ..scenario import build_poc

#: 一次 agent 运行里，工具被调用的硬上限 —— 防跑飞
DEFAULT_MAX_CALLS = 12
#: 单次 scan_corpus 允许的用例上限
MAX_LIMIT = 2000
MAX_PROPOSALS = 20


@dataclass(frozen=True)
class Tool:
    """一个可被模型调用的动作。``parameters`` 只用于**校验与展示**，不执行模型给的代码。"""

    name: str
    description: str
    parameters: dict[str, str]
    handler: Callable[[dict], dict]
    optional: bool = True


@dataclass
class ToolBox:
    """工具集 + 运行状态（累计的提案、扫描结果、按 case_id 索引的发现）。"""

    adapter: Any
    evaluator: Any
    conn: Any = None
    client: Any = None
    mode: str = "axis"
    limit: int | None = 60
    seed: int = 42
    max_calls: int = DEFAULT_MAX_CALLS

    proposals: list[tuple[str, bytes]] = field(default_factory=list)
    results: list[ScanResult] = field(default_factory=list)
    calls: int = 0
    finished: bool = False
    summary: str = ""
    _findings: dict[str, Any] = field(default_factory=dict, repr=False)

    # ---------------------------------------------------------------- 注册表

    def tools(self) -> dict[str, Tool]:
        return {tool.name: tool for tool in (
            Tool("scan_corpus",
                 "跑一轮差分扫描（包含已入池的提案），返回汇总与按轴分组的命中。"
                 "判定由确定性内核给出，不是模型说的。",
                 {"mode": "axis | cross（可选，默认沿用本次运行的模式）",
                  "limit": "整数，1..%d（可选）" % MAX_LIMIT},
                 self._scan_corpus),
            Tool("propose_axes",
                 "让模型提出新的非规范请求提案。每条提案都会被两道机械门槛筛过："
                 "语法/白名单编译 + 差分 oracle 准入实验；通不过的直接丢弃、不算数。"
                 "通过准入的自动入池，下一轮 scan_corpus 会带上它们。"
                 "**注意：这个工具会额外向模型要一次提案**（多花一次模型调用，但不占工具预算）。",
                 {"n": "整数，1..%d（可选，默认 8）" % MAX_PROPOSALS},
                 self._propose_axes),
            Tool("inspect",
                 "看一条发现（case_id）的完整证据：两侧观测差异、消融实验、"
                 "最小复现样本、链式复现、端到端 PoC 步骤。",
                 {"case_id": "字符串，来自 scan_corpus 返回的 findings"},
                 self._inspect),
            Tool("ledger",
                 "看提案台账：命中率（模型 vs 手写轴，同一把尺子）与最近的轴族。",
                 {}, self._ledger),
            Tool("finish",
                 "结束本次运行并给出结论性说明。注意：说明是叙述，不是判定。",
                 {"summary": "字符串，这段叙述会被记入运行轨迹"},
                 self._finish, optional=False),
        )}

    def spec(self) -> list[dict]:
        """给模型看的工具清单。"""
        return [{"name": t.name, "description": t.description,
                 "parameters": t.parameters} for t in self.tools().values()]

    # ---------------------------------------------------------------- 调度

    def call(self, name: str, args: dict | None) -> dict:
        """校验并执行一次工具调用。**永不抛异常** —— 失败也是一种观测。"""
        args = args if isinstance(args, dict) else {}
        if self.calls >= self.max_calls:
            return {"ok": False, "error": f"已用完 {self.max_calls} 次工具调用的预算",
                    "hint": "请立刻用 finish 结束"}
        table = self.tools()
        tool = table.get(name)
        if tool is None:
            return {"ok": False,
                    "error": f"没有这个工具：{name}",
                    "hint": f"可用工具：{', '.join(sorted(table))}"}
        self.calls += 1
        try:
            out = tool.handler(args)
        except Exception as exc:                       # noqa: BLE001 —— 工具异常也是观测
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        return out

    # ---------------------------------------------------------------- 工具实现

    def _scan_corpus(self, args: dict) -> dict:
        mode = str(args.get("mode") or self.mode)
        if mode not in ("axis", "cross"):
            return {"ok": False, "error": f"mode 只能是 axis 或 cross，收到 {mode!r}"}
        limit = args.get("limit", self.limit)
        if limit is not None:
            if not isinstance(limit, int) or isinstance(limit, bool):
                return {"ok": False, "error": "limit 必须是整数"}
            if not 1 <= limit <= MAX_LIMIT:
                return {"ok": False, "error": f"limit 必须在 1..{MAX_LIMIT} 之间"}

        result = scan(self.adapter, self.evaluator, mode=mode, limit=limit,
                      seed=self.seed, do_minimize=True,
                      extra_cases=list(self.proposals))
        self.results.append(result)
        for finding in result.findings:
            self._findings.setdefault(finding.case_id, finding)

        by_axis: dict[str, dict[str, int]] = {}
        for finding in result.findings:
            bucket = by_axis.setdefault(finding.divergence.axis,
                                        {"total": 0, "security": 0})
            bucket["total"] += 1
            bucket["security"] += int(finding.verdict.is_security)

        return {
            "ok": True,
            "mode": mode, "limit": limit,
            "total_cases": result.total_cases, "jobs": result.jobs,
            "proposed_cases": result.proposed_cases,
            "rejected_cases": result.rejected_cases,
            "divergences": len(result.divergences),
            "security": len(result.security),
            "by_axis": by_axis,
            "findings": [_brief(f) for f in _top(result)],
            "note": "判定来自确定性内核（差分 + 消融），不是模型自述。",
        }

    def _propose_axes(self, args: dict) -> dict:
        want = args.get("n", 8)
        if not isinstance(want, int) or isinstance(want, bool) or not 1 <= want <= MAX_PROPOSALS:
            return {"ok": False, "error": f"n 必须是 1..{MAX_PROPOSALS} 的整数"}
        if self.client is None or not getattr(self.client, "available", False):
            return {"ok": False,
                    "error": "未配置模型（CED_LLM_BASE_URL / CED_LLM_MODEL）",
                    "hint": "改用 scan_corpus 继续，或直接 finish"}

        history = store.proposal_history_brief(self.conn) if self.conn else ""
        proposals, rejected, _raw = propose_axes(
            self.client, adapter_name=self.adapter.name, n=want,
            existing_axes=axes.AXES, history=history)
        for item in rejected:
            if self.conn is not None:
                record_rejected(self.conn, item)

        if not proposals:
            return {"ok": True, "admitted": 0, "items": [],
                    "rejected": [r.reason for r in rejected],
                    "hint": "模型没产出可用提案；换一轮或直接 finish"}

        admissions = admit_proposals(proposals, self.adapter, self.evaluator)
        if self.conn is not None:
            record_many(self.conn, admissions)

        admitted = [a for a in admissions if a.admitted]
        for admission in admitted:
            case = admission.proposal.to_case()
            if case not in self.proposals:
                self.proposals.append(case)

        return {
            "ok": True,
            "admitted": len(admitted),
            "rejected": len(rejected) + (len(admissions) - len(admitted)),
            "items": [{"axis": a.proposal.axis, "admitted": a.admitted,
                       "fields": list(a.fields), "note": a.detail}
                      for a in admissions],
            "pool": len(self.proposals),
            "note": "只有通过差分 oracle 准入实验的提案才入池。",
        }

    def _inspect(self, args: dict) -> dict:
        case_id = str(args.get("case_id") or "")
        finding = self._findings.get(case_id)
        if finding is None:
            return {"ok": False, "error": f"没有这个 case_id：{case_id or '(空)'}",
                    "hint": f"已知：{', '.join(sorted(self._findings)[:12])}"[:300]}
        divergence = finding.divergence
        payload = finding.minimized if finding.minimized is not None else divergence.payload
        out = {
            "ok": True,
            "case_id": case_id,
            "level": finding.verdict.level,
            "kind": finding.verdict.kind,
            "left": divergence.left.impl_id,
            "right": divergence.right.impl_id,
            "axis": divergence.axis,
            "diffs": {d.key: [d.left, d.right] for d in divergence.diffs},
            "ablation": finding.verdict.ablation,
            "reason": finding.verdict.reason,
            "sample_repr": repr(payload),
            "sample_len": len(payload),
            "chain_evidence": finding.chain_evidence,
        }
        poc = build_poc(finding)
        if poc is not None:
            out["scenario"] = poc.scenario
            out["impact"] = poc.impact
            out["steps"] = list(poc.steps)
            out["forwarded"] = poc.forwarded
            out["back_consumed"] = poc.back_consumed
            out["smuggled_len"] = poc.smuggled_len
        return out

    def _ledger(self, args: dict) -> dict:
        if self.conn is None:
            return {"ok": True, "stats": {}, "note": "本次运行未挂台账库"}
        stats = store.proposal_stats(self.conn)
        recent = store.recent_proposals(self.conn, limit=20)
        return {
            "ok": True,
            "stats": stats,
            "recent": [{"axis": r["axis"], "origin": r["origin"],
                        "compiled": r["compiled"], "admitted": r["admitted"],
                        "note": r["note"][:120]} for r in recent],
            "note": "命中 = 提案通过了差分 oracle 的准入实验，不是模型自述。",
        }

    def _finish(self, args: dict) -> dict:
        self.summary = str(args.get("summary") or "")
        self.finished = True
        return {"ok": True, "summary": self.summary}


# --------------------------------------------------------------------- 小工具

def _brief(finding) -> dict:
    """给模型的紧凑视图 —— 省上下文，但保留可复核的关键字段。"""
    return {
        "case_id": finding.case_id,
        "level": finding.verdict.level,
        "kind": finding.verdict.kind,
        "left": finding.divergence.left.impl_id,
        "right": finding.divergence.right.impl_id,
        "axis": finding.divergence.axis,
        "fields": finding.divergence.keys,
        "controllable": finding.verdict.controllable,
    }


def _top(result: ScanResult, cap: int = 12) -> list:
    """按严重程度排序后取前若干 —— 别把整轮发现灌进模型上下文。"""
    order = {"security": 0, "unknown": 1, "compatibility": 2}
    ranked = sorted(result.findings,
                    key=lambda f: order.get(f.verdict.level, 9))
    return ranked[:cap]


__all__ = ["Tool", "ToolBox", "DEFAULT_MAX_CALLS", "MAX_LIMIT", "MAX_PROPOSALS"]
