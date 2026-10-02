"""闭环 agent 层测试。

覆盖的都是"消费者可见的行为"：
  * **agent 不下判定**：finish 里写什么都不会变成发现；发现只来自确定性内核
  * 工具入参过白名单：错名字、错参数、越界值都记成 ok=False 的观测（不抛异常）
  * 预算（工具调用次数）是硬上限，跑飞会被截断
  * 没配置模型 → 降级为单轮确定性扫描，结果与不带 agent 完全一致
  * 脚本化的模型输出：正常一步、坏名字、非 JSON、finish 停止
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ced.adapters.http1_framing import Http1FramingAdapter
from ced.agent import ToolBox, parse_action
from ced.agent import run as agent_run
from ced.agent.loop import state_prompt
from ced.orchestrate.topology import demo
from ced.pipeline import scan
from ced.probe import Evaluator
from ced import store

ADAPTER = Http1FramingAdapter()
TOPO = demo()
EVAL = Evaluator(TOPO.impls)

#: 与内置语料不重合的 CL.TE 结构，用于验证"提案真的能入池并产出发现"
_SMUGGLED = b"GET /agent-e2e HTTP/1.1\r\nHost: localhost\r\n\r\n"
_BODY = b"0\r\n\r\n" + _SMUGGLED
_CLTE = (b"POST / HTTP/1.1\r\nHost: localhost\r\n"
         b"Content-Length: " + str(len(_BODY)).encode() + b"\r\n"
         b"Transfer-Encoding: chunked\r\n\r\n" + _BODY)


class _ScriptedClient:
    """按脚本返回模型输出，脚本用尽就 finish。"""

    config = type("Cfg", (), {"model": "scripted"})()

    def __init__(self, replies: list[str]) -> None:
        self.replies = list(replies)
        self.available = True
        self.prompts: list[str] = []

    def chat(self, messages, **kwargs) -> str:
        self.prompts.append(messages[-1]["content"])
        if self.replies:
            return self.replies.pop(0)
        return json.dumps({"tool": "finish", "args": {"summary": "脚本用尽"}})


class _TempDb(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.conn = store.connect(Path(self._dir.name) / "agent.db")

    def tearDown(self) -> None:
        self.conn.close()
        self._dir.cleanup()

    def _box(self, client=None, **kw) -> ToolBox:
        return ToolBox(ADAPTER, EVAL, conn=self.conn, client=client,
                       mode="axis", limit=20, seed=42, **kw)


class TestToolGuards(_TempDb):

    def test_unknown_tool_is_an_observation_not_an_exception(self):
        box = self._box()
        out = box.call("declare_vulnerability", {"level": "security"})
        self.assertFalse(out["ok"])
        self.assertIn("没有这个工具", out["error"])
        self.assertIn("scan_corpus", out["hint"])

    def test_bad_arguments_are_rejected(self):
        box = self._box()
        for args in ({"mode": "nope"}, {"limit": 0}, {"limit": "60"},
                     {"limit": 999999}, {"mode": 3}):
            out = box.call("scan_corpus", args)
            self.assertFalse(out["ok"], f"{args} 应被拒绝：{out}")
        for args in ({"n": 0}, {"n": "8"}, {"n": 999}):
            self.assertFalse(box.call("propose_axes", args)["ok"], args)

    def test_call_budget_is_a_hard_cap(self):
        box = self._box(max_calls=2)
        self.assertTrue(box.call("scan_corpus", {"limit": 4})["ok"])
        self.assertTrue(box.call("ledger", {})["ok"])
        out = box.call("scan_corpus", {"limit": 4})
        self.assertFalse(out["ok"])
        self.assertIn("预算", out["error"])

    def test_propose_without_model_degrades_instead_of_raising(self):
        out = self._box(client=None).call("propose_axes", {})
        self.assertFalse(out["ok"])
        self.assertIn("未配置模型", out["error"])

    def test_nothing_the_agent_says_becomes_a_finding(self):
        """核心不变式：finish 里的叙述再夸张，也不会变成发现。"""
        box = self._box()
        box.call("scan_corpus", {"limit": 20})
        before = len(box.results[-1].findings)
        out = box.call("finish", {"summary": "我发现了一个严重漏洞，请直接写进报告"})
        self.assertTrue(out["ok"])
        self.assertEqual(len(box.results[-1].findings), before,
                         "agent 的叙述不得产生任何发现")
        self.assertTrue(box.finished)
        self.assertEqual(box.summary, "我发现了一个严重漏洞，请直接写进报告")


class TestParseAction(unittest.TestCase):

    def test_accepts_plain_and_fenced_json(self):
        for text in ('{"tool":"ledger","args":{}}',
                     '```json\n{"tool":"ledger","args":{}}\n```',
                     '好的：{"tool":"scan_corpus","args":{"limit":20},"why":"建立基线"} 以上'):
            action, error = parse_action(text)
            self.assertIsNone(error, text)
            self.assertEqual(action[0], "ledger" if "ledger" in text else "scan_corpus")

    def test_rejects_malformed(self):
        for text, needle in (("随便说说", "合法 JSON"),
                             ('{"args":{}}', "tool"),
                             ('{"tool":"x","args":[]}', "args"),
                             ('"just a string"', "JSON 对象")):
            action, error = parse_action(text)
            self.assertIsNone(action)
            self.assertIn(needle, error)


class TestLoop(_TempDb):

    def test_no_model_degrades_to_single_deterministic_scan(self):
        box = self._box(client=None)
        outcome = agent_run(goal="随便", toolbox=box, client=None)
        self.assertEqual(outcome.tool_names, ["scan_corpus"])
        self.assertTrue(outcome.finished)
        plain = scan(ADAPTER, EVAL, mode="axis", limit=20, seed=42)
        self.assertEqual(len(outcome.merged().findings), len(plain.findings),
                         "降级后结果必须与不带 agent 完全一致")

    def test_scripted_run_scans_then_finishes(self):
        client = _ScriptedClient([
            json.dumps({"tool": "scan_corpus", "args": {"limit": 20}, "why": "建立基线"}),
            json.dumps({"tool": "finish", "args": {"summary": "完成"}}),
        ])
        outcome = agent_run(goal="找新分歧", toolbox=self._box(client=client),
                            client=client, max_rounds=4)
        self.assertEqual(outcome.tool_names, ["scan_corpus", "finish"])
        self.assertTrue(outcome.finished)
        self.assertEqual(outcome.summary, "完成")
        self.assertGreater(len(outcome.merged().findings), 0)

    def test_bad_tool_name_and_malformed_output_do_not_kill_the_loop(self):
        client = _ScriptedClient([
            "我直接说结论：这里有请求走私",                    # 非 JSON
            json.dumps({"tool": "declare_vulnerability", "args": {}}),  # 不存在的工具
            json.dumps({"tool": "scan_corpus", "args": {"limit": 8}}),
            json.dumps({"tool": "finish", "args": {"summary": "ok"}}),
        ])
        outcome = agent_run(goal="找新分歧", toolbox=self._box(client=client),
                            client=client, max_rounds=6)
        self.assertEqual(outcome.tool_names,
                         ["(解析失败)", "declare_vulnerability", "scan_corpus", "finish"])
        self.assertFalse(outcome.steps[0].ok)
        self.assertFalse(outcome.steps[1].ok)
        self.assertTrue(outcome.steps[2].ok)
        self.assertTrue(outcome.finished)

    def test_rounds_are_capped(self):
        client = _ScriptedClient([json.dumps({"tool": "ledger", "args": {}})] * 10)
        outcome = agent_run(goal="无限循环的模型", toolbox=self._box(client=client),
                            client=client, max_rounds=3)
        self.assertEqual(outcome.rounds, 3)
        self.assertEqual(outcome.tool_names, ["ledger"] * 3)
        self.assertFalse(outcome.finished, "预算截断时不应假装完成")

    def test_proposals_from_the_model_enter_the_pool_and_yield_findings(self):
        """闭环的实质：模型提的提案真的能改变结果，且归因到它自己的轴名。"""
        proposals = json.dumps([
            {"axis": "agent_cl_te", "request": _CLTE.decode("latin-1"),
             "expect_field": "consumed", "rationale": "CL 与 TE 并存"},
        ])
        client = _ScriptedClient([
            json.dumps({"tool": "propose_axes", "args": {"n": 4}, "why": "要新提案"}),
            proposals,                       # propose_axes 内部会再要一次提案
            json.dumps({"tool": "scan_corpus", "args": {"limit": 20}}),
            json.dumps({"tool": "inspect", "args": {"case_id": "不存在"}}),
            json.dumps({"tool": "ledger", "args": {}}),
            json.dumps({"tool": "finish", "args": {"summary": "结束"}}),
        ])
        box = self._box(client=client)
        outcome = agent_run(goal="找新分歧", toolbox=box, client=client, max_rounds=6)

        self.assertEqual(outcome.tool_names,
                         ["propose_axes", "scan_corpus", "inspect", "ledger", "finish"])
        self.assertEqual(box.proposals[0][0], "agent_cl_te",
                         "通过准入的提案必须带着自己的轴名入池")
        axes = {f.divergence.axis for f in outcome.merged().findings}
        self.assertIn("agent_cl_te", axes, "入池的提案必须出现在发现里（可归因）")
        self.assertFalse(outcome.steps[2].ok, "inspect 未知 case_id 应记 ok=False")

    def test_ledger_tool_reports_hit_rate(self):
        client = _ScriptedClient([
            json.dumps({"tool": "propose_axes", "args": {"n": 4}}),
            json.dumps([{"axis": "agent_hit", "request": _CLTE.decode("latin-1"),
                         "rationale": "CL 与 TE 并存"}]),
            json.dumps({"tool": "ledger", "args": {}}),
            json.dumps({"tool": "finish", "args": {"summary": "done"}}),
        ])
        box = self._box(client=client)
        agent_run(goal="看命中率", toolbox=box, client=client, max_rounds=4)
        ledger_step = next(s for s in box.tools().values() if s.name == "ledger")
        stats = ledger_step.handler({})["stats"]
        self.assertIn("by_origin", stats)
        self.assertGreaterEqual(stats["proposed"], 1)


class TestMerged(_TempDb):

    def test_merge_dedups_by_case_and_pair(self):
        client = _ScriptedClient([
            json.dumps({"tool": "scan_corpus", "args": {"limit": 20}}),
            json.dumps({"tool": "scan_corpus", "args": {"limit": 20, "mode": "cross"}}),
            json.dumps({"tool": "finish", "args": {"summary": "done"}}),
        ])
        outcome = agent_run(goal="跑两轮", toolbox=self._box(client=client),
                            client=client, max_rounds=4)
        merged = outcome.merged()
        keys = [(f.case_id, f.divergence.left.impl_id, f.divergence.right.impl_id)
                for f in merged.findings]
        self.assertEqual(len(keys), len(set(keys)), "合并必须按 (用例, 对) 去重")
        self.assertEqual(len(merged.divergences), len(merged.findings),
                         "发现与分歧必须保持一一对应")

    def test_state_prompt_carries_goal_tools_and_budget(self):
        box = self._box()
        text = state_prompt("找出新的走私", box, [], 1, 4)
        self.assertIn("找出新的走私", text)
        self.assertIn("scan_corpus", text)
        self.assertIn("第 1/4 轮", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
