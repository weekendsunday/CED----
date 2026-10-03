"""单一入口（自动识别 + 自动编排）与设置窗口的测试。

覆盖消费者可见的行为：
  * 识别：HTTP 请求 → 原始字节；nuclei/Burp/HAR/curl/清单 → 各自的路；乱码 → 人话错误
  * 编排：链路节点都报过（DAG 才有东西可画）；**报告是逐行实时吐的**，且与最终报告一致
  * 产物：安全级发现自带端到端 PoC（步骤非空）
  * 设置：默认值 → 保存 → 密钥只回显掩码；拼错键/类型错都要当场报人话
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ced import detect, settings

CL_TE = (b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 48\r\n"
         b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
         b"GET /smuggled HTTP/1.1\r\nHost: localhost\r\n\r\n").decode("latin-1")
NUCLEI = json.dumps([{"template-id": "x", "matched-at": "https://example.com/a/b",
                      "host": "example.com"}])


class TestIdentify(unittest.TestCase):

    def test_http_request_is_recognized_as_raw_bytes(self):
        kind, why, hypotheses = detect.identify(CL_TE)
        self.assertEqual(kind, "raw-request")
        self.assertIn("请求行", why)
        self.assertEqual(hypotheses, [], "原始字节不该走外部假设那条路")

    def test_nuclei_result_is_recognized(self):
        kind, why, hypotheses = detect.identify(NUCLEI)
        self.assertEqual(kind, "nuclei")
        self.assertEqual(len(hypotheses), 1)

    def test_plain_list_is_accepted(self):
        kind, _, hypotheses = detect.identify("admin")
        self.assertEqual(kind, "list")
        self.assertTrue(hypotheses)

    def test_junk_is_rejected_with_a_human_message(self):
        with self.assertRaises(ValueError) as ctx:
            detect.identify("这不是任何已知形态的输入 ###")
        message = str(ctx.exception)
        self.assertIn("认不出", message)
        self.assertIn("接受的形态", message)
        self.assertIn("pcap", message, "要说清 pcap 为什么不支持、该怎么办")


class TestRun(unittest.TestCase):

    def test_raw_request_runs_the_whole_chain_and_streams_the_report(self):
        events: list[dict] = []
        result = detect.run(CL_TE, emit=events.append)

        nodes = {event["node"] for event in events if event["type"] == "stage"}
        self.assertTrue(set(detect.STAGES) <= nodes,
                        f"DAG 节点没报全：{sorted(nodes)}")
        states = {(event["node"], event["state"]) for event in events
                  if event["type"] == "stage"}
        self.assertIn(("identify", "done"), states)
        self.assertIn(("report", "done"), states)

        streamed = [event["line"] for event in events if event["type"] == "report"]
        self.assertTrue(streamed, "报告必须逐行实时吐")
        self.assertEqual("\n".join(streamed), result["report"],
                         "实时吐的报告与最终报告必须一致")

        self.assertEqual(result["kind"], "raw-request")
        self.assertGreater(result["summary"]["divergences"], 0)
        security = [item for item in result["findings"] if item["level"] == "security"]
        self.assertTrue(security, "CL+TE 应当判出安全级")
        self.assertEqual(security[0]["cwe"], "CWE-444")
        self.assertTrue(security[0]["poc"]["steps"], "安全级发现必须带复现步骤")
        self.assertIn("def ", security[0]["poc"]["script"])

    def test_domain_subset_is_respected(self):
        result = detect.run(CL_TE, domains=["url-norm"])
        self.assertEqual(list(result["domains"]), ["url-norm"])

    def test_external_findings_go_through_the_three_state_chain(self):
        result = detect.run(NUCLEI)
        self.assertEqual(result["kind"], "nuclei")
        self.assertTrue(result["findings"])
        self.assertIn(result["findings"][0]["verdict"],
                      ("confirmed", "refuted", "unverifiable"))
        self.assertEqual(sum(result["summary"][key] for key in
                             ("confirmed", "refuted", "unverifiable")), 1)


class TestSettings(unittest.TestCase):

    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(scratch.cleanup)
        self._old_path = settings.SETTINGS_PATH
        settings.SETTINGS_PATH = Path(scratch.name) / "ced-settings.json"
        self.addCleanup(lambda: setattr(settings, "SETTINGS_PATH", self._old_path))
        self._env = {key: os.environ.get(key) for key in
                     ("CED_LLM_BASE_URL", "CED_LLM_MODEL", "CED_LLM_API_KEY")}
        self.addCleanup(self._restore_env)

    def _restore_env(self) -> None:
        for key, value in self._env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_defaults_then_save_then_masked_key(self):
        self.assertFalse(settings.public_view()["llm"]["api_key_set"])
        saved = settings.save({"llm": {"base_url": "http://127.0.0.1:8000/v1",
                                       "model": "demo", "api_key": "sk-abcdef1234"}})
        self.assertEqual(saved["llm"]["model"], "demo")

        view = settings.public_view()
        self.assertTrue(view["llm"]["api_key_set"])
        self.assertNotIn("sk-abcdef1234", json.dumps(view), "密钥不许回显明文")
        self.assertTrue(view["llm"]["api_key"].endswith("1234"))
        self.assertTrue(settings.SETTINGS_PATH.exists())

    def test_unknown_key_and_wrong_type_are_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            settings.save({"llm": {"bas_url": "x"}})
        self.assertIn("未知设置项", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            settings.save({"capture": {"port": "abc"}})
        self.assertIn("需要 int", str(ctx.exception))
        with self.assertRaises(ValueError):
            settings.save({"不存在的分组": {}})

    def test_saved_llm_config_reaches_the_env(self):
        settings.save({"llm": {"base_url": "http://127.0.0.1:9999/v1",
                               "model": "m1", "api_key": "k1"}})
        self.assertEqual(os.environ.get("CED_LLM_MODEL"), "m1")
        self.assertEqual(os.environ.get("CED_LLM_BASE_URL"), "http://127.0.0.1:9999/v1")

    def test_broken_file_falls_back_to_defaults(self):
        settings.SETTINGS_PATH.write_text("{ 这不是 JSON", encoding="utf-8")
        self.assertEqual(settings.load()["capture"]["port"], 18081)


if __name__ == "__main__":
    unittest.main(verbosity=2)
