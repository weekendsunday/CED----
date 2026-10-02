"""assist 层测试：全部离线，不发起任何真实网络请求。

覆盖的都是"消费者可见的行为"：
  * 模型输出解析：围栏/解说文字容忍、逐条失败逐条丢、幻觉字段丢弃
  * 语法门槛：非规范写法放行、规范请求拒绝、非消息拒绝
  * 准入实验：真的逼出分歧才命中，探针异常绝不伪装成命中，无本地对照保守拒绝
  * 客户端：未配置即不可用、请求体/URL/鉴权头正确、任何异常都降级为 LlmUnavailable
  * 提示词与降级：没有模型时必须返回空提案，绝不抛异常
  * 台账：命中口径只认 admitted，且幂等只看涨不看跌
"""
from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ced import store
from ced.adapters.http1_framing import Http1FramingAdapter
from ced.assist.client import LlmClient, LlmConfig, LlmUnavailable, config_from_env
from ced.assist.compile import Admission, admit, compile_specs, framing_relevant
from ced.assist.ledger import record, record_rejected, summary
from ced.assist.propose import propose
from ced.assist.schema import ProposalSpec, extract_json, parse_specs
from ced.contracts import ORIGIN_LLM, ImplSpec, Proposal, Rejected
from ced.impls import reference
from ced.mutate.axes import AXES
from ced.probe import Evaluator

ADAPTER = Http1FramingAdapter()
EVAL = Evaluator(reference.specs())

#: 完全规范的请求 —— 两侧必然一致
_CANONICAL = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nabc"

#: 经典 CL.TE：CL 覆盖整段、TE 只消费到 0 块结束 → 结构分歧
_CL_TE = (b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
          b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")

#: 非规范（重复 CL）但所有参照实现理解一致 → 不该命中
_DUP_CL = (b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n"
           b"Content-Length: 3\r\n\r\nabc")


def _proposal(axis: str, payload: bytes) -> Proposal:
    return Proposal(axis=axis, payload=payload, origin=ORIGIN_LLM)


class _Resp:
    """urlopen 的返回替身（支持 with 语义）。"""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_Resp":
        return self

    def __exit__(self, *_: object) -> bool:
        return False


class _FakeClient:
    """可控的假客户端：离线驱动 propose 的每条分支。"""

    def __init__(self, reply: str = "", available: bool = True,
                 error: Exception | None = None) -> None:
        self.config = LlmConfig(base_url="http://x/v1", model="fake-model")
        self._reply = reply
        self._available = available
        self._error = error
        self.calls: list[list[dict]] = []

    @property
    def available(self) -> bool:
        return self._available

    def chat(self, messages: list[dict], **_: object) -> str:
        self.calls.append(messages)
        if self._error is not None:
            raise self._error
        return self._reply


class TestSchema(unittest.TestCase):

    def test_extract_json_strips_fence(self):
        text = '这是候选：\n```json\n[{"axis":"aa_b"}]\n```\n完毕'
        self.assertEqual(extract_json(text), [{"axis": "aa_b"}])

    def test_extract_json_embedded_in_prose(self):
        text = '好的，结果如下 [{"axis":"aa_b"}, {"axis":"cc_d"}] 以上'
        self.assertEqual(extract_json(text), [{"axis": "aa_b"}, {"axis": "cc_d"}])

    def test_extract_json_rejects_garbage(self):
        with self.assertRaises(ValueError):
            extract_json("没有任何 JSON 的一段话")

    def test_parse_specs_drops_only_bad_item(self):
        bad = {"axis": "llm_bad_one", "request": "POST / HTTP/1.1\r\n\r\n",
               "cwe": "CWE-444"}
        good = {"axis": "llm_good_one", "request": "POST / HTTP/1.1\r\nHost: x\r\n\r\n"}
        specs, rejected = parse_specs(json.dumps([bad, good]))
        self.assertEqual([s.axis for s in specs], ["llm_good_one"])
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0].reason, "未知字段")
        self.assertIn("cwe", rejected[0].detail)

    def test_parse_specs_rejects_reserved_axis(self):
        item = {"axis": AXES[0], "request": "POST / HTTP/1.1\r\nHost: x\r\n\r\n"}
        specs, rejected = parse_specs(json.dumps([item]))
        self.assertEqual(specs, [])
        self.assertEqual(rejected[0].reason, "与手写轴重名")

    def test_parse_specs_rejects_malformed_axis(self):
        for axis in ("Bad_Axis", "ab", "3bad_axis"):
            item = {"axis": axis, "request": "POST / HTTP/1.1\r\nHost: x\r\n\r\n"}
            specs, rejected = parse_specs(json.dumps([item]))
            self.assertEqual(specs, [], f"{axis} 不应通过")
            self.assertEqual(rejected[0].reason, "轴名不合规")

    def test_parse_specs_rejects_duplicate_axis(self):
        item = {"axis": "llm_dup_axis", "request": "POST / HTTP/1.1\r\nHost: x\r\n\r\n"}
        specs, rejected = parse_specs(json.dumps([item, item]))
        self.assertEqual(len(specs), 1)
        self.assertEqual(rejected[0].reason, "同批重复轴名")

    def test_parse_specs_top_level_proposals_object(self):
        item = {"axis": "llm_obj_wrap", "request": "POST / HTTP/1.1\r\nHost: x\r\n\r\n"}
        specs, rejected = parse_specs(json.dumps({"proposals": [item]}))
        self.assertEqual([s.axis for s in specs], ["llm_obj_wrap"])
        self.assertEqual(rejected, [])

    def test_to_bytes_unescapes_crlf(self):
        spec = ProposalSpec("llm_escaped", r"POST / HTTP/1.1\r\nHost: x\r\n\r\n")
        payload = spec.to_bytes()
        self.assertIn(b"\r\n", payload)
        self.assertNotIn(b"\\r", payload)


class TestFramingRelevant(unittest.TestCase):

    def test_canonical_request_is_rejected(self):
        self.assertEqual(framing_relevant(_CANONICAL), "没有落在分帧分歧轴上")

    def test_noncanonical_content_length_is_relevant(self):
        raw = (b"POST / HTTP/1.1\r\nHost: localhost\r\n"
               b"Content-Length: 03\r\n\r\nabc")
        self.assertIsNone(framing_relevant(raw))

    def test_absolute_uri_request_line_is_relevant(self):
        raw = (b"POST http://localhost/ HTTP/1.1\r\nHost: localhost\r\n"
               b"Content-Length: 3\r\n\r\nabc")
        self.assertIsNone(framing_relevant(raw))

    def test_non_message_is_rejected(self):
        self.assertEqual(framing_relevant(b"POST / HTTP/1.1\r\nHost: localhost"),
                         "不是一条 HTTP 消息")

    def test_bare_lf_headers_are_relevant(self):
        self.assertIsNone(framing_relevant(b"POST / HTTP/1.1\nHost: localhost\n\n"))

    def test_canonical_chunked_is_not_relevant(self):
        raw = (b"POST / HTTP/1.1\r\nHost: localhost\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
        self.assertEqual(framing_relevant(raw), "没有落在分帧分歧轴上")


class TestCompileSpecs(unittest.TestCase):

    def test_valid_spec_becomes_llm_proposal(self):
        spec = ProposalSpec("llm_cl_zero",
                            "POST / HTTP/1.1\r\nHost: localhost\r\n"
                            "Content-Length: 03\r\n\r\nabc",
                            rationale="前导零")
        proposals, rejected = compile_specs([spec], model="fake-model")
        self.assertEqual(rejected, [])
        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0].origin, ORIGIN_LLM)
        self.assertEqual(proposals[0].model, "fake-model")
        self.assertIsInstance(proposals[0].payload, bytes)
        self.assertEqual(proposals[0].rationale, "前导零")

    def test_canonical_spec_is_rejected(self):
        spec = ProposalSpec("llm_canon",
                            "POST / HTTP/1.1\r\nHost: localhost\r\n"
                            "Content-Length: 3\r\n\r\nabc")
        proposals, rejected = compile_specs([spec])
        self.assertEqual(proposals, [])
        self.assertEqual(rejected[0].reason, "没有落在分帧分歧轴上")

    def test_duplicate_payload_dropped(self):
        text = ("POST / HTTP/1.1\r\nHost: localhost\r\n"
                "Content-Length: 03\r\n\r\nabc")
        specs = [ProposalSpec("llm_zero_one", text), ProposalSpec("llm_zero_two", text)]
        proposals, rejected = compile_specs(specs)
        self.assertEqual(len(proposals), 1)
        self.assertEqual(rejected[0].reason, "与本批重复")


class TestAdmit(unittest.TestCase):

    def test_cl_te_divergence_is_admitted(self):
        admission = admit([_proposal("llm_cl_te", _CL_TE)], ADAPTER, EVAL)[0]
        self.assertTrue(admission.admitted)
        self.assertIn("consumed", admission.fields)
        self.assertIn("↔", admission.detail)

    def test_noncanonical_but_consistent_is_not_admitted(self):
        admission = admit([_proposal("llm_dup_cl", _DUP_CL)], ADAPTER, EVAL)[0]
        self.assertIs(admission.admitted, False)
        self.assertEqual(admission.fields, ())
        self.assertIn("未命中", admission.detail)

    def test_no_local_pairs_is_conservative(self):
        socket_specs = [ImplSpec(impl_id=i, name=i, runner="socket",
                                 endpoint="127.0.0.1:1") for i in ("a", "b")]
        evaluator = Evaluator(socket_specs)

        class _RemotePairs:
            compare_keys = ("consumed",)

            def pairs(self):
                return {"x": ("a", "b")}

        admission = admit([_proposal("llm_x", _CL_TE)], _RemotePairs(), evaluator)[0]
        self.assertIs(admission.admitted, False)
        self.assertIn("无本地对照", admission.detail)

    def test_probe_exception_is_not_faked_as_hit(self):
        class _BoomEvaluator:
            specs = EVAL.specs

            def __call__(self, impl_id, payload):
                raise RuntimeError("探针挂了")

        admission = admit([_proposal("llm_x", _CL_TE)], ADAPTER, _BoomEvaluator())[0]
        self.assertIs(admission.admitted, False)
        self.assertIn("异常", admission.detail)
        self.assertIn("RuntimeError", admission.detail)


class TestClient(unittest.TestCase):

    def test_unconfigured_client_is_unavailable(self):
        client = LlmClient(config_from_env({}))
        self.assertFalse(client.available)
        with self.assertRaises(LlmUnavailable):
            client.chat([{"role": "user", "content": "hi"}])

    def test_config_from_env_parses_numbers(self):
        cfg = config_from_env({
            "CED_LLM_BASE_URL": "https://api.deepseek.com/v1",
            "CED_LLM_MODEL": "deepseek-chat",
            "CED_LLM_API_KEY": "sk-x",
            "CED_LLM_TIMEOUT": "12.5",
            "CED_LLM_TEMPERATURE": "0.7",
            "CED_LLM_MAX_TOKENS": "512",
        })
        self.assertTrue(cfg.ready)
        self.assertEqual(cfg.timeout, 12.5)
        self.assertEqual(cfg.temperature, 0.7)
        self.assertEqual(cfg.max_tokens, 512)

    def test_config_from_env_falls_back_on_bad_numbers(self):
        cfg = config_from_env({"CED_LLM_BASE_URL": "http://x/v1",
                               "CED_LLM_MODEL": "m",
                               "CED_LLM_TIMEOUT": "not-a-number"})
        self.assertEqual(cfg.timeout, 60.0)

    def test_chat_posts_openai_payload(self):
        seen: dict = {}

        def fake_urlopen(request, timeout=None):
            seen["url"] = request.full_url
            seen["timeout"] = timeout
            seen["body"] = json.loads(request.data.decode("utf-8"))
            seen["headers"] = dict(request.headers)
            return _Resp(json.dumps(
                {"choices": [{"message": {"content": "[]"}}]}).encode("utf-8"))

        cfg = LlmConfig(base_url="http://x/v1/", model="m", api_key="sk-k")
        with mock.patch("urllib.request.urlopen", fake_urlopen):
            out = LlmClient(cfg).chat([{"role": "user", "content": "hi"}])

        self.assertEqual(out, "[]")
        self.assertEqual(seen["url"], "http://x/v1/chat/completions")
        self.assertEqual(seen["timeout"], 60.0)
        self.assertEqual(seen["body"]["model"], "m")
        self.assertEqual(seen["body"]["temperature"], 0.3)
        self.assertEqual(seen["body"]["max_tokens"], 2048)
        self.assertEqual(seen["body"]["messages"][0]["content"], "hi")
        self.assertEqual(seen["headers"]["Authorization"], "Bearer sk-k")

    def test_http_error_becomes_unavailable(self):
        cfg = LlmConfig(base_url="http://x/v1", model="m")
        err = urllib.error.HTTPError("http://x/v1/chat/completions", 500, "boom",
                                     {}, io.BytesIO(b"oops"))
        with mock.patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(LlmUnavailable):
                LlmClient(cfg).chat([{"role": "user", "content": "hi"}])

    def test_malformed_response_becomes_unavailable(self):
        cfg = LlmConfig(base_url="http://x/v1", model="m")
        for body in (b"not json", b'{"foo": 1}'):
            with mock.patch("urllib.request.urlopen",
                            lambda request, timeout=None, _b=body: _Resp(_b)):
                with self.assertRaises(LlmUnavailable):
                    LlmClient(cfg).chat([{"role": "user", "content": "hi"}])


class TestPropose(unittest.TestCase):

    def test_propose_without_client_degrades(self):
        self.assertEqual(propose(None), ([], [], ""))

    def test_propose_with_unavailable_client_degrades(self):
        self.assertEqual(propose(LlmClient(LlmConfig())), ([], [], ""))

    def test_propose_compiles_model_output(self):
        request_text = ("POST / HTTP/1.1\\r\\nHost: localhost\\r\\n"
                        "Content-Length: 03\\r\\n\\r\\nabc")
        reply = "```json\n" + json.dumps(
            [{"axis": "llm_cl_zero", "request": request_text,
              "rationale": "前导零"}]) + "\n```"
        client = _FakeClient(reply=reply)

        proposals, rejected, text = propose(client, n=1)

        self.assertEqual(rejected, [])
        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0].origin, ORIGIN_LLM)
        self.assertEqual(proposals[0].model, "fake-model")
        self.assertIn(b"\r\n", proposals[0].payload)
        self.assertEqual(text, reply)
        self.assertEqual(client.calls[0][0]["role"], "system")
        self.assertIn("提案者", client.calls[0][0]["content"])

    def test_propose_swallows_unavailable(self):
        proposals, rejected, text = propose(_FakeClient(error=LlmUnavailable("boom")))
        self.assertEqual(proposals, [])
        self.assertEqual(text, "")
        self.assertEqual(rejected[0].reason, "模型不可用")

    def test_propose_reports_bad_json(self):
        proposals, rejected, text = propose(_FakeClient(reply="这不是 JSON"))
        self.assertEqual(proposals, [])
        self.assertEqual(text, "这不是 JSON")
        self.assertEqual(rejected[0].reason, "模型输出不是合法 JSON")

    def test_propose_offline_specs_bypasses_model(self):
        spec = ProposalSpec("llm_cl_zero",
                            "POST / HTTP/1.1\r\nHost: localhost\r\n"
                            "Content-Length: 03\r\n\r\nabc")
        proposals, rejected, text = propose(None, specs=[spec])
        self.assertEqual(len(proposals), 1)
        self.assertEqual(rejected, [])
        self.assertEqual(text, "")


class TestLedger(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.conn = store.connect(Path(self.tmp) / "nested" / "ced.db")

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_only_admitted_counts_as_hit_and_is_monotonic(self):
        payload = (b"POST / HTTP/1.1\r\nHost: localhost\r\n"
                   b"Content-Length: 03\r\n\r\nabc")
        proposal = _proposal("llm_cl_zero", payload)

        record(self.conn, Admission(proposal, True, ("consumed",), "命中"))
        self.assertEqual(summary(self.conn)["admitted"], 1)

        # 同一条再记一次"未命中"版本：命中只看涨不看跌
        record(self.conn, Admission(proposal, False, (), "未命中"))
        stats = summary(self.conn)
        self.assertEqual(stats["admitted"], 1)
        self.assertEqual(stats["proposed"], 1)
        self.assertEqual(stats["hit_rate"], 1.0)
        self.assertEqual(stats["by_origin"][ORIGIN_LLM]["hit_rate"], 1.0)

    def test_rejected_is_traced_without_crashing(self):
        record_rejected(self.conn, Rejected("llm_x", "没有落在分帧分歧轴上", "第 1 条"))
        record_rejected(self.conn, Rejected("llm_x", "没有落在分帧分歧轴上", "第 1 条"))
        stats = summary(self.conn)
        self.assertEqual(stats["proposed"], 1)     # 幂等：不因重复记录而膨胀
        self.assertEqual(stats["admitted"], 0)
        rows = store.recent_proposals(self.conn, 5)
        self.assertEqual(rows[0]["axis"], "llm_x")
        self.assertIn("没有落在分帧分歧轴上", rows[0]["note"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
