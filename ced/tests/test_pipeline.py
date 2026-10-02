"""端到端测试：不依赖网络与 Docker，只用标准库。

覆盖的都是"消费者可见的行为"，不是实现细节：
  * 同一实现自比对必须为 0 分歧（差分的差分，防自噪声）
  * 对无歧义的正常请求，所有实现必须一致（防假阳性）
  * 消息边界分歧必须被检出、并升级为 security
  * **没发生结构变化的分歧，绝不允许升级为 security**（防"拿诊断差异当漏洞"）
  * 可控性必须由消融实验给出证据
  * 最小化必须既缩短样本、又保持分歧
  * 链式复现必须给出"被夹带字节数"
  * 落库必须自动创建父目录
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ced.adapters.http1_framing import (KIND_FRAMING_BOUNDARY,
                                        Http1FramingAdapter, meta_of)
from ced.classify.upgradability import judge
from ced.contracts import (LEVEL_COMPAT, LEVEL_SECURITY, Divergence, FieldDiff,
                           Observation)
from ced.differ.comparator import compare, diff_keys
from ced.impls import reference
from ced.minimize.ddmin import minimize_headers
from ced.orchestrate.chain import chain_evidence
from ced.orchestrate.topology import demo
from ced.pipeline import case_id_of, plan_jobs, scan
from ced.probe import Evaluator
from ced import store

ADAPTER = Http1FramingAdapter()
TOPO = demo()
EVAL = Evaluator(TOPO.impls)

#: 经典 CL.TE：Content-Length 覆盖整个 body（含后续请求），
#: 于是"前置按 CL 定界"会把整段转发，"后端按 TE 定界"只消费到 0 块结束，
#: 之后的部分就是被夹带的下一条请求。
_SMUGGLED_REQ = b"GET /smuggled HTTP/1.1\r\nHost: localhost\r\n\r\n"
_BODY = b"0\r\n\r\n" + _SMUGGLED_REQ
CL_TE_PAYLOAD = (
    b"POST / HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Content-Length: " + str(len(_BODY)).encode() + b"\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n" + _BODY
)

#: 完全正常的请求（对照组）
BENIGN_PAYLOAD = (
    b"POST / HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Content-Length: 3\r\n"
    b"\r\n"
    b"abc"
)


class TestDifferentialCore(unittest.TestCase):

    def test_same_impl_no_divergence(self):
        """同一实现自比对必须一致 —— 归一化不得引入自噪声。"""
        for spec in TOPO.impls:
            left = EVAL(spec.impl_id, CL_TE_PAYLOAD)
            right = EVAL(spec.impl_id, CL_TE_PAYLOAD)
            self.assertIsNone(
                compare("x", "axis", CL_TE_PAYLOAD, left, right, ADAPTER.compare_keys),
                f"{spec.impl_id} 自比对出现分歧")

    def test_benign_request_agrees_across_impls(self):
        """对无歧义的正常请求，所有参照实现必须给出相同观测（防假阳性）。"""
        for spec in TOPO.impls:
            obs = EVAL(spec.impl_id, BENIGN_PAYLOAD)
            self.assertEqual(obs.get("consumed"), len(BENIGN_PAYLOAD),
                             f"{spec.impl_id} 对正常请求的消费字节数不对")
            self.assertTrue(obs.get("accepted"), f"{spec.impl_id} 拒绝了正常请求")

    def test_cl_te_conflict_is_detected_as_boundary(self):
        """CL 优先与 TE 优先的两个实现必须被判为边界分歧。"""
        left = EVAL("ref-cl-first", CL_TE_PAYLOAD)
        right = EVAL("ref-te-first", CL_TE_PAYLOAD)
        div = compare(case_id_of(CL_TE_PAYLOAD), "cl_te_conflict", CL_TE_PAYLOAD,
                      left, right, ADAPTER.compare_keys)
        self.assertIsNotNone(div, "CL.TE 冲突未被检出")
        self.assertIn("consumed", div.keys)
        self.assertEqual(ADAPTER.classify([d.key for d in div.diffs]),
                         KIND_FRAMING_BOUNDARY)

    def test_axis_jobs_are_distinct_pairs(self):
        jobs = plan_jobs(ADAPTER, TOPO.ids(), "axis")
        self.assertEqual(len(jobs), len(set((a, b) for a, b, _ in jobs)))
        self.assertTrue(all(a in TOPO.ids() and b in TOPO.ids() for a, b, _ in jobs))

    def test_cross_mode_covers_all_pairs(self):
        jobs = plan_jobs(ADAPTER, TOPO.ids(), "cross")
        n = len(TOPO.ids())
        self.assertEqual(len(jobs), n * (n - 1) // 2)


class TestUpgradability(unittest.TestCase):

    def test_boundary_divergence_is_security_with_ablation_evidence(self):
        result = scan(ADAPTER, EVAL, mode="axis", do_minimize=False)
        found = [f for f in result.findings
                 if (f.divergence.left.impl_id, f.divergence.right.impl_id)
                 == ("ref-cl-first", "ref-te-first")]
        self.assertTrue(found, "CL.TE 轴未产出发现")
        f = found[0]
        self.assertEqual(f.verdict.level, LEVEL_SECURITY)
        self.assertTrue(f.verdict.controllable, "可控性未被判定为真")
        self.assertIsNotNone(f.verdict.ablation, "缺少消融实验证据")
        # CL.TE 的分歧由 CL 与 TE 共同承载，两者都应出现在证据里
        self.assertIn("Content-Length", f.verdict.ablation)
        self.assertIn("Transfer-Encoding", f.verdict.ablation)

    def test_no_security_without_structural_change(self):
        """不变式：没有结构字段变化，就不允许判为 security。

        这条直接编码了"不能拿诊断差异当漏洞"的教训 ——
        与"任何 errors 字段差异都升级"的做法相反。
        """
        structural = {"consumed", "framing_source", "leftover_len",
                      "body_len", "cl", "te", "accepted", "status"}
        result = scan(ADAPTER, EVAL, mode="axis", do_minimize=False)
        self.assertTrue(result.findings, "扫描未产出任何发现")
        for f in result.security:
            keys = set(f.divergence.keys)
            self.assertTrue(keys & structural,
                            f"{f.case_id} 判为 security 但差异字段全非结构字段: {keys}")

    def test_request_line_carried_divergence_is_security(self):
        """分歧由**请求行**承载时，消融实验也必须能定位到 —— 不能只删请求头。

        否则这类真实的分歧会被保守地判成 unknown（曾经就是这样漏报的）。
        """
        payload = (b"POST http://localhost/ HTTP/1.1\r\n"
                   b"Host: localhost\r\n"
                   b"Content-Length: 3\r\n"
                   b"\r\nabc")
        left = EVAL("ref-cl-first", payload)
        right = EVAL("ref-loose-request-line", payload)
        div = compare("x", "request_line", payload, left, right, ADAPTER.compare_keys)
        self.assertIsNotNone(div, "绝对形式请求目标未被检出")
        kind = ADAPTER.classify([d.key for d in div.diffs])
        verdict = judge(div, kind, ADAPTER, EVAL)
        self.assertEqual(verdict.level, LEVEL_SECURITY)
        self.assertTrue(verdict.controllable, "请求行承载的分歧未被判定为可控")
        self.assertIn("请求行", verdict.ablation or "")

    def test_diagnostic_only_divergence_is_compat(self):
        """非结构字段的差异（诊断信息）只能到 compatibility。"""
        fields = {k: 1 for k in ADAPTER.compare_keys}
        left = Observation(impl_id="ref-cl-first", fields=dict(fields))
        right = Observation(impl_id="ref-te-first", fields=dict(fields))
        div = Divergence(case_id="x", axis="axis", payload=BENIGN_PAYLOAD,
                         left=left, right=right,
                         diffs=[FieldDiff("note", "x", "y")])
        kind = ADAPTER.classify([d.key for d in div.diffs])
        verdict = judge(div, kind, ADAPTER, EVAL)
        self.assertEqual(verdict.level, LEVEL_COMPAT)
        self.assertIsNone(verdict.scenario)
        self.assertIsNone(meta_of(kind)["cwe"])


class TestMinimize(unittest.TestCase):

    def test_minimize_shrinks_and_preserves_divergence(self):
        def diverges(payload: bytes) -> bool:
            return bool(diff_keys(EVAL("ref-cl-first", payload),
                                  EVAL("ref-te-first", payload),
                                  ADAPTER.compare_keys))

        self.assertTrue(diverges(CL_TE_PAYLOAD), "前置条件：原始样本应构成分歧")
        minimized = minimize_headers(CL_TE_PAYLOAD, diverges)
        self.assertLess(len(minimized), len(CL_TE_PAYLOAD), "最小化没有缩短样本")
        self.assertTrue(diverges(minimized), "最小化后分歧消失了 —— 语义没保持")

    def test_minimize_keeps_request_line(self):
        minimized = minimize_headers(CL_TE_PAYLOAD, lambda _: True)
        self.assertTrue(minimized.startswith(b"POST / HTTP/1.1"))


class TestChainEvidence(unittest.TestCase):

    def test_smuggling_is_quantified(self):
        ev = chain_evidence(CL_TE_PAYLOAD,
                            reference.policy_of("ref-cl-first"),
                            reference.policy_of("ref-te-first"),
                            "ref-cl-first", "ref-te-first")
        self.assertFalse(ev.same_view, "CL 优先 → TE 优先 不应一致")
        self.assertGreater(ev.smuggled_len, 0, "没有夹带字节就不是走私原语")
        self.assertEqual(ev.smuggled, _SMUGGLED_REQ)

    def test_identical_policies_smuggle_nothing(self):
        ev = chain_evidence(CL_TE_PAYLOAD,
                            reference.policy_of("ref-cl-first"),
                            reference.policy_of("ref-cl-first"))
        self.assertTrue(ev.same_view)
        self.assertEqual(ev.smuggled_len, 0)


class TestPipelineAndStore(unittest.TestCase):

    def test_scan_produces_security_findings_with_evidence(self):
        result = scan(ADAPTER, EVAL, mode="axis", do_minimize=True)
        self.assertGreater(len(result.divergences), 0)
        self.assertGreater(len(result.security), 0, "未产出任何安全级发现")
        for f in result.security:
            self.assertIsNotNone(f.minimized, "安全级发现必须带最小化样本")
            self.assertIsNotNone(f.chain_evidence, "安全级发现必须带链式复现证据")

    def test_chain_evidence_uses_findings_own_pair(self):
        """链式证据必须针对这条发现自己的那一对，而不是拓扑里固定的链路。

        否则会出现"安全级发现"配着另一对实现的证据 —— 曾经就是这么错的。
        """
        result = scan(ADAPTER, EVAL, mode="axis", do_minimize=True)
        checked = 0
        for f in result.security:
            self.assertIsNotNone(f.chain_evidence, "安全级发现缺少链式证据")
            pair = f"**{f.divergence.left.impl_id} → {f.divergence.right.impl_id}**"
            self.assertIn(pair, f.chain_evidence)
            checked += 1
        self.assertGreater(checked, 0, "没有可校验的安全级发现")

    def test_scan_is_deterministic(self):
        a = scan(ADAPTER, EVAL, mode="axis", limit=40, do_minimize=False)
        b = scan(ADAPTER, EVAL, mode="axis", limit=40, do_minimize=False)
        self.assertEqual([f.case_id for f in a.findings],
                         [f.case_id for f in b.findings])

    def test_store_creates_missing_parent_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            nested = Path(tmp) / "a" / "b" / "ced.db"
            conn = store.connect(nested)          # 不得抛 OperationalError
            result = scan(ADAPTER, EVAL, mode="axis", limit=30, do_minimize=False)
            store.save_scan(conn, result, ADAPTER.name)
            stats = store.stats(conn)
            conn.close()
            self.assertTrue(nested.exists())
            self.assertEqual(stats["cases"],
                             len({d.case_id for d in result.divergences}))
            self.assertGreater(stats["cases"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
