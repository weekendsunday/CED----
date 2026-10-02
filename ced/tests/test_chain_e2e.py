"""链路端到端测试：真实前置 → 探针，**不需要 Docker**。

这是最有价值的一组测试 —— 它把"审查中发现、但项目自身从未验证过"的能力
变成了可重复执行的事实：

  * 透明前置        → 0 分歧（差分的差分，证明无自噪声/假阳性）
  * 会改写的前置    → 检出边界分歧（证明链路差分真的能工作）
  * 前置不可达      → **抛错**，绝不合成观测（防"探测失败 → 成片假阳性"）
  * 前置收下不转发  → **抛错**，同样不得合成
"""
from __future__ import annotations

import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ced.adapters.http1_framing import Http1FramingAdapter
from ced.contracts import ImplSpec
from ced.orchestrate.topology import Topology
from ced.pipeline import scan
from ced.probe import Evaluator, ProbeUnreachable

ADAPTER = Http1FramingAdapter()
FRONT = Path(__file__).resolve().parent / "fixtures" / "standin_front.py"
DEVNULL = subprocess.DEVNULL


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _wait_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise unittest.SkipTest(f"端口 {port} 未在 {timeout}s 内就绪")


class TestChainE2E(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.probe_data = _free_port()
        cls.probe_api = _free_port()
        cls.probe = subprocess.Popen(
            [sys.executable, "-m", "ced.probe.server",
             "--policy", "ref-cl-first",
             "--data-port", str(cls.probe_data),
             "--api-port", str(cls.probe_api)],
            cwd=str(ROOT), stdout=DEVNULL, stderr=DEVNULL)
        try:
            _wait_port(cls.probe_api)
        except unittest.SkipTest:
            cls.probe.terminate()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        _stop(cls.probe)

    # ---------------------------------------------------------------- 工具

    def _start_front(self, mode: str) -> int:
        port = _free_port()
        proc = subprocess.Popen(
            [sys.executable, str(FRONT), mode, str(port), str(self.probe_data)],
            cwd=str(ROOT), stdout=DEVNULL, stderr=DEVNULL)
        self.addCleanup(_stop, proc)
        _wait_port(port)
        return port

    def _evaluator(self, front_port: int) -> Evaluator:
        """链路侧 = 前置 → 探针（探针用的是 ref-cl-first 策略）；
        基准侧 = 直接跑 ref-cl-first。

        所以两侧的"解析器"是同一个 —— 任何分歧都只能来自**前置改写了字节**。
        """
        topo = Topology(domain="http1-framing", impls=[
            ImplSpec(impl_id="front", name="front", role="front", runner="chain",
                     endpoint=f"127.0.0.1:{front_port}",
                     probe_api=f"127.0.0.1:{self.probe_api}"),
            ImplSpec(impl_id="ref-cl-first", name="ref-cl-first", role="solo",
                     runner="local", policy="ref-cl-first"),
        ])
        return Evaluator(topo.impls)

    # ---------------------------------------------------------------- 用例

    def test_transparent_front_yields_no_divergence(self):
        """透明前置：所有观测都必须与基线一致 —— 一个假阳性都不许有。"""
        evaluator = self._evaluator(self._start_front("pass"))
        result = scan(ADAPTER, evaluator, mode="cross", limit=24, do_minimize=False)
        self.assertEqual(len(result.divergences), 0,
                         f"透明前置下出现假阳性：{result.divergences[:3]}")
        self.assertEqual(len(result.findings), 0)

    def test_rewriting_front_is_detected(self):
        """会改写 Content-Length 的前置必须被检出，且分歧落在 CL 相关字段上。"""
        evaluator = self._evaluator(self._start_front("rewrite_cl"))
        result = scan(ADAPTER, evaluator, mode="cross", limit=60, do_minimize=False)
        self.assertGreater(len(result.divergences), 0, "改写前置未被检出")
        structural = {"cl", "framing_source", "body_len", "consumed", "leftover_len"}
        for f in result.findings:
            self.assertTrue(structural & set(f.divergence.keys),
                            f"{f.case_id} 的分歧不在结构字段上：{f.divergence.keys}")

    def test_unreachable_front_raises_instead_of_fabricating(self):
        """前置端口没人监听 → 必须抛错；绝不能合成观测产出"发现"。"""
        evaluator = self._evaluator(_free_port())
        with self.assertRaises(ProbeUnreachable):
            scan(ADAPTER, evaluator, mode="cross", limit=6, do_minimize=False)

    def test_front_that_forwards_nothing_raises(self):
        """前置收下字节但不转发 → 同样必须抛错（这就是 F1 的回归守卫）。"""
        evaluator = self._evaluator(self._start_front("drop"))
        with self.assertRaises(ProbeUnreachable):
            scan(ADAPTER, evaluator, mode="cross", limit=6, do_minimize=False)

    def test_probe_control_api_unreachable_raises(self):
        """前置活着但探针控制口不可达 → 报错必须指明是探针的问题。"""
        port = self._start_front("pass")
        topo = Topology(domain="http1-framing", impls=[
            ImplSpec(impl_id="front", name="front", role="front", runner="chain",
                     endpoint=f"127.0.0.1:{port}",
                     probe_api=f"127.0.0.1:{_free_port()}"),
            ImplSpec(impl_id="ref-cl-first", name="ref-cl-first", role="solo",
                     runner="local", policy="ref-cl-first"),
        ])
        with self.assertRaises(ProbeUnreachable) as ctx:
            scan(ADAPTER, Evaluator(topo.impls), mode="cross", limit=4,
                 do_minimize=False)
        self.assertIn("探针控制口", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
