"""探针协议测试：socket 路径必须与本地路径给出**完全一致**的观测。

这条保证"接入真实产品"时，观测语义与内部基准一致 ——
否则同一份 payload 在两条路径上会得到不同结论。

注意：探针服务启动失败必须让测试**失败**，不能跳过。
会 skip 的测试等于不存在 —— 参数改名导致服务起不来，却报 "OK (skipped=1)"，
这类沉默失败比崩溃更危险。
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

from ced.impls import reference
from ced.impls.http_reader import parse_request
from ced.mutate import axes
from ced.probe import SocketEvaluator

PAYLOAD = (
    b"POST / HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Content-Length: 47\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"0\r\n\r\n"
    b"GET /smuggled HTTP/1.1\r\nHost: localhost\r\n\r\n"
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _drain(proc: subprocess.Popen) -> str:
    try:
        return proc.stdout.read() if proc.stdout else ""
    except Exception:
        return ""


def _wait_port(port: int, proc: subprocess.Popen, timeout: float = 10.0) -> None:
    """等端口就绪；进程若提前退出则直接失败（不 skip）。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise AssertionError(
                f"探针服务提前退出（exit={proc.returncode}）：\n{_drain(proc)}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    proc.kill()
    raise AssertionError(f"探针端口 {port} 未在 {timeout}s 内就绪：\n{_drain(proc)}")


class TestSocketProbe(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.data_port = _free_port()
        cls.api_port = _free_port()
        cls.proc = subprocess.Popen(
            [sys.executable, "-m", "ced.probe.server",
             "--policy", "ref-te-first",
             "--data-port", str(cls.data_port),
             "--api-port", str(cls.api_port)],
            cwd=str(ROOT), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True)

    @classmethod
    def tearDownClass(cls) -> None:
        proc = getattr(cls, "proc", None)
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def setUp(self) -> None:
        # 端口等待放在每个用例里：失败即 ERROR，不会被 setUpClass 吞成 skip
        _wait_port(self.data_port, self.proc)
        _wait_port(self.api_port, self.proc)

    def test_socket_matches_local_for_same_policy(self):
        client = SocketEvaluator(f"127.0.0.1:{self.data_port}")
        policy = reference.policy_of("ref-te-first")
        payloads = [payload for _, payload in axes.corpus()] + [PAYLOAD]
        self.assertGreater(len(payloads), 10)
        for payload in payloads:
            local = parse_request(payload, policy).to_fields()
            remote = client("ref-te-first@socket", payload).fields
            self.assertEqual(local, remote,
                             f"探针协议与本地解析不一致：{payload!r}")

    def test_socket_evaluator_reports_the_same_boundary(self):
        """同一实现走 socket 与走本地，对 CL.TE 样本的消费字节数必须一致。"""
        client = SocketEvaluator(f"127.0.0.1:{self.data_port}")
        remote = client("ref-te-first@socket", PAYLOAD)
        local = parse_request(PAYLOAD, reference.policy_of("ref-te-first")).to_fields()
        self.assertEqual(remote.get("consumed"), local["consumed"])
        self.assertLess(remote.get("consumed"), len(PAYLOAD))


if __name__ == "__main__":
    unittest.main(verbosity=2)
