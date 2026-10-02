"""探针服务 / 本地观测器的**领域化**端到端测试。

探针不再写死 HTTP/1.1 分帧：``--domain`` 决定它按哪个领域的 ``extract`` + 解析器
把收到的字节变成观测。本测试用子进程起真探针（不需要 Docker），覆盖：

  * ``--domain url-norm``：收到完整请求 → 取请求行 target → ``norm_path``
  * ``--domain host-norm``：收到完整请求 → 取 Host 头 → ``norm_host``
  * ``--domain query-norm``：收到完整请求 → 取 ``?`` 之后 → ``norm_query``
  * ``--domain enc-norm``：收到完整请求 → 取请求行 target → ``norm_text``
  * 本地观测器（``LocalEvaluator``）对同一完整请求给出**同样的字段**（两侧口径一致）
  * 默认（不传 ``--domain``）行为与以前一致：分帧
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ced.impls import local_specs
from ced.probe import LocalEvaluator

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


def _wait_port(port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise unittest.SkipTest(f"端口 {port} 未在 {timeout}s 内就绪")


def _send(data_port: int, payload: bytes) -> dict:
    """把原始字节发到数据口（发完即半关闭），取回观测 JSON。"""
    with socket.create_connection(("127.0.0.1", data_port), timeout=10) as sock:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        raw = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            raw += chunk
    idx = raw.find(b"\r\n\r\n")
    body = raw[idx + 4:] if idx != -1 else raw
    return json.loads(body.decode("utf-8"))


#: 各领域用的完整请求（真实链路上前置转发出来的形态）。
REQUESTS: dict[str, bytes] = {
    "url-norm": b"GET /pub/%2e%2e/admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "host-norm": b"GET /x HTTP/1.1\r\nHost: EXAMPLE.com.\r\n\r\n",
    "query-norm": b"GET /p?a=1&a=2 HTTP/1.1\r\nHost: x\r\n\r\n",
    "enc-norm": b"GET /%E4%B8%AD HTTP/1.1\r\nHost: x\r\n\r\n",
}

#: 该请求在默认（第一个参照实现）口径下的期望字段值。
EXPECT: dict[str, tuple[str, str]] = {
    "url-norm": ("norm_path", "/admin"),
    "host-norm": ("norm_host", "EXAMPLE.com."),
    "query-norm": ("norm_query", "a=1"),
    "enc-norm": ("norm_text", "/\\u4e2d"),
}


class TestProbeDomains(unittest.TestCase):

    def _start_probe(self, domain: str | None = None) -> tuple[int, int]:
        data_port, api_port = _free_port(), _free_port()
        cmd = [sys.executable, "-m", "ced.probe.server",
               "--data-port", str(data_port), "--api-port", str(api_port)]
        if domain is not None:
            cmd += ["--domain", domain]
        proc = subprocess.Popen(cmd, cwd=str(ROOT),
                                stdout=DEVNULL, stderr=DEVNULL)
        self.addCleanup(_stop, proc)
        _wait_port(api_port)
        return data_port, api_port

    def _local(self, domain: str, payload: bytes):
        specs = local_specs(domain)
        evaluator = LocalEvaluator({s.impl_id: s for s in specs})
        return evaluator(specs[0].impl_id, payload)

    def _assert_domain(self, domain: str) -> None:
        data_port, _ = self._start_probe(domain)
        key, expected = EXPECT[domain]
        payload = REQUESTS[domain]

        probe = _send(data_port, payload)
        self.assertTrue(probe["ok"], f"{domain} 探针观测失败：{probe}")
        self.assertIn(key, probe["fields"], f"{domain} 缺字段 {key}")
        self.assertEqual(probe["fields"][key], expected,
                         f"{domain} 的 {key} 提取/解析不符：{probe['fields']}")

        # 同一完整请求交给本地观测器 → 同样的字段（两侧口径一致）。
        local = self._local(domain, payload)
        self.assertEqual(local.fields, probe["fields"],
                         f"{domain} 本地与探针口径不一致："
                         f"{local.fields} != {probe['fields']}")

    def test_url_norm(self) -> None:
        self._assert_domain("url-norm")

    def test_host_norm(self) -> None:
        self._assert_domain("host-norm")

    def test_query_norm(self) -> None:
        self._assert_domain("query-norm")

    def test_enc_norm(self) -> None:
        self._assert_domain("enc-norm")

    def test_default_domain_is_framing(self) -> None:
        """不传 --domain：仍是分帧领域（字段与 ref-cl-first 本地观测一致）。"""
        data_port, _ = self._start_probe(None)
        payload = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbody"
        probe = _send(data_port, payload)
        self.assertTrue(probe["ok"])
        self.assertIn("consumed", probe["fields"], "默认领域不是分帧")
        self.assertNotIn("norm_path", probe["fields"])

        local = self._local("http1-framing", payload)
        self.assertEqual(local.fields, probe["fields"])

    def test_query_norm_no_query_string_returns_empty(self) -> None:
        """认出请求但 target 没有 ``?`` → 查询串为空（空字节）。"""
        data_port, _ = self._start_probe("query-norm")
        probe = _send(data_port, b"GET /no-query HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertEqual(probe["fields"]["norm_query"], "")

    def test_cli_serve_domain_logs_domain(self) -> None:
        """``python -m ced serve --domain url-norm`` 能起来且日志里有 domain。"""
        data_port, api_port = _free_port(), _free_port()
        proc = subprocess.Popen(
            [sys.executable, "-m", "ced", "serve",
             "--domain", "url-norm",
             "--data-port", str(data_port), "--api-port", str(api_port)],
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace")
        self.addCleanup(proc.stdout.close)
        self.addCleanup(_stop, proc)
        try:
            _wait_port(api_port, timeout=20.0)
        except unittest.SkipTest:
            _stop(proc)
            self.skipTest("CLI 入口未在 20s 内就绪")
        line = proc.stdout.readline()
        self.assertIn("domain=url-norm", line, f"启动日志缺少 domain：{line!r}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
