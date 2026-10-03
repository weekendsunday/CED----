"""自动捕获的测试（不需要 Docker，不需要外网）。

覆盖的都是**消费者可见的行为**：
  * 明文 HTTP：请求被原样记录 + 被转发到真实站点（且记录与分析对象是客户端原样字节）
  * CONNECT：只记一条"未拆"，隧道照常双向直通（不假装能看 HTTPS 明文）
  * 同一份字节重复出现 → 只分析一次、计数累加
  * 静态资源默认跳过（不分析、但也不影响转发）
  * 分析层：一条请求同时喂 5 个领域；无歧义请求零分歧（防假阳性）
"""
from __future__ import annotations

import base64
import socket
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ced.capture import Config, analyze
from ced.capture.proxy import CaptureProxy

BENIGN = (b"POST /a HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc")
CL_TE = (b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 48\r\n"
         b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
         b"GET /smuggled HTTP/1.1\r\nHost: localhost\r\n\r\n")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait(predicate, timeout: float = 15.0, step: float = 0.05) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(step)
    return False


class _RawOrigin(threading.Thread):
    """最小 origin：把收到的字节记下来，回一个固定响应（不够聪明，够测试用）。"""

    def __init__(self, port: int, reply: bytes = b"ok") -> None:
        super().__init__(daemon=True)
        self.port = port
        self.reply = reply
        self.received: list[bytes] = []
        self.stop = threading.Event()
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(8)
        self.srv.settimeout(0.2)

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with conn:
                conn.settimeout(0.4)
                buf = b""
                try:
                    while True:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        buf += chunk
                        if b"\r\n\r\n" in buf and self._body_done(buf):
                            break
                except socket.timeout:
                    pass
                self.received.append(buf)
                body = self.reply
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n"
                             + body)

    @staticmethod
    def _body_done(buf: bytes) -> bool:
        head, _, body = buf.partition(b"\r\n\r\n")
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                try:
                    return len(body) >= int(line.split(b":", 1)[1].strip())
                except ValueError:
                    return True
        return True

    def close(self) -> None:
        self.stop.set()
        try:
            self.srv.close()
        except OSError:
            pass


class _ProxyHarness:
    """把代理跑在后台线程里，测试直接对它发原始字节。"""

    def __init__(self, **kwargs) -> None:
        self.port = _free_port()
        self.seen: list[dict] = []
        self.cfg = Config(port=self.port, on_result=self.seen.append, **kwargs)
        self.proxy = CaptureProxy(self.cfg)
        self.thread = threading.Thread(target=self.proxy.serve_forever, daemon=True)
        self.thread.start()
        _wait(lambda: self._up(), timeout=5)

    def _up(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                return True
        except OSError:
            return False

    def send(self, payload: bytes, read: bool = True) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            s.sendall(payload)
            if not read:
                return b""
            s.settimeout(5)
            buf = b""
            try:
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
            except socket.timeout:
                pass
            return buf

    def close(self) -> None:
        self.cfg.stop.set()
        self.thread.join(timeout=5)


class TestCaptureProxy(unittest.TestCase):

    def setUp(self) -> None:
        self.origin_port = _free_port()
        self.origin = _RawOrigin(self.origin_port)
        self.origin.start()
        self.harness = _ProxyHarness()
        self.addCleanup(self.harness.close)
        self.addCleanup(self.origin.close)

    def test_plain_http_is_recorded_analyzed_and_forwarded(self):
        """明文请求：原样转发到真实站点 + 被记录 + 拿到分析结果。"""
        response = self.harness.send(
            b"GET /hello HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n"
            % self.origin_port)
        self.assertIn(b"200 OK", response, "代理没有把上游的响应回给客户端")
        self.assertTrue(_wait(lambda: len(self.harness.seen) >= 1), "没有产生记录")
        self.assertTrue(self.origin.received, "代理没有把请求转发到真实站点")
        forwarded = self.origin.received[0]
        self.assertIn(b"GET /hello HTTP/1.1", forwarded)
        self.assertIn(b"Connection: close", forwarded)
        record = self.harness.seen[0]
        self.assertEqual(record["method"], "GET")
        self.assertEqual(record["path"], "/hello")
        self.assertTrue(_wait(lambda: record.get("analysis")))
        self.assertEqual(record["analysis"]["case_id"], record["case_id"])
        self.assertIn("http1-framing", record["analysis"]["domains"])

    def test_connect_is_recorded_as_tunnel_and_not_decrypted(self):
        """HTTPS 只做隧道直通：记一条「未拆」，但隧道本身要能双向通。"""
        echo_port = _free_port()
        stop = threading.Event()

        def echo() -> None:
            srv = socket.socket()
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", echo_port))
            srv.listen(4)
            srv.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with conn:
                    data = conn.recv(4096)
                    conn.sendall(data)
            srv.close()

        threading.Thread(target=echo, daemon=True).start()
        self.addCleanup(stop.set)

        with socket.create_connection(("127.0.0.1", self.harness.port), timeout=10) as s:
            s.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n"
                      % (echo_port, echo_port))
            s.settimeout(5)
            head = s.recv(4096)
            self.assertIn(b"200 Connection Established", head)
            s.sendall(b"PING-THROUGH-TUNNEL")
            self.assertEqual(s.recv(4096), b"PING-THROUGH-TUNNEL")

        self.assertTrue(_wait(lambda: len(self.harness.seen) >= 1))
        record = self.harness.seen[0]
        self.assertTrue(record["tunnel"])
        self.assertIsNone(record["analysis"])
        self.assertIn("不拆包", record["skip"])

    def test_same_bytes_are_analyzed_once(self):
        """同一份字节再来一次 → 只计数，不重复分析。"""
        request = (b"GET /dup HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n"
                   % self.origin_port)
        for _ in range(3):
            self.harness.send(request)
        self.assertTrue(_wait(lambda: self.harness.seen
                              and self.harness.seen[-1]["count"] == 3), "计数没有累加")
        analyzed = [r for r in self.harness.proxy.records if r.get("analysis")]
        self.assertEqual(len(analyzed), 1, "同一份字节被重复分析了")

    def test_static_assets_are_skipped_by_default(self):
        self.harness.send(b"GET /app.css HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                          b"Connection: close\r\n\r\n" % self.origin_port)
        self.assertTrue(_wait(lambda: len(self.harness.seen) >= 1))
        record = self.harness.seen[0]
        self.assertEqual(record["skip"], "静态资源")
        self.assertIsNone(record["analysis"])
        self.assertTrue(self.origin.received, "跳过分析不等于不转发")

    def test_absolute_form_is_normalized_before_analysis(self):
        """代理形式的请求行必须归一化成源站形式再分析。

        实测数字就是这条归一化存在的理由：
          绝对形式（代理原样）→ 19 条"安全级"（8 分帧 + 11 路径，全是部署位置带来的假阳性）
          源站形式（归一化后）→ 0 条
        原始字节仍然留证（raw_b64 / target），只是"分析对象"换成源站会看到的那份。
        """
        absolute = (b"GET http://127.0.0.1:%d/plain HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                    b"Proxy-Connection: keep-alive\r\n\r\n"
                    % (self.origin_port, self.origin_port))
        self.assertGreater(analyze(absolute).security, 0,
                           "前提不成立：绝对形式请求行本应触发 request-line-absolute-uri 分歧")

        self.harness.send(absolute)
        self.assertTrue(_wait(lambda: self.harness.seen
                              and self.harness.seen[-1].get("analysis")), "没有分析结果")
        record = self.harness.seen[-1]
        self.assertTrue(record["normalized"], "代理形式的请求行没有被归一化")
        self.assertEqual(record["analysis"]["divergences"], 0,
                         f"归一化后仍有分歧：{record['analysis']}")
        self.assertEqual(record["analysis"]["security"], 0)
        self.assertIn(b"http://", base64.b64decode(record["raw_b64"]), "原始字节没有留证")
        self.assertIn("http://", record["target"])

    def test_summary_counts_add_up(self):
        self.harness.send(b"GET /one HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                          b"Connection: close\r\n\r\n" % self.origin_port)
        self.assertTrue(_wait(lambda: self.harness.proxy.summary()["analyzed"] >= 1))
        parts = self.harness.proxy.summary()
        self.assertEqual(parts["requests"], 1)
        self.assertEqual(parts["analyzed"], 1)
        self.assertEqual(parts["tunnels"], 0)


class TestAnalyzeFanout(unittest.TestCase):

    def test_benign_request_has_no_divergence(self):
        """无歧义的正常请求：一个分歧都不许有（防假阳性）。"""
        result = analyze(BENIGN)
        self.assertEqual(result.divergences, 0,
                         f"正常请求出现假阳性：{result.to_dict()}")
        self.assertEqual(result.level, "none")

    def test_one_request_is_fanned_out_to_all_domains(self):
        """同一条请求要同时喂给 5 个领域（靠适配器的 extract 各自取段）。"""
        result = analyze(CL_TE)
        self.assertEqual(set(result.domains), {
            "http1-framing", "url-norm", "host-norm", "query-norm", "enc-norm"})
        self.assertGreater(result.divergences, 0, "CL+TE 应当被判出分歧")
        self.assertGreater(result.security, 0, "CL+TE 应当被判成安全级")
        self.assertIsNotNone(result.top)
        self.assertEqual(result.top.level, "security")
        self.assertEqual(result.top.case_id, result.case_id)

    def test_domain_subset_is_respected(self):
        result = analyze(CL_TE, domains=["http1-framing"])
        self.assertEqual(list(result.domains), ["http1-framing"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
