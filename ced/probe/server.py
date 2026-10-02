"""探针服务：把"某处收到的字节"变成一个可被差分的观测。

    python -m ced.probe.server --policy ref-cl-first --data-port 8800 --api-port 8801

两个端口：
  数据口  扮演**真实后端**：收原始字节 → 按策略解析 → 记录一个视角；
          回复一个合法的 HTTP 响应（响应体就是观测 JSON），
          这样前置（nginx 等）与直连客户端都能正常使用同一端口。
  控制口  GET /health、GET /views、POST /reset —— 供差分器取回视角。

**刻意不使用"等空闲超时"来判定输入结束**：客户端发完即半关闭写端，
服务端读到 EOF 立刻处理。这样不存在「等待窗口 vs 空闲超时」的竞态 ——
那是同类实现最常见的假阳性来源。
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..adapters import ADAPTERS, names
from ..impls import local_specs

MAX_BYTES = 1 << 20        # 1MB 上限，防内存爆炸
IDLE_TIMEOUT = 5.0         # 兜底：客户端不半关闭时

_lock = threading.Lock()
_views: list[dict] = []
_next_id = 1


# --------------------------------------------------------------------------- 观测

def observe(payload: bytes, policy, parse, extract) -> dict:
    res = parse(extract(payload), policy)
    return {"ok": res.ok,
            "error": None if res.ok else res.reason,
            "fields": res.to_fields()}


def record(payload: bytes, policy, parse, extract) -> dict:
    """记录一个视角并返回它（id 单调递增，供差分器区分新旧）。"""
    global _next_id
    view = {"id": 0, "raw_len": len(payload),
            **observe(payload, policy, parse, extract)}
    with _lock:
        view["id"] = _next_id
        _next_id += 1
        _views.append(view)
    return view


def get_views() -> list[dict]:
    with _lock:
        return [dict(v) for v in _views]


def reset() -> None:
    with _lock:
        _views.clear()


# --------------------------------------------------------------------------- 数据口

def _http_reply(obs: dict) -> bytes:
    body = json.dumps(obs, ensure_ascii=False).encode("utf-8")
    status = b"200 OK" if obs.get("ok") else b"400 Bad Request"
    return (b"HTTP/1.1 " + status + b"\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body)


def handle_conn(conn: socket.socket, policy, parse, extract) -> None:
    conn.settimeout(IDLE_TIMEOUT)
    buf = b""
    try:
        while len(buf) < MAX_BYTES:
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                break
            if not chunk:              # 客户端半关闭 → 立刻处理
                break
            buf += chunk
        conn.sendall(_http_reply(record(buf, policy, parse, extract)))
    except OSError:
        pass
    finally:
        conn.close()


# --------------------------------------------------------------------------- 控制口

class _ApiHandler(BaseHTTPRequestHandler):

    def do_GET(self):                                   # noqa: N802
        if self.path == "/health":
            self._send(200, b'{"status":"ok"}')
        elif self.path == "/views":
            self._send(200, json.dumps({"views": get_views()},
                                       ensure_ascii=False).encode("utf-8"))
        else:
            self._send(404, b'{"error":"not found"}')

    def do_POST(self):                                  # noqa: N802
        if self.path == "/reset":
            reset()
            self._send(204, b"")
        else:
            self._send(404, b'{"error":"not found"}')

    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, *args):                       # 安静模式
        pass


# --------------------------------------------------------------------------- 启动

def serve(host: str, data_port: int, api_port: int, policy,
          *, domain: str = "http1-framing") -> None:
    adapter = ADAPTERS[domain]()
    _, parse = adapter.local_parser()
    extract = adapter.extract

    api = ThreadingHTTPServer((host, api_port), _ApiHandler)
    threading.Thread(target=api.serve_forever, daemon=True).start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, data_port))
    srv.listen(64)
    print(f"probe ready: data={host}:{data_port} api={host}:{api_port} "
          f"domain={domain} policy={policy.name}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_conn,
                         args=(conn, policy, parse, extract), daemon=True).start()


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="CED 探针服务")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--domain", choices=names(), default="http1-framing",
                    help="领域名（默认 http1-framing）")
    ap.add_argument("--data-port", type=int, default=8800)
    ap.add_argument("--api-port", type=int, default=8801)
    ap.add_argument("--policy", default=None,
                    help="参照实现策略名，默认取该领域第一个参照实现；"
                         "见 ced.impls.reference.REFERENCES / 各领域 *_reference")
    args = ap.parse_args()

    adapter = ADAPTERS[args.domain]()
    policy_of, _ = adapter.local_parser()
    impl_id = args.policy or local_specs(args.domain)[0].impl_id
    serve(args.host, args.data_port, args.api_port, policy_of(impl_id),
          domain=args.domain)


if __name__ == "__main__":
    main()
