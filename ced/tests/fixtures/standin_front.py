"""测试替身：本机前置代理。

**不是被测对象**，只用于在无 Docker 的环境下验证 chain 链路本身。

    python standin_front.py <mode> <listen_port> <upstream_port>

mode:
  pass        透明转发（半关闭上游）—— 期望 0 分歧（差分的差分）
  rewrite_cl  转发前归一化 Content-Length 写法 —— 期望检出边界分歧
  drop        收下客户端的字节、回 200，但**不转发任何字节**
              —— 链路器必须抛错，绝不能合成观测
"""
from __future__ import annotations

import re
import socket
import sys
import threading

CRLF = b"\r\n"
# 把 "Content-Length: 03" / "+3" / " 3" 归一化成 "Content-Length: 3"
CL_RE = re.compile(rb"(?im)^(content-length):[ \t]*[+]?0*([0-9]+)[ \t\r]*$")


def rewrite_cl(buf: bytes) -> bytes:
    return CL_RE.sub(rb"\1: \2", buf)


def _read_all(conn: socket.socket, timeout: float = 2.0) -> bytes:
    conn.settimeout(timeout)
    buf = b""
    while True:
        try:
            chunk = conn.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def handle(conn: socket.socket, mode: str, upstream: tuple[str, int]) -> None:
    buf = _read_all(conn)

    if mode == "drop":
        # 收下但一个字节都不转发 —— 链路器必须报错，不得合成"被拒绝"的视角
        try:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except OSError:
            pass
        conn.close()
        return

    if mode == "rewrite_cl":
        buf = rewrite_cl(buf)

    try:
        up = socket.create_connection(upstream, timeout=3.0)
        up.sendall(buf)
        up.shutdown(socket.SHUT_WR)
        resp = b""
        while True:
            chunk = up.recv(65536)
            if not chunk:
                break
            resp += chunk
        up.close()
        conn.sendall(resp)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve(mode: str, listen_port: int, upstream_port: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", listen_port))
    srv.listen(64)
    print(f"standin-front ready mode={mode} on 127.0.0.1:{listen_port}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle,
                         args=(conn, mode, ("127.0.0.1", upstream_port)),
                         daemon=True).start()


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "pass"
    listen_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    upstream_port = int(sys.argv[3]) if len(sys.argv) > 3 else 8800
    serve(mode, listen_port, upstream_port)


if __name__ == "__main__":
    main()
