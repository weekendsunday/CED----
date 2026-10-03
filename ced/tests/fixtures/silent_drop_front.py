"""替身前置：**静默丢掉**某些请求 —— 既不转发、也不回响应。

为什么需要它（本机在 docker 里对真 gunicorn 23.0.0 实测）：

    对它不认的写法 —— 裸 LF 分行（`\\n` 前面不是 `\\r`）、大写块长（`0A`）——
    gunicorn 既不把任何字节交给应用/上游，也不回任何响应，直接把连接关掉。
    这是**真实产品的正常行为**，不是链路故障。

若链路器把它当成故障，一轮扫描会在第一条这种请求上中止（对真实产品完全不可用）；
若反过来无脑降级成"跳过"，又会把真正的链路故障伪装成"全被拒绝"。
所以链路器必须再探一次活性才能定性 —— 这个替身就是那条路径的测试件。

本替身复现这一条：payload 里出现**裸 LF** 就静默丢弃，其余照常转发（透明）。

用法：
    python silent_drop_front.py <listen_port> <upstream_port>
"""
from __future__ import annotations

import socket
import sys
import threading

CR, LF = 0x0D, 0x0A
READ_TIMEOUT = 3.0
IDLE_WINDOW = 0.2


def _has_bare_lf(payload: bytes) -> bool:
    for index, byte in enumerate(payload):
        if byte == LF and (index == 0 or payload[index - 1] != CR):
            return True
    return False


def _read_request(conn: socket.socket) -> bytes:
    """读到"客户端暂时没话了"为止（不依赖半关闭 —— 半关闭/不半关闭都要能工作）。"""
    buf = b""
    conn.settimeout(READ_TIMEOUT)
    first = conn.recv(65536)
    if not first:
        return b""
    buf += first
    conn.settimeout(IDLE_WINDOW)
    while True:
        try:
            chunk = conn.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def handle(conn: socket.socket, upstream: tuple[str, int]) -> None:
    try:
        payload = _read_request(conn)
        if not payload:
            return
        if _has_bare_lf(payload):
            return                      # ← 复现 gunicorn：不转发、不回响应、直接关连接
        with socket.create_connection(upstream, timeout=READ_TIMEOUT) as up:
            up.sendall(payload)
            up.shutdown(socket.SHUT_WR)
            response = b""
            while True:
                chunk = up.recv(65536)
                if not chunk:
                    break
                response += chunk
        conn.sendall(response)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve(listen_port: int, upstream_port: int, host: str = "127.0.0.1") -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, listen_port))
    srv.listen(64)
    print(f"silent-drop front ready on {host}:{listen_port} "
          f"→ 127.0.0.1:{upstream_port}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle,
                         args=(conn, ("127.0.0.1", upstream_port)),
                         daemon=True).start()


def main() -> None:
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    serve(int(sys.argv[1]), int(sys.argv[2]))


if __name__ == "__main__":
    main()
