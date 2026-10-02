"""替身前置：复现真实 nginx 的一个行为 —— **吃不下客户端"立即半关闭"**。

为什么需要它（本机在 docker 里对 nginx:1.25-alpine 实测）：

    客户端把请求发完**立即** shutdown(SHUT_WR)（CED 链路器原来的做法）
        → nginx 1.25.5 **既不把任何字节转发给上游、也不回任何响应**，
          客户端 0.0s 就断开，探针侧记到的视角是 raw_len=0（空连接）。
    客户端不半关闭（curl / 浏览器的做法）
        → nginx 正常转发（探针等 5 秒空闲超时后处理）。

于是链路器必须能自己换成"普通客户端"模式，否则真实链路永远扫不了 ——
这个替身就是为了把那条降级路径钉进测试里（不需要 Docker、不需要真 nginx）。

它只复现这一条行为；除此之外就是个透明前置。

用法：
    python nginx_like_front.py <listen_port> <upstream_port> [连接计数文件]
"""
from __future__ import annotations

import socket
import sys
import threading

#: 数据之后给这么久的窗口来判断客户端是否"立即"半关闭
FIN_WINDOW = 0.15
READ_TIMEOUT = 3.0


def _bump(path: str | None) -> None:
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("1\n")


def handle(conn: socket.socket, upstream: tuple[str, int], counter: str | None) -> None:
    _bump(counter)
    try:
        conn.settimeout(READ_TIMEOUT)
        buf = conn.recv(65536)
        if not buf:
            return                      # 探活连接：客户端连上就关，没什么可转发

        # 关键判断：客户端是不是在数据之后**立刻**给了 FIN
        conn.settimeout(FIN_WINDOW)
        try:
            more = conn.recv(65536)
        except socket.timeout:
            more = None                 # 还开着 → 正常转发
        if more == b"":
            return                      # ← 复现 nginx：不转发、也不回响应
        if more:
            buf += more

        with socket.create_connection(upstream, timeout=READ_TIMEOUT) as up:
            up.sendall(buf)
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


def serve(listen_port: int, upstream_port: int, counter: str | None,
          host: str = "127.0.0.1") -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, listen_port))
    srv.listen(64)
    print(f"nginx-like front ready on {host}:{listen_port} "
          f"→ 127.0.0.1:{upstream_port}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle,
                         args=(conn, ("127.0.0.1", upstream_port), counter),
                         daemon=True).start()


def main() -> None:
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    serve(int(sys.argv[1]), int(sys.argv[2]),
          sys.argv[3] if len(sys.argv) > 3 else None)


if __name__ == "__main__":
    main()
