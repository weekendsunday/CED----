"""替身前置：在没有 Docker、没有真实 nginx 的机器上，把「客户端 → 前置 → 后端」这条
链路的**形状**搭出来。

它**不是被测对象**。用途有两个：
  * 让 chain 观测与端到端 PoC 在任意环境都能演示（比赛现场 Docker 起不来时的兜底）；
  * 让"链路自身不引入噪声"这条不变式可被测试（``pass`` 模式必须 0 分歧）。

模式：
    pass                    透明转发（半关闭上游）
    rewrite_cl              转发前把 Content-Length 归一化成规范写法
    drop                    收下字节但不转发 —— 链路器必须抛错，不得合成观测
    <参照实现策略名>         按该策略重新定帧，只转发"前置认为属于本条请求"的字节
                            （这正是 ``orchestrate.chain`` 里那个链路模型的网络版）

最后一档最有价值：它让"前置按自己的策略定帧、后端按另一套策略再定帧"这件事
真的发生在两台进程之间，而不是在进程内模拟。
"""
from __future__ import annotations

import argparse
import re
import socket
import sys
import threading

from ..impls import reference
from ..impls.http_reader import parse_request

CRLF = b"\r\n"
#: 把 "Content-Length: 03" / "+3" / " 3" 归一化成 "Content-Length: 3"
CL_RE = re.compile(rb"(?im)^(content-length):[ \t]*[+]?0*([0-9]+)[ \t\r]*$")

MODES = ("pass", "rewrite_cl", "drop")


def rewrite_cl(buf: bytes) -> bytes:
    return CL_RE.sub(rb"\1: \2", buf)


def forward_bytes(buf: bytes, mode: str) -> bytes:
    """前置按自己的策略决定"转发哪一段"。返回实际要转发的字节。"""
    if mode == "drop":
        return b""
    if mode == "rewrite_cl":
        return rewrite_cl(buf)
    if mode == "pass":
        return buf
    # 其余情况按参照实现策略重新定帧：只转发前置认为属于本条请求的那一段
    policy = reference.policy_of(mode)
    result = parse_request(buf, policy)
    return buf[:result.consumed] if result.consumed else b""


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
    try:
        buf = _read_all(conn)

        if mode == "drop":
            # 收下但一个字节都不转发 —— 链路器必须报错，不得合成"被拒绝"的视角
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            return

        out = forward_bytes(buf, mode)
        with socket.create_connection(upstream, timeout=3.0) as up:
            up.sendall(out)
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


def serve(mode: str, listen_port: int, upstream_port: int,
          host: str = "127.0.0.1") -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, listen_port))
    srv.listen(64)
    print(f"standin-front ready mode={mode} on {host}:{listen_port} "
          f"→ 127.0.0.1:{upstream_port}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle,
                         args=(conn, mode, ("127.0.0.1", upstream_port)),
                         daemon=True).start()


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(
        description="CED 替身前置（无 Docker 时扮演被观测的前置）")
    ap.add_argument("--mode", default="pass",
                    help=f"{' | '.join(MODES)}，或一个参照实现策略名"
                         f"（如 ref-te-first）")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=18080,
                    help="前置对外入口（客户端打这里）；别用 8080：Windows 常保留该端口")
    ap.add_argument("--upstream-port", type=int, default=8800,
                    help="后面那个探针的数据口")
    args = ap.parse_args()
    serve(args.mode, args.listen_port, args.upstream_port, args.host)


if __name__ == "__main__":
    main()
