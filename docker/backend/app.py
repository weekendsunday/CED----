"""CED 第二档演示用的后端：跑在 gunicorn 上的最小 WSGI 应用（只用标准库）。

它在链路里的角色
----------------
    client ──> nginx(gateway, 8081) ──> gunicorn(8090) ──> 探针(8800)

第一档（docker/../front/nginx.conf）只看 nginx 怎么定帧：nginx 逐字节转发，
探针看到的字节最接近原始输入。

第二档多穿一层 gunicorn。gunicorn 是 WSGI 服务器，它**自己把 HTTP 解析完**才把
``environ`` 交给应用 —— 在 WSGI 这一层拿不到"原始字节"，只拿得到 gunicorn 的解析结果。
所以本应用有两种模式：

1. 默认（未设置 ``CED_PROBE_ADDR``）—— 把 environ 关键字段回成 JSON。
   用途：``curl -v http://127.0.0.1:8090/`` 直接看 gunicorn 对一条请求的解释。

2. 转发模式（``CED_PROBE_ADDR=probe:8800``，compose 里默认开着）——
   把「gunicorn 交给应用的视图」重建回一条 HTTP/1.1 请求，转给 CED 探针，
   响应体换成探针的观测 JSON。这样拓扑里的
   ``runner=chain, endpoint=127.0.0.1:8090, probe_api=127.0.0.1:8801``
   就能观测到 gunicorn 的定帧结果。

重建必然有损：这是**语义级**观测，不是字节级透传
------------------------------------------------
    · environ 丢掉了头的大小写与出现顺序，重复的同名头已被 gunicorn 合并；
    · 原始请求行（尤其畸形写法）已被 gunicorn 规范化；
    · chunked 请求体已被 gunicorn 去分块（本应用按 WSGI 规范重新给 Content-Length）；
    · hop-by-hop 头（Connection 等）按 WSGI 规范不出现在 environ 里。

因此重建时把 gunicorn 给的原始值回带到 ``X-CED-Orig-*`` 带上，证据不丢。
读差分结论时要按「gunicorn 理解成了什么」来读，而不是「gunicorn 原样转发了什么」
—— 后者只有 nginx 那一段能提供。
"""
from __future__ import annotations

import hashlib
import json
import os
import socket

#: 单条请求体的读取上限，防内存爆炸（与探针的 MAX_BYTES 同量级）
MAX_BODY = 1 << 20

#: 探针数据口；空 = 只回 environ JSON，不转发
PROBE_ADDR = os.environ.get("CED_PROBE_ADDR", "").strip()

#: 原样回显的 environ 关键字段
ENVIRON_KEYS = (
    "REQUEST_METHOD",
    "SCRIPT_NAME",
    "PATH_INFO",
    "QUERY_STRING",
    "SERVER_PROTOCOL",
    "SERVER_NAME",
    "SERVER_PORT",
    "REMOTE_ADDR",
    "REMOTE_PORT",
    "CONTENT_TYPE",
    "CONTENT_LENGTH",
    "wsgi.url_scheme",
    "wsgi.input_terminated",
)


def _read_body(environ) -> bytes:
    """按 gunicorn 给出的定帧结论读请求体。

    CONTENT_LENGTH 优先；没有 CL 但 gunicorn 声明输入可终止（chunked 场景
    gunicorn 会设 ``wsgi.input_terminated``）时读到 EOF。
    """
    stream = environ.get("wsgi.input")
    if stream is None:
        return b""
    length = str(environ.get("CONTENT_LENGTH") or "").strip()
    if length.isdigit():
        return stream.read(min(int(length), MAX_BODY))
    if environ.get("wsgi.input_terminated"):
        return stream.read(MAX_BODY)
    return b""


def _headers_of(environ) -> dict:
    """environ 里的 HTTP_* 还原成小写头名（大小写与重复已不可考，见模块 docstring）。"""
    return {k[5:].lower().replace("_", "-"): v
            for k, v in environ.items() if k.startswith("HTTP_")}


def _view(environ, body: bytes) -> dict:
    """gunicorn 交给应用的视图 —— 也就是"gunicorn 是这么理解的"。"""
    headers = _headers_of(environ)
    return {
        "server": "gunicorn",
        "environ": {k: environ.get(k) for k in ENVIRON_KEYS},
        "headers": headers,
        "content_length": environ.get("CONTENT_LENGTH"),
        "transfer_encoding": headers.get("transfer-encoding"),
        "input_terminated": bool(environ.get("wsgi.input_terminated")),
        "body_len": len(body),
        "body_sha1": hashlib.sha1(body).hexdigest(),
        "body_head": body[:120].decode("latin-1"),
    }


def _forward(view: dict, environ, body: bytes) -> bytes:
    """把该视图重建为请求，发给探针，返回探针的观测 JSON。

    定帧头按 gunicorn 的结论重建（CL = 它读到的体的长度），原始值另用
    X-CED-Orig-* 回带，避免"重建"把证据本身抹掉。
    """
    method = environ.get("REQUEST_METHOD") or "GET"
    target = environ.get("PATH_INFO") or "/"
    if environ.get("QUERY_STRING"):
        target = f"{target}?{environ['QUERY_STRING']}"

    lines = [f"{method} {target} HTTP/1.1"]
    for name, value in sorted(view["headers"].items()):
        # 定帧与跳步头由下面显式重建，不在这里重复发
        if name in ("content-length", "transfer-encoding", "connection", "host"):
            continue
        lines.append(f"{name}: {value}")

    lines.append(f"Host: {environ.get('HTTP_HOST') or 'gunicorn'}")
    lines.append(f"Content-Length: {len(body)}")
    if environ.get("CONTENT_LENGTH") is not None:
        lines.append(f"X-CED-Orig-Content-Length: {environ['CONTENT_LENGTH']}")
    if view["transfer_encoding"] is not None:
        # 出现不了就说明 gunicorn 把 TE 从 environ 里吞掉了 —— 这本身是一条证据
        lines.append(f"X-CED-Orig-Transfer-Encoding: {view['transfer_encoding']}")
    lines.append("X-CED-Observed-By: gunicorn-wsgi")
    lines.append("Connection: close")

    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body

    host, _, port = PROBE_ADDR.rpartition(":")
    with socket.create_connection((host or "127.0.0.1", int(port or "8800")),
                                  timeout=10) as sock:
        sock.sendall(raw)
        # 必须半关闭：探针只在写端关闭（或空闲超时）后才处理，否则会白等 5 秒
        sock.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            part = sock.recv(65536)
            if not part:
                break
            chunks.append(part)
    resp = b"".join(chunks)
    idx = resp.find(b"\r\n\r\n")
    return resp[idx + 4:] if idx != -1 else resp


def application(environ, start_response):
    """WSGI 入口（gunicorn 的 ``app:application``）。"""
    body = _read_body(environ)
    view = _view(environ, body)

    if PROBE_ADDR:
        try:
            payload = _forward(view, environ, body)
            status = "200 OK"
        except OSError as exc:
            # 探针不可达就说清楚，绝不合成一个"被拒绝"的观测（那会变成一整片假阳性）
            payload = json.dumps({"error": f"探针不可达: {exc}", "view": view},
                                 ensure_ascii=False).encode("utf-8")
            status = "502 Bad Gateway"
    else:
        payload = json.dumps(view, ensure_ascii=False,
                             indent=2).encode("utf-8")
        status = "200 OK"

    start_response(status, [("Content-Type", "application/json"),
                            ("Content-Length", str(len(payload)))])
    return [payload]
