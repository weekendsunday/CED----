"""链路观测：看**真实前置**到底把什么字节转发给了后端。

收敛进来的能力（原先在 diffmine 里叫 `chain_views`）：
    把 payload 发给前置，前置按自己的定帧策略处理后转发，
    再从前置后面的探针那里取回"后端实际收到了什么"。

与旧实现的差别有两点，都是针对已知缺陷的：

1. **不做"到达顺序配对"**。每次观测前先 `POST /reset` 清空探针的视角，
   再发送、再取第一条新视角 —— 不存在"迟到的视角被下一条用例消费"的错位。
2. **探测失败必须抛错**。前置不可达、或没把任何字节转发过去时，
   直接抛 `ProbeUnreachable`，绝不合成一个"被拒绝"的视角 ——
   合成的视角必然与基线不同，会把"探测失败"变成成片的假阳性安全结论。
"""
from __future__ import annotations

import json
import socket
import time
import urllib.request

from ..contracts import Observation
from .errors import ProbeRejected, ProbeUnreachable

SEND_TIMEOUT = 10.0     # 发字节 + 读响应的超时
VIEW_WAIT = 3.0         # 等探针记录视角的超时（前置没回响应时用）
#: 前置已经回了响应、但探针还没有视角 —— 只给这么久的宽限就判定"它没转发"。
#: 转发型前置必须先拿到后端响应才能回复客户端，所以视角必然先于响应出现。
REJECT_GRACE = 1.0


def _parse_addr(addr: str) -> tuple[str, int]:
    host, _, port = addr.rpartition(":")
    return host or "127.0.0.1", int(port)


def _send_raw(addr: tuple[str, int], payload: bytes) -> bytes:
    """发原始字节，半关闭写端后读尽响应。"""
    with socket.create_connection(addr, timeout=SEND_TIMEOUT) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        out = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
        return out


class ChainEvaluator:
    """通过"前置 → 探针"观测链路。``probe_api`` 是前置后面那个探针的控制口。"""

    def __init__(self, front: str, probe_api: str) -> None:
        self.front = _parse_addr(front)
        self.api = _parse_addr(probe_api)

    # ---------------------------------------------------------------- 控制口

    def _api(self, path: str, method: str = "GET") -> bytes:
        url = f"http://{self.api[0]}:{self.api[1]}{path}"
        req = urllib.request.Request(url, method=method)
        with urllib.request.urlopen(req, timeout=SEND_TIMEOUT) as resp:
            return resp.read()

    def healthy(self) -> bool:
        try:
            return json.loads(self._api("/health")).get("status") == "ok"
        except Exception:
            return False

    def reset(self) -> None:
        self._api("/reset", method="POST")

    def views(self) -> list[dict]:
        return json.loads(self._api("/views")).get("views", [])

    # ---------------------------------------------------------------- 观测

    @property
    def label(self) -> str:
        return f"{self.front[0]}:{self.front[1]}"

    def __call__(self, impl_id: str, payload: bytes) -> Observation:
        try:
            self.reset()
        except OSError as exc:
            raise ProbeUnreachable(
                f"前置 {self.label} 后面的探针控制口 "
                f"{self.api[0]}:{self.api[1]} 不可达：{exc}") from exc

        try:
            response = _send_raw(self.front, payload)
        except OSError as exc:
            raise ProbeUnreachable(f"前置 {self.label} 不可达：{exc}") from exc

        # 前置把字节转发给后端后，必须等后端响应才能回复客户端 —— 所以**响应到达时，
        # 视角早已写好**。反过来，如果前置回了响应却没有视角，它一定是没转发。
        # 据此把"被拒绝"的等待从 VIEW_WAIT 缩短到 REJECT_GRACE：
        # 一轮扫描里被拒绝的用例可能占多数，白等 3 秒会把整轮扫描拖成分钟级。
        budget = REJECT_GRACE if response else VIEW_WAIT
        deadline = time.time() + budget
        while time.time() < deadline:
            for view in self.views():
                # 零字节观测不可能对应一个非空请求 —— 它一定是端口探活之类的
                # 噪声连接被前置转发进来的。若把它当成本次用例的视角，
                # 就会产出与基线"必然不同"的假阳性。跳过它，继续等真正的视角。
                if payload and not view.get("raw_len"):
                    continue
                return Observation(impl_id=impl_id,
                                   ok=view.get("ok", True),
                                   error=view.get("error"),
                                   fields=view.get("fields", {}))
            time.sleep(0.02)

        if response:
            raise ProbeRejected(
                f"前置 {self.label} 收到 {len(payload)} 字节，"
                f"但未向后端转发任何字节（回了 {len(response)} 字节响应）"
                f"—— 按自身策略拒绝了这条请求，本条不可观测")
        raise ProbeUnreachable(
            f"前置 {self.label} 没有把任何字节转发到探针，也没有回响应"
            f"（被拒绝，或链路没起来）—— 拒绝合成视角，避免把探测失败当成耦合误差")
