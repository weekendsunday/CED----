"""探针层：把"实现"或"前置+探针链路"包成可被差分调用的观测源。

三种观测方式：
  local  —— 进程内直接跑参照实现（快、确定性，用于内部基准）
  socket —— 直连探针，观测某处收到的字节
  chain  —— 真实前置 → 探针，观测"前置转发出去的字节"

探针协议刻意避开"等空闲超时"：客户端发完即半关闭写端，服务端读到 EOF 立刻回复。
**但真实 nginx 吃不下客户端半关闭**（实测：它既不转发也不回响应），所以链路器
先试半关闭、失败再换普通客户端模式；失败类型见 ``ced.contracts`` 的
``ProbeRejected`` / ``ProbeUnreachable``。
"""
from .chain import ChainEvaluator
from .evaluator import Evaluator, LocalEvaluator, SocketEvaluator

__all__ = ["Evaluator", "LocalEvaluator", "SocketEvaluator", "ChainEvaluator"]
