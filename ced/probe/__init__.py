"""探针层：把"实现"或"前置+探针链路"包成可被差分调用的观测源。

三种观测方式：
  local  —— 进程内直接跑参照实现（快、确定性，用于内部基准）
  socket —— 直连探针，观测某处收到的字节
  chain  —— 真实前置 → 探针，观测"前置转发出去的字节"

探针协议刻意避开"等空闲超时"：客户端发完即半关闭写端，服务端读到 EOF 立刻回复。
"""
from .chain import ChainEvaluator
from .errors import ProbeRejected, ProbeUnreachable
from .evaluator import Evaluator, LocalEvaluator, SocketEvaluator

__all__ = ["Evaluator", "LocalEvaluator", "SocketEvaluator", "ChainEvaluator",
           "ProbeRejected", "ProbeUnreachable"]
