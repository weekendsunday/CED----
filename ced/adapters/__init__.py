"""领域适配器层：把"某个语义归一化领域的分歧知识"与引擎解耦。

**新增一个领域** = 在 ``ced/adapters/`` 下加一个模块，类上加 ``@register``，
并在本文件底部把该模块 import 进来（一行）。引擎
（差分 / 判定 / 消融 / 最小化 / 量化 / PoC / 报告 / 落库 / 控制台）一行都不用改。

领域名与它负责的语义：
    http1-framing   HTTP/1.1 消息分帧        → 请求走私
    url-norm        URL 路径归一化           → 鉴权绕过 / 路径穿越
"""

from .base import DomainAdapter, axis_names
from .registry import ADAPTERS, get, names, register

# 各领域模块：import 即注册（顺序无关）
from . import http1_framing      # noqa: F401,E402
from . import url_norm           # noqa: F401,E402
from . import host_norm          # noqa: F401,E402
from . import query_norm         # noqa: F401,E402
from . import enc_norm           # noqa: F401,E402

__all__ = ["DomainAdapter", "ADAPTERS", "get", "names", "register", "axis_names"]
