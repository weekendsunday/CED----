"""攻击场景层：把「可升级的语义分歧」升级成「可提交的端到端 PoC」。

    templates.py   场景模板（数据：标题/影响/前提/步骤）
    poc.py         字节归属量化 + 零依赖复现脚本生成

不变式：**只对 ``security`` 级发现生成 PoC**。``unknown`` / ``compatibility``
一律不出 —— 判定器没升级的，这里不许替它升级。
"""

from . import templates
from .poc import POC_PREFIX, Poc, build_poc, build_pocs, write_pocs

__all__ = ["Poc", "POC_PREFIX", "build_poc", "build_pocs", "write_pocs", "templates"]
