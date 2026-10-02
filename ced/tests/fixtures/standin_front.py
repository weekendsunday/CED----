"""测试替身：本机前置代理。

**不是被测对象**，只用于在无 Docker 的环境下验证 chain 链路本身。
实现已收敛到 ``ced.probe.front``（同一份代码，既给测试用也给演示用），
这里保留薄壳是为了让测试夹具能被独立当脚本执行。

    python standin_front.py <mode> <listen_port> <upstream_port>
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from ced.probe.front import main as front_main      # noqa: E402

if __name__ == "__main__":
    # 旧的 argv 顺序：<mode> <listen_port> <upstream_port>
    argv = sys.argv[1:]
    if len(argv) >= 3:
        sys.argv = [sys.argv[0], "--mode", argv[0],
                    "--listen-port", argv[1], "--upstream-port", argv[2]]
    front_main()
