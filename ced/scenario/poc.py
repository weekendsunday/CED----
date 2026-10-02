"""从一条发现生成**可运行的端到端 PoC**。

产出三样东西，缺一不可：

  1. **叙事** —— 场景、影响、前提、复现步骤（由 ``templates`` 提供，这里填数字）；
  2. **字节归属** —— 前置转发多少 / 后端消费多少 / 夹带多少（复用 ``orchestrate.chain``
     的链式模型，数字来自真实解析器，不是估的）；
  3. **脚本** —— 一个零第三方依赖、可直接执行的复现脚本，离线可算账、授权后可真发。

只对 ``security`` 级发现生成 PoC。``unknown`` / ``compatibility`` 一律不出 ——
**不夸大**是这套东西能站住的前提。
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from pathlib import Path

from ..impls import reference
from ..orchestrate.chain import ChainEvidence, chain_evidence
from . import templates

#: 生成的脚本文件名前缀
POC_PREFIX = "poc_"


@dataclass(frozen=True)
class Poc:
    """一条发现对应的端到端复现材料。"""

    case_id: str
    scenario: str
    title: str
    level: str
    cwe: str | None
    left: str
    right: str
    axis: str
    impact: str
    fix: str
    evidence: str
    chain_desc: str
    #: 字节归属；无法量化（两侧含非本地实现）时为 None
    forwarded: int | None
    back_consumed: int | None
    smuggled_len: int | None
    verified: bool
    original_len: int
    sample_len: int
    request_b64: str
    steps: tuple[str, ...] = field(default_factory=tuple)
    script: str = ""

    @property
    def request(self) -> bytes:
        return base64.b64decode(self.request_b64)

    @property
    def file_name(self) -> str:
        return f"{POC_PREFIX}{self.case_id}.py"

    def to_dict(self) -> dict:
        """给报告 / 网页 / 落库用的扁平行。"""
        return {
            "case_id": self.case_id, "scenario": self.scenario, "title": self.title,
            "level": self.level, "cwe": self.cwe, "left": self.left, "right": self.right,
            "axis": self.axis, "impact": self.impact, "fix": self.fix,
            "evidence": self.evidence, "chain_desc": self.chain_desc,
            "forwarded": self.forwarded, "back_consumed": self.back_consumed,
            "smuggled_len": self.smuggled_len, "verified": self.verified,
            "original_len": self.original_len, "sample_len": self.sample_len,
            "request_b64": self.request_b64, "steps": list(self.steps),
            "script": self.script, "file_name": self.file_name,
        }


# --------------------------------------------------------------------- 字节归属

def _accounting(front: str, back: str, payload: bytes) -> ChainEvidence | None:
    """两侧都是参照实现时才能算字节归属；真实产品要靠拓扑里的链路复现。"""
    try:
        evidence = chain_evidence(payload, reference.policy_of(front),
                                  reference.policy_of(back), front, back)
    except KeyError:
        return None
    return evidence


def _steps(scenario: templates.Scenario, values: dict) -> tuple[str, ...]:
    return tuple(step.format(**values) for step in scenario.steps)


_FALLBACK_STEPS = (
    "确认链路方向：客户端 → {front} → {back}",
    "把下面的最小复现样本原样发给 {front}",
    "两侧含非本地实现，本机无法量化字节归属 —— "
    "请在真实拓扑上按 §3.5 的方式复现，观察两侧观测差异",
    "消融实验证据：{evidence}",
    "修复：{fix}",
)


# --------------------------------------------------------------------- 脚本模板

_SCRIPT = '''#!/usr/bin/env python3
"""{title}

由 CED 自动生成 —— 用例 {case_id}，场景 {scenario}。
零第三方依赖；放在仓库任意位置都能跑（脚本会自己往上找仓库根目录）。

    python {file_name}                      # 离线：算清字节归属（默认，不联网）
    python {file_name} --send 127.0.0.1:8080 --i-am-authorized
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

from ced.impls import reference                      # noqa: E402
from ced.orchestrate.chain import chain_evidence     # noqa: E402

CASE_ID = {case_id!r}
FRONT = {front!r}
BACK = {back!r}
PAYLOAD = base64.b64decode({payload_b64!r})
EXPECT = ({forwarded!r}, {back_consumed!r}, {smuggled!r})


def accounting() -> tuple[int, int, int] | None:
    """用两侧的分帧策略算出：前置转发多少 / 后端消费多少 / 夹带多少。"""
    try:
        front_policy = reference.policy_of(FRONT)
        back_policy = reference.policy_of(BACK)
    except KeyError:
        return None
    ev = chain_evidence(PAYLOAD, front_policy, back_policy, FRONT, BACK)
    return ev.forwarded, ev.back_consumed, ev.smuggled_len


def main() -> int:
    ap = argparse.ArgumentParser(description="CED 生成的复现脚本")
    ap.add_argument("--send", metavar="HOST:PORT",
                    help="把最小复现样本真的发到这个地址（前置入口）")
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="确认对 --send 的目标已获授权；缺此项则拒绝发送")
    args = ap.parse_args()

    print(f"用例        {{CASE_ID}}")
    print(f"链路        {{FRONT}} → {{BACK}}")
    print(f"样本长度    {{len(PAYLOAD)}} 字节")

    got = accounting()
    if got is None:
        print("字节归属    无法量化（两侧含非本地实现）—— 请在真实拓扑上复现")
    else:
        forwarded, consumed, smuggled = got
        print(f"前置转发    {{forwarded}} 字节")
        print(f"后端消费    {{consumed}} 字节")
        print(f"被夹带      {{smuggled}} 字节")
        if EXPECT[0] is not None:
            ok = got == EXPECT
            print(f"断言        {{'PASS' if ok else 'FAIL'}}（期望 {{EXPECT}}）")
            if not ok:
                print("说明        期望值来自生成时的实现；不一致说明复现条件已变，")
                print("            请重新跑一次 scan 生成新的 PoC，而不是改期望值。")

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
        print(f"已发送      {{args.send}}，收到 {{len(response)}} 字节响应")
        print("提示        走私的效果要看**下一条请求**，单次发送看不到；"
              "请在后端日志或探针视角里确认被夹带的字节。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _render_script(poc_parts: dict) -> str:
    return _SCRIPT.format(**poc_parts)


# --------------------------------------------------------------------- 对外接口

def build_poc(finding, *, topo_desc: str = "") -> Poc | None:
    """为一条发现生成 PoC。**只对 security 级生成**，其余返回 None。"""
    verdict = finding.verdict
    if not verdict.is_security:
        return None

    divergence = finding.divergence
    payload = (finding.minimized if finding.minimized is not None
               else divergence.payload)
    template = templates.get(verdict.scenario)
    evidence = verdict.ablation or "（未定位到可控承载 —— 该分歧本不该判为安全级，请复核）"

    evidence_obj = _accounting(divergence.left.impl_id, divergence.right.impl_id,
                               payload)
    values = {
        "front": divergence.left.impl_id,
        "back": divergence.right.impl_id,
        "cwe": verdict.cwe or "—",
        "evidence": evidence,
        "fix": verdict.fix or "—",
        "forwarded": evidence_obj.forwarded if evidence_obj else "未知",
        "back_consumed": evidence_obj.back_consumed if evidence_obj else "未知",
        "smuggled": evidence_obj.smuggled_len if evidence_obj else "未知",
    }

    steps = (_steps(template, values) if evidence_obj is not None
             else tuple(step.format(**values) for step in _FALLBACK_STEPS))

    numbers = None
    if evidence_obj is not None:
        numbers = (evidence_obj.forwarded, evidence_obj.back_consumed,
                   evidence_obj.smuggled_len)

    script = _render_script({
        "title": template.title,
        "case_id": finding.case_id,
        "scenario": template.name,
        "file_name": f"{POC_PREFIX}{finding.case_id}.py",
        "front": divergence.left.impl_id,
        "back": divergence.right.impl_id,
        "payload_b64": base64.b64encode(payload).decode(),
        "forwarded": numbers[0] if numbers else None,
        "back_consumed": numbers[1] if numbers else None,
        "smuggled": numbers[2] if numbers else None,
    })

    return Poc(
        case_id=finding.case_id,
        scenario=template.name,
        title=template.title,
        level=verdict.level,
        cwe=verdict.cwe,
        left=divergence.left.impl_id,
        right=divergence.right.impl_id,
        axis=divergence.axis,
        impact=template.impact,
        fix=verdict.fix or "—",
        evidence=evidence,
        chain_desc=(finding.chain_evidence
                    or (evidence_obj.describe() if evidence_obj else
                        "（未量化：两侧含非本地实现）")),
        forwarded=numbers[0] if numbers else None,
        back_consumed=numbers[1] if numbers else None,
        smuggled_len=numbers[2] if numbers else None,
        verified=evidence_obj is not None,
        original_len=finding.original_len or len(divergence.payload),
        sample_len=len(payload),
        request_b64=base64.b64encode(payload).decode(),
        steps=steps,
        script=script,
    )


def build_pocs(result) -> list[Poc]:
    """一次扫描里所有 security 级发现的 PoC，按 case_id 去重。"""
    out: list[Poc] = []
    seen: set[str] = set()
    for finding in result.findings:
        if finding.case_id in seen:
            continue
        poc = build_poc(finding)
        if poc is None:
            continue
        seen.add(finding.case_id)
        out.append(poc)
    return out


def write_pocs(result, out_dir: str | Path) -> list[Path]:
    """把 PoC 脚本落盘，返回写出的路径（已存在且内容相同时不重写）。"""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for poc in build_pocs(result):
        path = directory / poc.file_name
        if not path.exists() or path.read_text(encoding="utf-8") != poc.script:
            path.write_text(poc.script, encoding="utf-8")
        written.append(path)
    return written


__all__ = ["Poc", "POC_PREFIX", "build_poc", "build_pocs", "write_pocs"]
