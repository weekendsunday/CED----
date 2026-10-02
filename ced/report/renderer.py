"""报告渲染。

原则：**不夸大**。未通过可控性判定的分歧只标 unknown，绝不写成漏洞结论。
"""
from __future__ import annotations

import json

from ..contracts import LEVEL_SECURITY


def _preview(payload: bytes, limit: int = 140) -> str:
    text = repr(payload[:limit])
    return text + ("...(截断)" if len(payload) > limit else "")


def _summary(result) -> dict:
    by_level: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    for f in result.findings:
        by_level[f.verdict.level] = by_level.get(f.verdict.level, 0) + 1
        by_kind[f.verdict.kind] = by_kind.get(f.verdict.kind, 0) + 1
    return {"by_level": by_level, "by_kind": by_kind}


def render_markdown(result, *, domain: str = "http1-framing",
                    topo_desc: str = "") -> str:
    stats = _summary(result)
    out: list[str] = []
    out.append("# 产品耦合误差报告")
    out.append("")
    out.append(f"- 领域：`{domain}`")
    if topo_desc:
        out.append(f"- 拓扑：{topo_desc}")
    out.append(f"- 用例数：{result.total_cases}　实现对：{result.jobs}")
    out.append(f"- 耦合误差：{len(result.divergences)}　"
               f"其中安全级：{len(result.security)}")
    out.append("")

    out.append("## 分级统计")
    out.append("")
    out.append("| 级别 | 数量 |")
    out.append("|---|---|")
    for level in ("security", "unknown", "compatibility"):
        if stats["by_level"].get(level):
            out.append(f"| {level} | {stats['by_level'][level]} |")
    out.append("")
    out.append("| 分歧类型 | 数量 |")
    out.append("|---|---|")
    for kind, n in sorted(stats["by_kind"].items()):
        out.append(f"| {kind} | {n} |")
    out.append("")

    if not result.findings:
        out.append("> 未发现任何耦合误差。注意：这**不等于**安全，只说明在本次语料范围内两侧理解一致。")
        out.append("")
        return "\n".join(out)

    out.append("## 误差明细（按级别排序）")
    out.append("")
    order = {LEVEL_SECURITY: 0, "unknown": 1, "compatibility": 2}
    for f in sorted(result.findings, key=lambda x: order.get(x.verdict.level, 9)):
        v = f.verdict
        out.append(f"### [{v.level}] `{f.case_id}` — {v.kind}")
        out.append("")
        out.append(f"- 对照：**{f.divergence.left.impl_id}** ↔ "
                   f"**{f.divergence.right.impl_id}**（轴：`{f.divergence.axis}`）")
        out.append(f"- 判定理由：{v.reason}")
        if v.ablation:
            out.append(f"- 可控性证据：{v.ablation}")
        out.append(f"- 安全后果：{v.effect}")
        out.append(f"- CWE：{v.cwe or '—'}"
                   + (f"　场景：**{v.scenario}**" if v.scenario else ""))
        out.append(f"- 修复建议：{v.fix}")
        out.append("")
        out.append("| 观测字段 | " + f.divergence.left.impl_id +
                   " | " + f.divergence.right.impl_id + " |")
        out.append("|---|---|---|")
        for d in f.divergence.diffs:
            out.append(f"| `{d.key}` | `{d.left!r}` | `{d.right!r}` |")
        out.append("")
        if f.minimized is not None:
            out.append(f"- 最小复现样本（{f.original_len} → {f.minimized_len} 字节）：")
        else:
            out.append("- 原始样本：")
        out.append("")
        out.append("  ```")
        out.append("  " + _preview(f.minimized if f.minimized is not None
                                   else f.divergence.payload))
        out.append("  ```")
        out.append("")
        if f.chain_evidence:
            out.append(f"- 链式复现：{f.chain_evidence}")
            out.append("")

    out.append("---")
    out.append("")
    out.append("> `security` 级 = 消息边界分歧 ∧ 分歧点由攻击者可控请求头承载。")
    out.append("> 未通过可控性消融的分歧一律标为 `unknown`，不作结论。")
    return "\n".join(out)


def render_json(result) -> str:
    payload = {
        "total_cases": result.total_cases,
        "jobs": result.jobs,
        "summary": _summary(result),
        "findings": [
            {
                "case_id": f.case_id,
                "axis": f.divergence.axis,
                "left": f.divergence.left.impl_id,
                "right": f.divergence.right.impl_id,
                "level": f.verdict.level,
                "kind": f.verdict.kind,
                "reason": f.verdict.reason,
                "controllable": f.verdict.controllable,
                "ablation": f.verdict.ablation,
                "cwe": f.verdict.cwe,
                "scenario": f.verdict.scenario,
                "diffs": {d.key: [d.left, d.right] for d in f.divergence.diffs},
                "payload_b64": __import__("base64").b64encode(
                    f.divergence.payload).decode(),
                "minimized_b64": (__import__("base64").b64encode(f.minimized).decode()
                                  if f.minimized is not None else None),
                "original_len": f.original_len,
                "minimized_len": f.minimized_len,
                "chain_evidence": f.chain_evidence,
            }
            for f in result.findings
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
