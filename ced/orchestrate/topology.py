"""拓扑定义与加载。

对应方案 §0.2 的输入契约：客户提供
  ① 产品本身（本地参照实现，或 socket 指向的真实服务）
  ② 产品之间的串联方式（chain）

拓扑文件支持 YAML 或 JSON；没有 YAML 时自动退回 JSON，**不强制依赖 PyYAML**。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..contracts import ImplSpec
from ..impls import reference


@dataclass
class Topology:
    domain: str = "http1-framing"
    impls: list[ImplSpec] = field(default_factory=list)
    #: 客户真实链路（前置, 后端）；None 表示只做两两差分
    chain: tuple[str, str] | None = None

    def ids(self) -> list[str]:
        return [s.impl_id for s in self.impls]

    def describe(self) -> str:
        chain = " → ".join(self.chain) if self.chain else "(未指定链路)"
        return f"domain={self.domain} impls={len(self.impls)} chain={chain}"


def _parse(text: str, suffix: str) -> dict:
    if suffix == ".json":
        return json.loads(text)
    try:
        import yaml
    except ImportError:
        return json.loads(text)
    return yaml.safe_load(text)


def load(path: str | Path) -> Topology:
    p = Path(path)
    raw = _parse(p.read_text(encoding="utf-8"), p.suffix.lower())
    default_domain = raw.get("domain", "http1-framing")

    impls: list[ImplSpec] = []
    for node in raw.get("impls", []):
        impls.append(ImplSpec(
            impl_id=node["id"],
            name=node.get("name", node["id"]),
            version=str(node.get("version", "")),
            role=node.get("role", "solo"),
            runner=node.get("runner", "local"),
            domain=node.get("domain") or default_domain,
            policy=node.get("policy"),
            endpoint=node.get("endpoint"),
            probe_api=node.get("probe_api"),
            image=node.get("image"),
            notes=node.get("notes", ""),
        ))

    chain = raw.get("chain")
    if chain is not None:
        if len(chain) != 2:
            raise ValueError("chain 必须是 [前置, 后端] 两个 id")
        known = {s.impl_id for s in impls}
        unknown = [i for i in chain if i not in known]
        if unknown:
            raise ValueError(f"chain 引用了未定义的实现: {unknown}")
        chain = (chain[0], chain[1])

    return Topology(domain=raw.get("domain", "http1-framing"),
                    impls=impls, chain=chain)


def demo(domain: str = "http1-framing") -> Topology:
    """内置拓扑：**某个领域**的全部参照实现。

    链路取该领域第一条定向对照 —— 分帧领域是 CL 优先 → TE 优先（经典 CL.TE 走私结构），
    路径领域是解算 `..` → 保留 `..`（经典穿越结构）。
    """
    from ..impls import axis_pairs, local_specs

    specs = local_specs(domain)
    pairs = axis_pairs(domain)
    chain = next(iter(pairs.values())) if pairs else (
        specs[0].impl_id, specs[1].impl_id)
    return Topology(domain=domain, impls=specs, chain=chain)
