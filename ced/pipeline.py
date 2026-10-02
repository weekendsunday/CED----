"""扫描主流程：计划 → 差分 → 判定 → 最小化 → 链式复现。

这个是"编排"，不含领域知识；领域知识全在 adapter 里。
"""
from __future__ import annotations

import hashlib
import itertools
import random
from dataclasses import dataclass, field

from .classify.upgradability import judge
from .contracts import Divergence, Finding
from .differ.comparator import compare, diff_keys
from .impls import reference
from .minimize.ddmin import minimize_headers
from .orchestrate.chain import chain_evidence


def case_id_of(payload: bytes) -> str:
    return hashlib.sha1(payload).hexdigest()[:8]


def plan_jobs(adapter, impl_ids: list[str], mode: str = "axis") -> list[tuple[str, str, str]]:
    """返回 (left, right, axis) 列表。

    axis  —— 适配器声明的定向对照（每个轴一对，归因清晰），
             **外加**任何未被定向对照覆盖的实现（例如客户自己的产品）
             与其余实现的交叉对照 —— 否则客户交了产品却被静默跳过。
    cross —— 全部两两组合（交叉矩阵，用于发现未预设的分歧）
    """
    if mode == "cross":
        return [(a, b, "cross") for a, b in itertools.combinations(impl_ids, 2)]

    known = set(impl_ids)
    jobs: list[tuple[str, str, str]] = []
    covered: set[str] = set()
    seen: set[frozenset] = set()

    for axis, (left, right) in adapter.pairs().items():
        if left in known and right in known:
            jobs.append((left, right, axis))
            covered.update((left, right))
            seen.add(frozenset((left, right)))

    for impl in impl_ids:
        if impl in covered:
            continue
        for other in impl_ids:
            if other == impl:
                continue
            key = frozenset((impl, other))
            if key in seen:
                continue
            seen.add(key)
            jobs.append((impl, other, "cross"))

    return jobs


@dataclass
class ScanResult:
    total_cases: int = 0
    jobs: int = 0
    divergences: list[Divergence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def security(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict.is_security]


def scan(adapter, evaluator, *, mode: str = "axis", limit: int | None = None,
         seed: int = 42, do_minimize: bool = True) -> ScanResult:
    rng = random.Random(seed)
    impl_ids = list(evaluator.specs)
    cases = adapter.expand(adapter.corpus(), rng)
    if limit is not None:
        cases = cases[:limit]
    jobs = plan_jobs(adapter, impl_ids, mode)

    result = ScanResult(total_cases=len(cases), jobs=len(jobs))

    for left_id, right_id, axis in jobs:
        def keeps_divergence(payload: bytes) -> bool:      # 最小化用的谓词
            lv = evaluator(left_id, payload)
            rv = evaluator(right_id, payload)
            return bool(diff_keys(lv, rv, adapter.compare_keys))

        for _, payload in cases:
            left = evaluator(left_id, payload)
            right = evaluator(right_id, payload)
            div = compare(case_id_of(payload), axis, payload,
                          left, right, adapter.compare_keys)
            if div is None:
                continue
            result.divergences.append(div)

            kind = adapter.classify([d.key for d in div.diffs])
            verdict = judge(div, kind, adapter, evaluator)
            finding = Finding(divergence=div, verdict=verdict,
                              original_len=len(payload))

            if do_minimize and verdict.is_security:
                minimized = minimize_headers(payload, keeps_divergence)
                finding.minimized = minimized
                finding.minimized_len = len(minimized)

            if verdict.is_security:
                # 链式复现必须针对**这条发现自己的那一对**，而不是拓扑里固定的链路，
                # 否则会出现"安全级发现"配着"两侧理解一致"的自相矛盾。
                specs = evaluator.specs
                fspec, bspec = specs.get(left_id), specs.get(right_id)
                if (fspec is not None and bspec is not None
                        and fspec.runner == "local" and bspec.runner == "local"):
                    evidence = chain_evidence(
                        finding.minimized or payload,
                        reference.policy_of(fspec.policy or left_id),
                        reference.policy_of(bspec.policy or right_id),
                        left_id, right_id)
                    finding.chain_evidence = evidence.describe()

            result.findings.append(finding)

    return result
