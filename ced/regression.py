"""已知案例反验证：平台有效性自证（方案 §6 的验收基线）。

**先证明能重新挖出已知的，再谈能发现未知的。**

每次改动归一化 / 分类 / 判定 / 最小化后都必须跑。断言刻意做成**非空转**的：

  1. 必须真的产出分歧 —— 不是"没跑通也算过"；
  2. 分歧类型必须符合案例标注的**已知类别**（标注来自 RFC / 公开研究，不是工具的输出）；
  3. 必须在**预期的结构字段**上出现差异，而不是只要 kind 对就算过；
  4. 对照的两个实现必须是**不同的策略** —— 防"自己跟自己比"。
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, replace
from pathlib import Path

from .adapters.http1_framing import Http1FramingAdapter
from .contracts import ImplSpec
from .differ.comparator import compare
from .impls import reference
from .pipeline import case_id_of
from .probe import Evaluator

CASES_DIR = Path(__file__).resolve().parent / "cases" / "known"


@dataclass
class CaseOutcome:
    name: str
    passed: bool
    detail: str


def load_cases(directory: Path | str = CASES_DIR) -> list[dict]:
    directory = Path(directory)
    if not directory.is_dir():
        return []
    return [json.loads(p.read_text(encoding="utf-8"))
            for p in sorted(directory.glob("*.json"))]


def _knobs(policy):
    """策略的可比部分（排除仅用于标识的 name）。"""
    return replace(policy, name="")


def _evaluate(adapter: Http1FramingAdapter, spec: dict) -> CaseOutcome:
    name = spec["id"]
    left_id, right_id = spec["left"], spec["right"]

    try:
        left_policy = reference.policy_of(left_id)
        right_policy = reference.policy_of(right_id)
    except KeyError as exc:
        return CaseOutcome(name, False, f"案例引用了不存在的实现：{exc}")

    if _knobs(left_policy) == _knobs(right_policy):
        return CaseOutcome(name, False, "对照的两个实现策略完全相同 —— 空转")

    payload = base64.b64decode(spec["payload_b64"])
    evaluator = Evaluator([
        ImplSpec(impl_id=left_id, name=left_id, runner="local", policy=left_id),
        ImplSpec(impl_id=right_id, name=right_id, runner="local", policy=right_id),
    ])
    left = evaluator(left_id, payload)
    right = evaluator(right_id, payload)
    div = compare(case_id_of(payload), spec.get("axis", "known"), payload,
                  left, right, adapter.compare_keys)
    if div is None:
        return CaseOutcome(name, False, "未检出分歧")

    kind = adapter.classify([d.key for d in div.diffs])
    expect_kind = spec.get("expect_kind")
    if expect_kind and kind != expect_kind:
        return CaseOutcome(name, False, f"类型不符：{kind} != {expect_kind}")

    keys = set(div.keys)
    missing = [f for f in spec.get("expect_fields", []) if f not in keys]
    if missing:
        return CaseOutcome(name, False, f"预期字段未出现：{missing}")

    return CaseOutcome(name, True, f"{kind} @ {sorted(keys)}")


def run(directory: Path | str = CASES_DIR,
        cases: list[dict] | None = None) -> list[CaseOutcome]:
    adapter = Http1FramingAdapter()
    cases = cases if cases is not None else load_cases(directory)
    return [_evaluate(adapter, spec) for spec in cases]
