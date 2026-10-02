"""LLM 原始输出 → 严格校验的提案规格。

这一层只做"文本形状"的校验：JSON 能不能抠出来、字段名对不对、轴名与请求文本本身
是否合规。它**不判断提案有没有价值** —— 那是 ``compile.py`` 的结构门槛与差分
oracle 准入实验的事。

逐条校验：任何一条不合法只丢这一条、记入 ``Rejected``，其余照常通过。模型幻觉
出来的字段、越界的轴名都不会拖垮整批输出。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ..contracts import Rejected
from ..mutate.axes import AXES

#: 轴名长度上限（与 AXIS_RE 的 {2,47} 对齐）
MAX_AXIS = 48
#: 单条请求文本上限 —— 超过这个长度必然不是我们要的分帧语法点
MAX_REQUEST = 4096

AXIS_RE = re.compile(r"^[a-z][a-z0-9_]{2,47}$")

#: 每条提案必须带的键
REQUIRED = ("axis",)
#: 允许出现的键；其余一律当幻觉字段丢弃
ALLOWED = frozenset({"axis", "request", "expect_field", "rationale"})

#: 反转义表：模型常把换行写成字面量 ``\r\n``，这里还原成真实控制字符。
#: 顺序敏感 —— ``\r\n`` 必须先于 ``\n`` 处理，否则会被拆成真实回车 + 真实换行。
_UNESCAPE = ((r"\r\n", "\r\n"), (r"\n", "\n"), (r"\t", "\t"))


@dataclass(frozen=True)
class ProposalSpec:
    """一条模型提案的文本形态（尚未变成字节）。"""

    axis: str
    request: str          # 已反转义的原始请求文本（仍可能含字面 \r\n 转义）
    expect_field: str = ""
    rationale: str = ""

    def to_bytes(self) -> bytes:
        """文本 → 原始请求字节。

        走 latin-1：HTTP 报文是字节流，latin-1 是唯一能无损地把 0-255 映射回
        单字节的常见编码；能进到这一步的文本已被 schema 校验过可编码性。
        """
        text = self.request
        for literal, real in _UNESCAPE:
            text = text.replace(literal, real)
        return text.encode("latin-1")


def extract_json(text: str) -> object:
    """从模型输出里抠出 JSON。

    容忍三种形态：纯 JSON、`````json`` 围栏、夹在解说文字里的 JSON。
    顶层是单个提案对象时包成 list；顶层 ``{"proposals": [...]}`` 原样保留。
    全都不行抛 ``ValueError``。
    """
    if not isinstance(text, str):
        raise ValueError("模型输出不是文本")
    for candidate in _candidates(text):
        try:
            obj = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(obj, dict) and "proposals" not in obj:
            return [obj]
        return obj
    raise ValueError("模型输出中找不到合法 JSON")


def _candidates(text: str) -> list[str]:
    text = text.strip()
    out = [text]
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if m:
        out.append(m.group(1).strip())
    for opener, closer in (("[", "]"), ("{", "}")):
        i, j = text.find(opener), text.rfind(closer)
        if i != -1 and j > i:
            out.append(text[i:j + 1])
    return out


def parse_specs(text: str) -> tuple[list[ProposalSpec], list[Rejected]]:
    """模型输出 → ``(合规规格, 被拒条目)``。

    顶层支持 list 或 ``{"proposals": [...]}``；``extract_json`` 拿不到 JSON 时
    向上抛 ``ValueError``（由调用方决定怎么记这一笔失败）。
    """
    data = extract_json(text)
    if isinstance(data, dict) and "proposals" in data:
        items = data["proposals"]
    else:
        items = data
    if not isinstance(items, list):
        raise ValueError("模型输出的 proposals 不是数组")

    specs: list[ProposalSpec] = []
    rejected: list[Rejected] = []
    seen_axes: set[str] = set()

    for i, item in enumerate(items, start=1):
        where = f"第 {i} 条"
        if not isinstance(item, dict):
            rejected.append(Rejected("", "不是对象",
                                     f"{where}：{type(item).__name__}"))
            continue

        unknown = sorted(set(item) - ALLOWED)
        if unknown:
            rejected.append(Rejected(str(item.get("axis", "")), "未知字段",
                                     f"{where}：{', '.join(unknown)}"))
            continue

        missing = [k for k in REQUIRED if k not in item]
        if missing:
            rejected.append(Rejected(str(item.get("axis", "")), "缺 axis",
                                     f"{where}：缺 {', '.join(missing)}"))
            continue

        axis = item["axis"]
        if not isinstance(axis, str) or not AXIS_RE.match(axis):
            rejected.append(Rejected(str(axis), "轴名不合规",
                                     f"{where}：{axis!r}"))
            continue
        if axis in AXES:
            rejected.append(Rejected(axis, "与手写轴重名",
                                     f"{where}：{axis}"))
            continue
        if axis in seen_axes:
            rejected.append(Rejected(axis, "同批重复轴名", where))
            continue

        reason = _request_reason(item.get("request", ""))
        if reason:
            rejected.append(Rejected(axis, "请求不合规", f"{where}：{reason}"))
            continue

        seen_axes.add(axis)
        specs.append(ProposalSpec(
            axis=axis,
            request=item["request"],
            expect_field=_text(item.get("expect_field", "")),
            rationale=_text(item.get("rationale", "")),
        ))

    return specs, rejected


def _request_reason(request: object) -> str:
    """请求文本不合规的原因；合规返回空串。"""
    if not isinstance(request, str):
        return f"不是字符串（{type(request).__name__}）"
    if not request.strip():
        return "为空"
    if len(request) > MAX_REQUEST:
        return f"超长（{len(request)} > {MAX_REQUEST}）"
    try:
        request.encode("latin-1")
    except UnicodeEncodeError as exc:
        return f"含非 latin-1 字符（{exc}）"
    return ""


def _text(value: object) -> str:
    return value if isinstance(value, str) else str(value)
