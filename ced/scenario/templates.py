"""攻击场景模板 —— 把"可升级的语义分歧"翻译成**可复现的攻击叙事**。

场景是**数据**，不是代码分支：每个场景只声明"标题 / 影响 / 前提 / 步骤模板"，
真正填数字（转发了多少字节、夹带了多少字节）由 ``poc.py`` 统一做。
这样新增一个场景不需要动复现逻辑。

占位符由 ``poc.py`` 填充：
    {front} {back} {cwe} {forwarded} {back_consumed} {smuggled} {evidence} {fix}
"""
from __future__ import annotations

from dataclasses import dataclass

SCENARIO_DESYNC = "desync"
SCENARIO_BYPASS = "bypass"
SCENARIO_GENERIC = "generic"


@dataclass(frozen=True)
class Scenario:
    """一个攻击场景的**模板**。"""

    name: str
    title: str
    impact: str
    preconditions: tuple[str, ...]
    steps: tuple[str, ...]
    #: 是否能用"前置转发了多少 / 后端消费了多少 / 夹带多少"来量化
    quotable: bool = True


DESYNC = Scenario(
    name=SCENARIO_DESYNC,
    title="请求走私（HTTP/1.1 消息边界分歧）",
    impact=(
        "前置与后端对『这条请求到哪里结束』判断不同：前置转发的字节里，"
        "后端只消费了一部分，剩下的成为后端眼中**下一条请求**的开头。"
        "于是攻击者可以在前置完全看不见的情况下，向后端注入一条自选请求 —— "
        "前置的鉴权、限流、审计对这条被夹带的请求全部失效。"
    ),
    preconditions=(
        "前置与后端对同一段字节的定帧策略不一致（本工具已用差分 + 消融实验证明）",
        "两侧串联且复用同一条后端连接（HTTP/1.1 长连接或连接池）",
        "攻击者能直接向前置发送请求（含畸形写法）",
    ),
    steps=(
        "确认链路方向：客户端 → {front}（前置） → {back}（后端）",
        "把下面的最小复现样本原样发给 {front}：它包含一处非规范的定帧写法",
        "{front} 按自身策略认为该请求占用 {forwarded} 字节，全部转发给 {back}",
        "{back} 按自身策略只消费 {back_consumed} 字节 → 剩余 **{smuggled} 字节**留在后端缓冲区",
        "紧随其后的下一条请求会被拼接在那 {smuggled} 字节之后，"
        "被夹带的字节成为后端眼中另一条请求的开头",
        "修复：{fix}",
    ),
)

BYPASS = Scenario(
    name=SCENARIO_BYPASS,
    title="防护绕过（接受性分歧）",
    impact=(
        "一侧接受、另一侧拒绝同一段字节。前置放行而下游拒绝（或反之）时，"
        "任何依赖前置做拦截的保护（WAF 规则、鉴权中间件、路径白名单）"
        "都可能被绕过，或被用于制造可用性差异。"
    ),
    preconditions=(
        "两侧对同一份非规范语法的接受度不同（本工具已用消融实验证明分歧由可控字节承载）",
        "前置的保护策略建立在其自身解析结果之上",
    ),
    steps=(
        "确认链路方向：客户端 → {front}（前置） → {back}（下游）",
        "把下面的最小复现样本发给 {front}",
        "{front} 与 {back} 对这份字节的接受性判断不同（接受/拒绝分叉）",
        "消融实验证据：{evidence}",
        "修复：{fix}",
    ),
    quotable=False,
)

GENERIC = Scenario(
    name=SCENARIO_GENERIC,
    title="可升级分歧（场景未归类）",
    impact=(
        "该分歧已通过『消息边界解释 + 攻击者可控』两道判定，但尚未归入已知攻击场景。"
        "这里只给出**最小复现样本与对比观测**，不对攻击后果下结论。"
    ),
    preconditions=(
        "分歧落在结构字段上且由攻击者可直接发送的字节承载",
    ),
    steps=(
        "确认链路方向：客户端 → {front} → {back}",
        "把下面的最小复现样本发给 {front}，观察两侧观测差异",
        "消融实验证据：{evidence}",
        "修复：{fix}",
    ),
    quotable=False,
)

#: 场景注册表：键与 ``Verdict.scenario`` 对齐
SCENARIOS: dict[str, Scenario] = {
    DESYNC.name: DESYNC,
    BYPASS.name: BYPASS,
    SCENARIO_GENERIC: GENERIC,
}


def get(scenario: str | None) -> Scenario:
    """按 ``Verdict.scenario`` 取模板；未知或为空时退回通用模板。"""
    return SCENARIOS.get(scenario or "", GENERIC)


def names() -> list[str]:
    return sorted(SCENARIOS)


__all__ = ["DESYNC", "BYPASS", "GENERIC", "SCENARIOS", "Scenario", "get", "names",
           "AUTO_UPGRADED", "SCENARIO_DESYNC", "SCENARIO_BYPASS",
           "SCENARIO_GENERIC"]


#: 真正会被自动升级的场景（其余走通用模板，只给复现不给后果结论）
AUTO_UPGRADED: tuple[str, ...] = (SCENARIO_DESYNC, SCENARIO_BYPASS)
