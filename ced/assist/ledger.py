"""提案台账 —— "LLM 有没有用"的度量底座（创新点④）。

命中口径是本模块的硬约束：**只有 ``admitted=True`` 的提案才算命中**，也就是
"真的逼出了结构分歧"。模型说得多漂亮都不算 —— ``hit_rate`` 恒为
"逼出分歧的提案 / 全部提案"，绝不允许用自述质量污染这个指标。

被语法门槛丢掉的提案没有 payload，无法构成 ``Proposal``，这里直接用一条占位
INSERT 留痕（proposal_id 由 axis+detail 派生），保证"丢掉了什么"也可统计。
"""
from __future__ import annotations

import hashlib
import sqlite3
import time

from ..contracts import ORIGIN_LLM, Rejected
from .. import store


def record(conn: sqlite3.Connection, admission, *, note: str = "") -> None:
    """记一条过了编译门槛的提案及其准入结果。"""
    store.save_proposal(conn, admission.proposal, compiled=True,
                        admitted=admission.admitted, fields=admission.fields,
                        note=note or admission.detail)


def record_rejected(conn: sqlite3.Connection, rejected: Rejected, *,
                    origin: str = ORIGIN_LLM, model: str = "") -> None:
    """记一条被语法门槛丢掉的提案（无 payload，用占位 INSERT 留痕）。"""
    seed = f"{rejected.axis}|{rejected.detail}".encode("utf-8")
    proposal_id = hashlib.sha1(seed).hexdigest()[:8]
    note = rejected.reason
    if rejected.detail:
        note = f"{note}：{rejected.detail}"
    conn.execute(
        "INSERT OR IGNORE INTO proposal (proposal_id, axis, origin, model, rationale,"
        " payload, compiled, admitted, hit_fields, note, ts)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (proposal_id, rejected.axis, origin, model, "",
         sqlite3.Binary(b""), 0, 0, "[]", note, time.time()))
    conn.commit()


def record_many(conn: sqlite3.Connection, admissions, *,
                notes: list[str] | None = None) -> None:
    """批量记台账；``notes`` 与 ``admissions`` 按下标对齐（可短于后者）。"""
    for i, admission in enumerate(admissions):
        note = notes[i] if notes and i < len(notes) else ""
        record(conn, admission, note=note)


def summary(conn: sqlite3.Connection) -> dict:
    """命中率总览（直接转发 ``store.proposal_stats``，口径见模块 docstring）。"""
    return store.proposal_stats(conn)


def history(conn: sqlite3.Connection, limit: int = 12) -> str:
    """供提示词回写的历史摘要（命中过的方向优先扩展、未命中的别重复）。"""
    return store.proposal_history_brief(conn, limit)


def recent(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    return store.recent_proposals(conn, limit)
