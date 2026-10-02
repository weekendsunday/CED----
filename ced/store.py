"""结果落库（SQLite）。

刻意做了两件在同类工具里常被忽略的事：
  * ``connect()`` 自动创建父目录 —— 目标目录不存在时不再直接崩；
  * 库文件是**产物**，不应随源码分发（见 .gitignore）。
"""
from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS case_t (
    case_id   TEXT PRIMARY KEY,
    adapter   TEXT NOT NULL,
    axis      TEXT NOT NULL,
    payload   BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS divergence (
    divergence_id INTEGER PRIMARY KEY,
    case_id       TEXT NOT NULL,
    axis          TEXT NOT NULL,
    left_impl     TEXT NOT NULL,
    right_impl    TEXT NOT NULL,
    diffs         TEXT NOT NULL          -- JSON
);
CREATE TABLE IF NOT EXISTS verdict (
    verdict_id    INTEGER PRIMARY KEY,
    divergence_id INTEGER NOT NULL,
    level         TEXT NOT NULL,
    kind          TEXT NOT NULL,
    reason        TEXT,
    cwe           TEXT,
    scenario      TEXT,
    controllable  INTEGER DEFAULT 0,
    ablation      TEXT
);
CREATE TABLE IF NOT EXISTS finding (
    finding_id    INTEGER PRIMARY KEY,
    divergence_id INTEGER NOT NULL,
    original_len  INTEGER,
    minimized_len INTEGER,
    minimized     BLOB,
    chain_evidence TEXT
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    p = Path(path)
    if p.parent and str(p.parent) not in ("", "."):
        p.parent.mkdir(parents=True, exist_ok=True)     # ← 不因父目录缺失而崩
    conn = sqlite3.connect(p)
    conn.executescript(SCHEMA)
    return conn


def open_fresh(path: str | Path) -> sqlite3.Connection:
    """每次扫描用一个干净的库 —— 否则重复运行会在同一库里累积重复记录。"""
    p = Path(path)
    if p.exists():
        p.unlink()
    return connect(p)


def save_scan(conn: sqlite3.Connection, result, adapter_name: str) -> None:
    """把一次扫描全量落库。"""
    seen_cases: set[str] = set()
    for div in result.divergences:
        if div.case_id not in seen_cases:
            seen_cases.add(div.case_id)
            conn.execute(
                "INSERT OR REPLACE INTO case_t (case_id, adapter, axis, payload) "
                "VALUES (?,?,?,?)",
                (div.case_id, adapter_name, div.axis, sqlite3.Binary(div.payload)))
        cur = conn.execute(
            "INSERT INTO divergence (case_id, axis, left_impl, right_impl, diffs) "
            "VALUES (?,?,?,?,?)",
            (div.case_id, div.axis, div.left.impl_id, div.right.impl_id,
             json.dumps({d.key: [d.left, d.right] for d in div.diffs},
                        ensure_ascii=False)))
        div_id = cur.lastrowid
        for f in result.findings:
            if f.divergence is div:
                conn.execute(
                    "INSERT INTO verdict (divergence_id, level, kind, reason, cwe, "
                    "scenario, controllable, ablation) VALUES (?,?,?,?,?,?,?,?)",
                    (div_id, f.verdict.level, f.verdict.kind, f.verdict.reason,
                     f.verdict.cwe, f.verdict.scenario,
                     int(f.verdict.controllable), f.verdict.ablation))
                conn.execute(
                    "INSERT INTO finding (divergence_id, original_len, minimized_len, "
                    "minimized, chain_evidence) VALUES (?,?,?,?,?)",
                    (div_id, f.original_len, f.minimized_len,
                     sqlite3.Binary(f.minimized) if f.minimized is not None else None,
                     f.chain_evidence))
                break
    conn.commit()


def stats(conn: sqlite3.Connection) -> dict:
    cases = conn.execute("SELECT COUNT(*) FROM case_t").fetchone()[0]
    levels = dict(conn.execute(
        "SELECT level, COUNT(*) FROM verdict GROUP BY level").fetchall())
    kinds = dict(conn.execute(
        "SELECT kind, COUNT(*) FROM verdict GROUP BY kind").fetchall())
    return {"cases": cases, "by_level": levels, "by_kind": kinds}


def dump_finding(conn: sqlite3.Connection, case_id: str) -> dict | None:
    """按 case_id 取回一条完整发现（含最小化样本），便于二次复现。"""
    row = conn.execute(
        "SELECT d.divergence_id, d.left_impl, d.right_impl, d.diffs, v.level, v.kind, "
        "f.minimized, f.chain_evidence FROM divergence d "
        "JOIN verdict v ON v.divergence_id = d.divergence_id "
        "LEFT JOIN finding f ON f.divergence_id = d.divergence_id "
        "WHERE d.case_id = ? LIMIT 1", (case_id,)).fetchone()
    if not row:
        return None
    return {"divergence_id": row[0], "left": row[1], "right": row[2],
            "diffs": json.loads(row[3]), "level": row[4], "kind": row[5],
            "minimized_b64": base64.b64encode(row[6]).decode() if row[6] else None,
            "chain_evidence": row[7]}
