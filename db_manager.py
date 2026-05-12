# -*- coding: utf-8 -*-
"""PostgreSQL Bug 记录管理：建库建表、解析 Cursor 摘要入库、CRUD、人工判别。"""
from __future__ import annotations

import os
import re
import uuid
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

_ROOT = Path(__file__).resolve().parent
load_dotenv(_ROOT / ".env")
load_dotenv(Path.cwd() / ".env")


def _pg_params() -> dict:
    return dict(
        host=os.environ.get("PG_HOST", "localhost"),
        port=int(os.environ.get("PG_PORT", "5432")),
        user=os.environ.get("PG_USER", "postgres"),
        password=os.environ.get("PG_PASSWORD", "admin"),
    )


def _dbname() -> str:
    return os.environ.get("PG_DATABASE", "serial_log_analysis")


def _get_conn(dbname: str | None = None):
    import psycopg2
    return psycopg2.connect(dbname=dbname or _dbname(), **_pg_params())


def init_db() -> None:
    """自动建库 + 建表（幂等）。"""
    import psycopg2

    dbname = _dbname()
    # 先连 postgres 库，确保目标库存在
    conn = psycopg2.connect(dbname="postgres", **_pg_params())
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (dbname,))
    if not cur.fetchone():
        cur.execute(f'CREATE DATABASE "{dbname}"')
    cur.close()
    conn.close()

    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS bug_records (
            id            SERIAL PRIMARY KEY,
            analysis_id   TEXT NOT NULL,
            source_file   TEXT NOT NULL,
            analyzed_at   TIMESTAMP DEFAULT NOW(),
            bug_no        TEXT,
            title         TEXT,
            severity      TEXT,
            bug_type      TEXT,
            log_time      TEXT,
            evidence      TEXT,
            conclusion    TEXT,
            human_verdict TEXT DEFAULT '待定',
            human_notes   TEXT DEFAULT '',
            raw_summary   TEXT,
            created_at    TIMESTAMP DEFAULT NOW(),
            updated_at    TIMESTAMP DEFAULT NOW()
        );
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_bug_analysis ON bug_records(analysis_id);
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_bug_verdict ON bug_records(human_verdict);
    """)
    conn.commit()
    cur.close()
    conn.close()


# ── 解析 Cursor 摘要 → Bug 列表 ──────────────────────────────────

_FIELD_MAP: list[tuple[str, str]] = [
    ("Bug编号", "bug_no"),
    ("标题", "title"),
    ("严重级别", "severity"),
    ("类型", "bug_type"),
    ("时间", "log_time"),
    ("证据/原文", "evidence"),
    ("证据", "evidence"),
    ("分析结论", "conclusion"),
]


def parse_bugs_from_summary(text: str) -> list[dict]:
    """从含有 【Bug编号】…【分析结论】 的文本中提取 Bug 条目。"""
    blocks = re.split(r"(?=【Bug编号】)", text)
    bugs: list[dict] = []
    for block in blocks:
        if "【Bug编号】" not in block:
            continue
        bug: dict[str, str] = {}
        for cn, key in _FIELD_MAP:
            if key in bug:
                continue
            m = re.search(
                rf"【{re.escape(cn)}】\s*(.*?)(?=\n【|\Z)", block, re.DOTALL
            )
            if m:
                bug[key] = m.group(1).strip()
        if bug.get("bug_no"):
            bugs.append(bug)
    return bugs


# ── CRUD ──────────────────────────────────────────────────────────

def save_bugs(
    bugs: list[dict],
    source_file: str,
    raw_summary: str,
    analysis_id: str | None = None,
) -> int:
    """批量入库，返回实际插入条数。"""
    if not bugs:
        return 0
    aid = analysis_id or uuid.uuid4().hex[:12]
    conn = _get_conn()
    cur = conn.cursor()
    n = 0
    for b in bugs:
        cur.execute(
            """INSERT INTO bug_records
               (analysis_id, source_file, bug_no, title, severity,
                bug_type, log_time, evidence, conclusion, raw_summary)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                aid,
                source_file,
                b.get("bug_no", ""),
                b.get("title", ""),
                b.get("severity", ""),
                b.get("bug_type", ""),
                b.get("log_time", ""),
                b.get("evidence", ""),
                b.get("conclusion", ""),
                raw_summary,
            ),
        )
        n += 1
    conn.commit()
    cur.close()
    conn.close()
    return n


def save_bugs_from_summary(summary: str, source_file: str) -> int:
    """一步到位：解析摘要 → 入库。"""
    init_db()
    bugs = parse_bugs_from_summary(summary)
    return save_bugs(bugs, source_file, summary)


def list_bugs(
    limit: int = 200,
    offset: int = 0,
    verdict: str | None = None,
    source_file: str | None = None,
) -> list[dict]:
    conn = _get_conn()
    cur = conn.cursor()
    sql = "SELECT * FROM bug_records WHERE 1=1"
    params: list = []
    if verdict and verdict != "全部":
        sql += " AND human_verdict = %s"
        params.append(verdict)
    if source_file:
        sql += " AND source_file ILIKE %s"
        params.append(f"%{source_file}%")
    sql += " ORDER BY id DESC LIMIT %s OFFSET %s"
    params.extend([limit, offset])
    cur.execute(sql, params)
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    cur.close()
    conn.close()
    return rows


def count_bugs(verdict: str | None = None) -> dict:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT human_verdict, COUNT(*) FROM bug_records GROUP BY human_verdict")
    counts = {r[0]: r[1] for r in cur.fetchall()}
    cur.execute("SELECT COUNT(*) FROM bug_records")
    total = cur.fetchone()[0]
    cur.close()
    conn.close()
    return {"total": total, **counts}


def update_verdict(bug_id: int, verdict: str, notes: str = "") -> bool:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE bug_records SET human_verdict=%s, human_notes=%s, updated_at=NOW() WHERE id=%s",
        (verdict, notes, bug_id),
    )
    ok = cur.rowcount > 0
    conn.commit()
    cur.close()
    conn.close()
    return ok


def delete_bug(bug_id: int) -> bool:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM bug_records WHERE id=%s", (bug_id,))
    ok = cur.rowcount > 0
    conn.commit()
    cur.close()
    conn.close()
    return ok


def get_bug(bug_id: int) -> dict | None:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM bug_records WHERE id=%s", (bug_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return None
    cols = [d[0] for d in cur.description]
    cur.close()
    conn.close()
    return dict(zip(cols, row))


def get_learning_context(max_items: int = 40, max_chars: int = 6000) -> str:
    """从历史人工判别中构建学习上下文（注入 LLM prompt）。

    只取「确认」和「误报」的记录，让模型了解：
    - 哪些模式是真实 Bug（确认）→ 继续重点关注
    - 哪些模式是误报 → 避免重复报告或降低严重级别
    """
    try:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT bug_no, title, severity, bug_type, conclusion,
                      human_verdict, human_notes
               FROM bug_records
               WHERE human_verdict IN ('确认', '误报')
               ORDER BY updated_at DESC
               LIMIT %s""",
            (max_items,),
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()
    except Exception:
        return ""

    if not rows:
        return ""

    lines: list[str] = []
    total = 0
    for bug_no, title, severity, btype, conclusion, verdict, notes in rows:
        tag = "✓真实Bug" if verdict == "确认" else "✗误报"
        entry = f"- [{tag}] {title or bug_no} (级别:{severity}, 类型:{btype})"
        if notes:
            entry += f" 人工备注:{notes}"
        if conclusion and len(entry) + len(conclusion) + 10 < 300:
            entry += f" → {conclusion[:120]}"
        if total + len(entry) > max_chars:
            break
        lines.append(entry)
        total += len(entry) + 1

    return (
        "## 历史人工判别（持续学习）\n\n"
        "以下是人工审核过的历史 Bug 记录。请参考这些经验：\n"
        "- 标记为「✓真实Bug」的模式请继续重点关注并如实报告；\n"
        "- 标记为「✗误报」的模式请**降低权重或不再报告为 Bug**，"
        "除非本次有明显不同的新证据。\n\n"
        + "\n".join(lines)
    )


def test_connection() -> tuple[bool, str]:
    """测试数据库连接，返回 (成功, 消息)。"""
    try:
        init_db()
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM bug_records")
        n = cur.fetchone()[0]
        cur.close()
        conn.close()
        return True, f"连接成功，已有 {n} 条 Bug 记录。"
    except Exception as e:
        return False, str(e)[:500]
