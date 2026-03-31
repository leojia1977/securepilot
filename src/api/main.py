"""
src/api/main.py — SecuPilot FastAPI 后端

作为 LangGraph 图和前端之间的桥梁。
启动：uvicorn src.api.main:app --host 0.0.0.0 --port 8080 --reload
"""

from __future__ import annotations

import os
os.environ["NO_PROXY"] = "localhost,127.0.0.1"
os.environ["no_proxy"] = "localhost,127.0.0.1"

import asyncio
import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, List, Optional

import aiosqlite
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.graph.soc_graph import SOCState, build_soc_graph

# ── 配置 ──────────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "securepilot.db")
DB_PATH = os.path.normpath(DB_PATH)

_graph = None          # 共享 graph 实例
_graph_lock = asyncio.Lock()
_running_tasks: dict[str, asyncio.Task] = {}


# ── 数据库初始化 ──────────────────────────────────────────────────────────────

_INIT_SQL = """
CREATE TABLE IF NOT EXISTS events (
    thread_id           TEXT PRIMARY KEY,
    timestamp           TEXT NOT NULL,
    risk_score          REAL DEFAULT 0.0,
    status              TEXT DEFAULT 'pending',
    analysis_json       TEXT,
    kill_chain_json     TEXT,
    recommendations_json TEXT
);

CREATE TABLE IF NOT EXISTS rlhf_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id   TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    action      TEXT NOT NULL,
    reason      TEXT,
    analyst_id  TEXT,
    risk_score  REAL DEFAULT 0.0
);
"""



async def _init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(_INIT_SQL)
        await db.commit()


# ── 风险等级工具 ──────────────────────────────────────────────────────────────

def _risk_level(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 5.0:
        return "medium"
    return "low"


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _graph
    await _init_db()
    _graph = build_soc_graph()
    yield


app = FastAPI(title="SecuPilot API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Pydantic 模型 ─────────────────────────────────────────────────────────────

class ApproveRequest(BaseModel):
    action: str        # "accepted" | "rejected"
    reason: Optional[str] = None
    analyst_id: str = "unknown"


class TriggerRequest(BaseModel):
    events: List[dict]


class InternalEventWrite(BaseModel):
    thread_id: str
    risk_score: float
    status: str = "pending"
    analysis_json: Optional[str] = None
    kill_chain_json: Optional[str] = None
    recommendations_json: Optional[str] = None


# ── 辅助：持久化事件 ──────────────────────────────────────────────────────────

async def _upsert_event(db: aiosqlite.Connection, thread_id: str, state: dict) -> None:
    ti = state.get("threat_intel") or {}
    kc = state.get("kill_chain") or {}
    recs = state.get("recommendations") or []

    await db.execute(
        """
        INSERT INTO events
            (thread_id, timestamp, risk_score, status,
             analysis_json, kill_chain_json, recommendations_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(thread_id) DO UPDATE SET
            risk_score=excluded.risk_score,
            status=excluded.status,
            analysis_json=excluded.analysis_json,
            kill_chain_json=excluded.kill_chain_json,
            recommendations_json=excluded.recommendations_json
        """,
        (
            thread_id,
            datetime.now(tz=timezone.utc).isoformat(),
            float(state.get("risk_score", 0.0)),
            state.get("approval_status", "pending"),
            json.dumps(ti, ensure_ascii=False),
            json.dumps(kc, ensure_ascii=False),
            json.dumps(recs, ensure_ascii=False),
        ),
    )
    await db.commit()


# ── 后台图执行 ────────────────────────────────────────────────────────────────

async def _run_graph(thread_id: str, events: list[dict]) -> None:
    """在后台运行 LangGraph 图，完成后将结果写入 SQLite。"""
    cfg = {"configurable": {"thread_id": thread_id}}
    init_state: SOCState = {
        "raw_events":              events,
        "thread_id":               thread_id,
        "enriched_events":         [],
        "network_analysis":        None,
        "endpoint_analysis":       None,
        "threat_intel":            None,
        "kill_chain":              None,
        "recommendations":         [],
        "risk_score":              0.0,
        "human_approval_required": False,
        "approval_status":         "pending",
        "rejection_reason":        None,
        "rlhf_record":             None,
        "error":                   None,
    }

    result = {"risk_score": 0.0, "approval_status": "pending"}
    try:
        result = await _graph.ainvoke(init_state, config=cfg)
    except BaseException as exc:
        # GraphInterrupt (BaseException) is raised when graph pauses at interrupt()
        # Partial state may still have analysis results from completed nodes
        err_name = type(exc).__name__
        if err_name != "GraphInterrupt":
            result["error"] = str(exc)
        # keep whatever partial result we have (may be empty dict from init)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        await _upsert_event(db, thread_id, result)


# ════════════════════════════════════════════════════════════════════════════
# 接口实现
# ════════════════════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


# ── GET /api/events ────────────────────────────────────────────────────────

@app.get("/api/events")
async def list_events(limit: int = 20, min_risk_score: float = 0.0):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM events WHERE risk_score >= ? ORDER BY timestamp DESC LIMIT ?",
            (min_risk_score, limit),
        )
        rows = await cursor.fetchall()

    events_out = []
    for row in rows:
        risk_score = row["risk_score"]
        ti = json.loads(row["analysis_json"] or "{}")
        kc = json.loads(row["kill_chain_json"] or "{}")
        mitre_tactics = [m.get("tactic", "") for m in (ti.get("final_mitre_mapping") or []) if m.get("tactic")]
        summary = kc.get("summary") or ti.get("kill_chain_stage") or ti.get("root_cause", "")[:100]
        events_out.append({
            "thread_id":       row["thread_id"],
            "timestamp":       row["timestamp"],
            "risk_score":      risk_score,
            "risk_level":      _risk_level(risk_score),
            "status":          row["status"],
            "mitre_tactics":   list(dict.fromkeys(mitre_tactics)),
            "affected_assets": ti.get("affected_assets", []),
            "summary":         summary,
        })

    return {"events": events_out, "total": len(events_out)}


# ── GET /api/events/{thread_id} ───────────────────────────────────────────

@app.get("/api/events/{thread_id}")
async def get_event(thread_id: str):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM events WHERE thread_id = ?", (thread_id,)
        )
        row = await cursor.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Event not found")

    return {
        "thread_id":       row["thread_id"],
        "timestamp":       row["timestamp"],
        "risk_score":      row["risk_score"],
        "approval_status": row["status"],
        "analysis_result": json.loads(row["analysis_json"] or "{}"),
        "kill_chain":      json.loads(row["kill_chain_json"] or "{}"),
        "recommendations": json.loads(row["recommendations_json"] or "[]"),
    }


# ── POST /api/events/{thread_id}/approve ─────────────────────────────────

@app.post("/api/events/{thread_id}/approve")
async def approve_event(thread_id: str, body: ApproveRequest):
    if body.action not in ("accepted", "rejected"):
        raise HTTPException(status_code=400, detail="action must be 'accepted' or 'rejected'")

    from langgraph.types import Command

    cfg = {"configurable": {"thread_id": thread_id}}
    try:
        await _graph.ainvoke(
            Command(resume={
                "action":           body.action,
                "rejection_reason": body.reason,
                "analyst_id":       body.analyst_id,
            }),
            config=cfg,
        )
    except BaseException:
        pass  # 图可能已完成或不存在，忽略恢复错误

    now = datetime.now(tz=timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.execute(
            "UPDATE events SET status = ? WHERE thread_id = ?",
            (body.action, thread_id),
        )
        await db.execute(
            """
            INSERT INTO rlhf_records (thread_id, timestamp, action, reason, analyst_id, risk_score)
            SELECT ?, ?, ?, ?, ?, risk_score FROM events WHERE thread_id = ?
            """,
            (thread_id, now, body.action, body.reason, body.analyst_id, thread_id),
        )
        await db.commit()

    return {"success": True, "thread_id": thread_id}


# ── GET /api/metrics/mtta ─────────────────────────────────────────────────

@app.get("/api/metrics/mtta")
async def mtta_metrics():
    today = datetime.now(tz=timezone.utc).date().isoformat()

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        # 今日事件总数
        cur = await db.execute(
            "SELECT COUNT(*) as total FROM events WHERE timestamp LIKE ?", (f"{today}%",)
        )
        row = await cur.fetchone()
        total_today = row["total"] if row else 0

        # 今日接受/拒绝数
        cur = await db.execute(
            "SELECT COUNT(*) as cnt FROM rlhf_records WHERE action='accepted' AND timestamp LIKE ?",
            (f"{today}%",),
        )
        row = await cur.fetchone()
        accepted_today = row["cnt"] if row else 0

        cur = await db.execute(
            "SELECT COUNT(*) as cnt FROM rlhf_records WHERE action='rejected' AND timestamp LIKE ?",
            (f"{today}%",),
        )
        row = await cur.fetchone()
        rejected_today = row["cnt"] if row else 0

        # MTTA：从事件创建到审批的时间差（分钟）
        cur = await db.execute(
            """
            SELECT e.timestamp AS created, r.timestamp AS resolved
            FROM rlhf_records r
            JOIN events e ON e.thread_id = r.thread_id
            WHERE r.timestamp LIKE ?
            """,
            (f"{today}%",),
        )
        mtta_rows = await cur.fetchall()

    deltas: list[float] = []
    for mrow in mtta_rows:
        try:
            t0 = datetime.fromisoformat(mrow["created"].replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(mrow["resolved"].replace("Z", "+00:00"))
            deltas.append(abs((t1 - t0).total_seconds()) / 60.0)
        except Exception:
            pass

    def _p95(vals: list[float]) -> float:
        if not vals:
            return 0.0
        s = sorted(vals)
        return s[max(0, int(len(s) * 0.95) - 1)]

    mtta_avg = sum(deltas) / len(deltas) if deltas else 0.0
    mtta_p95 = _p95(deltas)
    reviewed = accepted_today + rejected_today
    acceptance_rate = accepted_today / reviewed if reviewed else 0.0

    return {
        "mtta_avg_minutes":   round(mtta_avg, 2),
        "mtta_p95_minutes":   round(mtta_p95, 2),
        "total_events_today": total_today,
        "accepted_today":     accepted_today,
        "rejected_today":     rejected_today,
        "acceptance_rate":    round(acceptance_rate, 4),
    }


# ── POST /api/trigger ────────────────────────────────────────────────────

@app.post("/api/trigger")
async def trigger_analysis(body: TriggerRequest):
    thread_id = f"manual-{uuid.uuid4().hex[:12]}"
    task = asyncio.create_task(_run_graph(thread_id, body.events))
    _running_tasks[thread_id] = task
    task.add_done_callback(lambda t: _running_tasks.pop(thread_id, None))
    return {"thread_id": thread_id, "status": "started"}


# ── POST /internal/events ────────────────────────────────────────────────

@app.post("/internal/events")
async def internal_write_event(body: InternalEventWrite):
    """内部接口：供 openclaw bridge 写入事件记录。"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO events
                (thread_id, timestamp, risk_score, status,
                 analysis_json, kill_chain_json, recommendations_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(thread_id) DO UPDATE SET
                risk_score=excluded.risk_score,
                status=excluded.status,
                analysis_json=COALESCE(excluded.analysis_json, events.analysis_json),
                kill_chain_json=COALESCE(excluded.kill_chain_json, events.kill_chain_json),
                recommendations_json=COALESCE(excluded.recommendations_json, events.recommendations_json)
            """,
            (
                body.thread_id,
                datetime.now(tz=timezone.utc).isoformat(),
                body.risk_score,
                body.status,
                body.analysis_json,
                body.kill_chain_json,
                body.recommendations_json,
            ),
        )
        await db.commit()
    return {"success": True, "thread_id": body.thread_id}
