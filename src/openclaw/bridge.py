"""
src/openclaw/bridge.py — OpenClaw 持久化桥接模块

将 SOC 分析结果写入 FastAPI 后端（SQLite）并触发 IM 推送。
"""

from __future__ import annotations

import json
import os

import httpx

_API_BASE = os.getenv("API_BASE_URL", "http://localhost:8080")


class DashboardPushSkill:
    """将分析结果推送到 Dashboard 后端，并在高危时发送 IM 告警。"""

    async def execute(self, state: dict) -> dict:
        """
        1. 调用 POST /internal/events 写入事件到 SQLite
        2. 当 risk_score >= 8.0 时调用钉钉 Bot 推送告警卡片
        """
        thread_id    = state.get("thread_id", "")
        risk_score   = float(state.get("risk_score", 0.0))
        ti           = state.get("threat_intel") or {}
        kc           = state.get("kill_chain") or {}
        recs         = state.get("recommendations") or []
        status       = state.get("approval_status", "pending")

        # ── 写入后端 ──────────────────────────────────────────────
        payload = {
            "thread_id":             thread_id,
            "risk_score":            risk_score,
            "status":                status,
            "analysis_json":         json.dumps(ti,   ensure_ascii=False),
            "kill_chain_json":       json.dumps(kc,   ensure_ascii=False),
            "recommendations_json":  json.dumps(recs, ensure_ascii=False),
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(f"{_API_BASE}/internal/events", json=payload)
        except Exception:
            pass  # 写入失败不影响主流程

        # ── 高危 IM 推送 ──────────────────────────────────────────
        if risk_score >= 8.0:
            try:
                from src.im_bot.dingtalk_bot import send_alert_card

                mitre = ti.get("final_mitre_mapping") or []
                event_data = {
                    "thread_id":      thread_id,
                    "risk_score":     risk_score,
                    "summary":        kc.get("summary") or ti.get("kill_chain_stage") or "",
                    "affected_assets": [m.get("tactic", "") for m in mitre if m.get("tactic")],
                }
                send_alert_card(event_data)
            except Exception:
                pass

        return state
