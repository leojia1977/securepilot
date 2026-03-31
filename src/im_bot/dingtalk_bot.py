"""
src/im_bot/dingtalk_bot.py — 钉钉群告警推送模块

风险评分 >= 8.0 时向钉钉群发送高危告警卡片。
Webhook URL 从环境变量 DINGTALK_WEBHOOK 读取，
未配置时静默跳过，不抛出异常。
"""

from __future__ import annotations

import os
from typing import Any

import httpx

DINGTALK_WEBHOOK: str = os.getenv("DINGTALK_WEBHOOK", "")
DASHBOARD_URL: str    = os.getenv("DASHBOARD_URL", "http://localhost:8080")

_RISK_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "⚪",
}


def _risk_level(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 5.0: return "medium"
    return "low"


def _truncate(s: str, max_len: int = 100) -> str:
    return s[:max_len] + "…" if len(s) > max_len else s


def send_alert_card(event_data: dict) -> bool:
    """
    发送高危告警卡片到钉钉群。

    Args:
        event_data: 包含 thread_id, risk_score, summary/root_cause,
                    affected_assets, risk_level 等字段的字典。

    Returns:
        True 表示发送成功，False 表示跳过或失败。
    """
    if not DINGTALK_WEBHOOK:
        return False

    thread_id    = event_data.get("thread_id", "unknown")
    risk_score   = float(event_data.get("risk_score", 0.0))
    level        = event_data.get("risk_level") or _risk_level(risk_score)
    summary      = _truncate(str(event_data.get("summary") or event_data.get("root_cause") or "暂无摘要"))
    assets       = event_data.get("affected_assets") or []
    assets_str   = "、".join(str(a) for a in assets[:5]) or "未知"
    emoji        = _RISK_EMOJI.get(level, "🔴")
    detail_url   = f"{DASHBOARD_URL}/events/{thread_id}"

    text = (
        f"## {emoji} 高危告警 | 风险评分 {risk_score:.1f}\n\n"
        f"> **风险等级**：{level.upper()}\n\n"
        f"**根因摘要**：{summary}\n\n"
        f"**受影响资产**：{assets_str}\n\n"
        f"---\n"
        f"*事件 ID：{thread_id}*"
    )

    payload = {
        "msgtype": "actionCard",
        "actionCard": {
            "title":       f"{emoji} 高危告警 | 风险评分 {risk_score:.1f}",
            "text":        text,
            "singleTitle": "在 Dashboard 中查看详情",
            "singleURL":   detail_url,
        },
    }

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(DINGTALK_WEBHOOK, json=payload)
            resp.raise_for_status()
            result = resp.json()
            return result.get("errcode", -1) == 0
    except Exception:
        return False


def send_daily_summary() -> bool:
    """
    发送昨日安全运营日报到钉钉群。
    数据从 FastAPI GET /api/metrics/mtta 获取。

    Returns:
        True 表示发送成功，False 表示跳过或失败。
    """
    if not DINGTALK_WEBHOOK:
        return False

    api_base = os.getenv("API_BASE_URL", "http://localhost:8080")

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(f"{api_base}/api/metrics/mtta")
            resp.raise_for_status()
            metrics = resp.json()
    except Exception:
        return False

    total   = metrics.get("total_events_today", 0)
    mtta    = metrics.get("mtta_avg_minutes", 0.0)
    acc     = metrics.get("accepted_today", 0)
    rej     = metrics.get("rejected_today", 0)
    acc_r   = metrics.get("acceptance_rate", 0.0)

    text = (
        "## 📊 SecuPilot 安全运营日报\n\n"
        f"| 指标 | 数值 |\n"
        f"|------|------|\n"
        f"| 昨日事件总数 | {total} |\n"
        f"| MTTA 均值 | {mtta:.1f} 分钟 |\n"
        f"| 已接受 | {acc} |\n"
        f"| 已拒绝 | {rej} |\n"
        f"| 接受率 | {acc_r*100:.1f}% |\n"
    )

    payload = {
        "msgtype": "actionCard",
        "actionCard": {
            "title":       "📊 SecuPilot 安全运营日报",
            "text":        text,
            "singleTitle": "打开 Dashboard",
            "singleURL":   DASHBOARD_URL,
        },
    }

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(DINGTALK_WEBHOOK, json=payload)
            resp.raise_for_status()
            result = resp.json()
            return result.get("errcode", -1) == 0
    except Exception:
        return False
