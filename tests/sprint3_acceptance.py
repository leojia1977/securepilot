"""
tests/sprint3_acceptance.py
Sprint 3 验收脚本：FastAPI 后端 + Dashboard + IM Bot

运行前需启动：
  1. Mock vLLM: cd mock && uvicorn vllm_server:app --port 8000 --reload
  2. FastAPI:   uvicorn src.api.main:app --port 8080 --reload
"""

from __future__ import annotations

import os
os.environ["NO_PROXY"] = "localhost,127.0.0.1"
os.environ["no_proxy"] = "localhost,127.0.0.1"

import asyncio
import sys
import time
from pathlib import Path

_PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

import httpx

API = "http://localhost:8080"
FIXTURES_DIR = Path(__file__).parent / "fixtures"

_SAMPLE_EVENT = {
    "event_id":    "sprint3-test-0001",
    "timestamp":   "2024-03-15T08:03:22Z",
    "source_type": "endpoint",
    "source_system": "edr",
    "severity":    4,
    "risk_score":  8.5,
    "src_ip":      "203.0.113.45",
    "dst_ip":      "192.168.10.47",
    "alert_name":  "LSASS Memory Access Detected",
    "alert_description": "LSASS process memory read detected",
    "hostname":    "WORKSTATION-047",
    "user":        "zhang.wei",
}


def _icon(ok: bool) -> str:
    return "✓" if ok else "✗"


async def run_checks() -> bool:
    results: list[tuple[str, bool, str]] = []

    async with httpx.AsyncClient(timeout=15.0) as client:

        # ── 1. /health ────────────────────────────────────────────────────
        try:
            r = await client.get(f"{API}/health")
            ok = r.status_code == 200 and r.json().get("status") == "ok"
            results.append(("FastAPI /health 返回 200", ok, f"status={r.status_code}"))
        except Exception as e:
            results.append(("FastAPI /health 返回 200", False, str(e)[:60]))

        # ── 2. POST /api/trigger ──────────────────────────────────────────
        thread_id = None
        try:
            r = await client.post(f"{API}/api/trigger", json={"events": [_SAMPLE_EVENT]})
            d = r.json()
            thread_id = d.get("thread_id")
            ok = r.status_code == 200 and bool(thread_id) and d.get("status") == "started"
            results.append(("POST /api/trigger 返回 thread_id", ok, f"thread_id={thread_id}"))
        except Exception as e:
            results.append(("POST /api/trigger 返回 thread_id", False, str(e)[:60]))

        # ── 等待图执行 ────────────────────────────────────────────────────
        if thread_id:
            await asyncio.sleep(15)

        # ── 3. GET /api/events ────────────────────────────────────────────
        try:
            r = await client.get(f"{API}/api/events?limit=10")
            d = r.json()
            ok = r.status_code == 200 and len(d.get("events", [])) >= 1
            results.append(("GET /api/events 返回 >= 1 条事件", ok,
                             f"total={d.get('total',0)}"))
        except Exception as e:
            results.append(("GET /api/events 返回 >= 1 条事件", False, str(e)[:60]))

        # ── 4. GET /api/events/{thread_id} ───────────────────────────────
        if thread_id:
            try:
                r = await client.get(f"{API}/api/events/{thread_id}")
                d = r.json()
                has_kc   = "kill_chain"      in d
                has_recs = "recommendations" in d
                ok = r.status_code == 200 and has_kc and has_recs
                results.append(("GET /api/events/{id} 含 kill_chain+recommendations", ok,
                                 f"kc={has_kc} recs={has_recs}"))
            except Exception as e:
                results.append(("GET /api/events/{id} 含 kill_chain+recommendations",
                                 False, str(e)[:60]))

        # ── 5. POST /api/events/{thread_id}/approve ───────────────────────
        if thread_id:
            try:
                r = await client.post(
                    f"{API}/api/events/{thread_id}/approve",
                    json={"action": "accepted", "reason": None, "analyst_id": "sprint3-test"},
                )
                d = r.json()
                ok = r.status_code == 200 and d.get("success") is True
                results.append(("POST /approve 接受操作返回 success=true", ok,
                                 f"success={d.get('success')}"))
            except Exception as e:
                results.append(("POST /approve 接受操作返回 success=true",
                                 False, str(e)[:60]))

        # ── 6. GET /api/metrics/mtta ──────────────────────────────────────
        try:
            r = await client.get(f"{API}/api/metrics/mtta")
            d = r.json()
            ok = (r.status_code == 200
                  and isinstance(d.get("mtta_avg_minutes"), (int, float))
                  and isinstance(d.get("acceptance_rate"),  (int, float)))
            results.append(("GET /api/metrics/mtta 返回合法数字", ok,
                             f"mtta={d.get('mtta_avg_minutes')} acc={d.get('acceptance_rate')}"))
        except Exception as e:
            results.append(("GET /api/metrics/mtta 返回合法数字", False, str(e)[:60]))

    # ── 7. Dashboard HTML 文件 ────────────────────────────────────────────
    dash_path = _PROJECT_ROOT / "src" / "dashboard" / "index.html"
    size = dash_path.stat().st_size if dash_path.exists() else 0
    ok = dash_path.exists() and size > 5 * 1024
    results.append(("src/dashboard/index.html 存在且 > 5KB", ok,
                     f"size={size} bytes"))

    # ── 8. IM Bot 无 Webhook 时返回 False ────────────────────────────────
    try:
        orig = os.environ.pop("DINGTALK_WEBHOOK", None)
        import importlib
        import src.im_bot.dingtalk_bot as bot_mod
        # 临时置空 webhook
        saved = bot_mod.DINGTALK_WEBHOOK
        bot_mod.DINGTALK_WEBHOOK = ""
        ret = bot_mod.send_alert_card({"thread_id": "test", "risk_score": 9.0})
        bot_mod.DINGTALK_WEBHOOK = saved
        if orig is not None:
            os.environ["DINGTALK_WEBHOOK"] = orig
        ok = ret is False
        results.append(("IM Bot 无 Webhook 时返回 False 不抛异常", ok,
                         f"returned={ret}"))
    except Exception as e:
        results.append(("IM Bot 无 Webhook 时返回 False 不抛异常",
                         False, str(e)[:60]))

    # ── 输出报告 ──────────────────────────────────────────────────────────
    print()
    print("── Sprint 3 验收报告 ──────────────────────────────")
    for label, ok, detail in results:
        print(f"  {_icon(ok)}  {label:<45}  {detail}")

    all_pass = all(ok for _, ok, _ in results)
    print()
    if all_pass:
        print("  最终结论：Sprint 3 门禁 通过 → 可进入 Sprint 4")
    else:
        fails = [lbl for lbl, ok, _ in results if not ok]
        print(f"  最终结论：Sprint 3 门禁 未通过 → {len(fails)} 项未通过")

    return all_pass


def main() -> None:
    print("── Sprint 3 验收开始 ──────────────────────────────")
    all_pass = asyncio.run(run_checks())
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
