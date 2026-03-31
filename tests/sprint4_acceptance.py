"""
tests/sprint4_acceptance.py
Sprint 4 验收脚本：PoC 交付包完整性 + 演示数据注入

运行前需启动：
  uvicorn src.api.main:app --port 8080 --reload
"""

from __future__ import annotations

import os
os.environ["NO_PROXY"] = "localhost,127.0.0.1"
os.environ["no_proxy"] = "localhost,127.0.0.1"

import asyncio
import ast
import sys
import time
from pathlib import Path

import httpx

_PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

API = "http://localhost:8080"


def _icon(ok: bool) -> str:
    return "✓" if ok else "✗"


async def run_checks() -> bool:
    results: list[tuple[str, bool, str]] = []

    # ── 1. deploy/Dockerfile 存在 ─────────────────────────────────────────
    p = _PROJECT_ROOT / "deploy" / "Dockerfile"
    ok = p.exists()
    results.append(("deploy/Dockerfile 文件存在", ok, str(p.stat().st_size) + " bytes" if ok else "not found"))

    # ── 2. deploy/docker-compose.prod.yml 存在 ───────────────────────────
    p = _PROJECT_ROOT / "deploy" / "docker-compose.prod.yml"
    ok = p.exists()
    results.append(("deploy/docker-compose.prod.yml 文件存在", ok,
                     str(p.stat().st_size) + " bytes" if ok else "not found"))

    # ── 3. deploy/setup.py 语法正确 ──────────────────────────────────────
    p = _PROJECT_ROOT / "deploy" / "setup.py"
    if p.exists():
        try:
            ast.parse(p.read_text(encoding="utf-8"))
            ok = True
            detail = "syntax OK"
        except SyntaxError as e:
            ok = False
            detail = str(e)[:60]
    else:
        ok = False
        detail = "not found"
    results.append(("deploy/setup.py 存在且语法正确", ok, detail))

    # ── 4. deploy/DEPLOYMENT_CHECKLIST.md > 2KB ──────────────────────────
    p = _PROJECT_ROOT / "deploy" / "DEPLOYMENT_CHECKLIST.md"
    size = p.stat().st_size if p.exists() else 0
    ok = p.exists() and size > 2 * 1024
    results.append(("deploy/DEPLOYMENT_CHECKLIST.md > 2KB", ok, f"size={size} bytes"))

    # ── 5. demo/inject_demo_data.py 存在 ─────────────────────────────────
    p = _PROJECT_ROOT / "demo" / "inject_demo_data.py"
    ok = p.exists()
    results.append(("demo/inject_demo_data.py 文件存在", ok, "found" if ok else "not found"))

    # ── 6. 运行 inject_demo_data.py，70秒后 events >= 3 ─────────────────
    inject_ok = False
    inject_detail = "skipped"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            # 先确认 API 可达
            r = await client.get(f"{API}/health")
            if r.status_code == 200:
                # 注入三个场景
                from tests.fixtures.synthetic_alerts import SCENARIO_A, SCENARIO_B, SCENARIO_C
                for scenario in [SCENARIO_A, SCENARIO_B, SCENARIO_C]:
                    await client.post(f"{API}/api/trigger", json={"events": scenario})

                print("  等待分析完成（70秒）...", flush=True)
                await asyncio.sleep(70)

                r = await client.get(f"{API}/api/events?limit=50")
                total = r.json().get("total", 0)
                inject_ok = total >= 3
                inject_detail = f"total={total}"
            else:
                inject_detail = f"API health={r.status_code}"
    except Exception as e:
        inject_detail = str(e)[:60]
    results.append(("注入演示数据后 /api/events >= 3 条", inject_ok, inject_detail))

    # ── 7. GET /api/metrics/mtta total_events_today >= 3 ─────────────────
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(f"{API}/api/metrics/mtta")
            d = r.json()
            total_today = d.get("total_events_today", 0)
            ok = r.status_code == 200 and total_today >= 3
            results.append(("GET /api/metrics/mtta total_events_today >= 3", ok,
                             f"total_today={total_today}"))
    except Exception as e:
        results.append(("GET /api/metrics/mtta total_events_today >= 3", False, str(e)[:60]))

    # ── 8. src/dashboard/index.html > 5KB ────────────────────────────────
    p = _PROJECT_ROOT / "src" / "dashboard" / "index.html"
    size = p.stat().st_size if p.exists() else 0
    ok = p.exists() and size > 5 * 1024
    results.append(("src/dashboard/index.html > 5KB", ok, f"size={size} bytes"))

    # ── 输出报告 ──────────────────────────────────────────────────────────
    print()
    print("── Sprint 4 验收报告 ──────────────────────────────")
    for label, ok, detail in results:
        print(f"  {_icon(ok)}  {label:<50}  {detail}")

    all_pass = all(ok for _, ok, _ in results)
    print()
    if all_pass:
        print("  最终结论：Sprint 4 门禁 通过 → PoC 交付包就绪")
    else:
        fails = [lbl for lbl, ok, _ in results if not ok]
        print(f"  最终结论：Sprint 4 门禁 未通过 → {len(fails)} 项未通过")

    return all_pass


def main() -> None:
    print("── Sprint 4 验收开始 ──────────────────────────────")
    all_pass = asyncio.run(run_checks())
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
