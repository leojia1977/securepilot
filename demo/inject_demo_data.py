"""
demo/inject_demo_data.py — 演示数据注入工具

向 SecuPilot 注入三批演示攻击场景数据，用于客户演示。
运行前需确保 FastAPI 后端在 http://localhost:8080 运行。
"""

import os
os.environ["NO_PROXY"] = "localhost,127.0.0.1"
os.environ["no_proxy"] = "localhost,127.0.0.1"

import sys
import time
from pathlib import Path

import httpx

_PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from tests.fixtures.synthetic_alerts import SCENARIO_A, SCENARIO_B, SCENARIO_C

API = "http://localhost:8080"

_SCENARIOS = [
    ("场景A（APT鱼叉钓鱼）", SCENARIO_A),
    ("场景B（勒索软件扩散）", SCENARIO_B),
    ("场景C（供应链攻击）",  SCENARIO_C),
]


def inject_all() -> None:
    thread_ids: list[str] = []

    with httpx.Client(timeout=30.0) as client:
        for label, events in _SCENARIOS:
            print(f"注入{label}... ", end="", flush=True)
            try:
                r = client.post(f"{API}/api/trigger", json={"events": events})
                r.raise_for_status()
                thread_id = r.json().get("thread_id", "unknown")
                thread_ids.append(thread_id)
                print(f"完成，thread_id={thread_id}")
            except Exception as e:
                print(f"失败：{e}")
                continue

            print("  等待分析完成（20秒）...")
            time.sleep(20)

        # 查询最终事件数
        try:
            r = client.get(f"{API}/api/events?limit=50")
            total = r.json().get("total", 0)
            print()
            print(f"演示数据注入完成，共 {total} 条事件可在 Dashboard 查看")
        except Exception as e:
            print(f"查询事件列表失败：{e}")


if __name__ == "__main__":
    inject_all()
