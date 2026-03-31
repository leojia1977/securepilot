"""
tests/sprint2_acceptance.py
Sprint 2 验收脚本：杀伤链重建器 + 响应建议引擎

测试流程：
  1. 取场景 A 前 5 条样本（连续攻击链）
  2. 一起放入 enriched_events 跑完整图
  3. 遇到 interrupt 自动注入 accepted
  4. 验收 kill_chain / recommendations / human_approval_required / 延迟
"""

from __future__ import annotations

import os
os.environ["NO_PROXY"] = "localhost,127.0.0.1"
os.environ["no_proxy"] = "localhost,127.0.0.1"

import asyncio
import sys
import time
from pathlib import Path
from typing import Optional

_PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from langgraph.types import Command

from src.graph.soc_graph import SOCState, build_soc_graph
from tests.fixtures.synthetic_alerts import SCENARIO_A

_P_LATENCY_MAX = 30.0  # 秒


# ════════════════════════════════════════════════════════════════════════════
# 检查函数
# ════════════════════════════════════════════════════════════════════════════

def _icon(ok: bool) -> str:
    return "✓" if ok else "✗"


def _check_kill_chain(kc: Optional[dict]) -> tuple[bool, bool, int]:
    """返回 (stages_ok, fields_ok, stage_count)"""
    if not kc:
        return False, False, 0
    stages = kc.get("kill_chain_stages") or []
    stage_count = len(stages)
    stages_ok = stage_count >= 3

    required_fields = {"tactic", "technique_id", "timestamp", "description"}
    fields_ok = all(
        required_fields.issubset(s.keys()) and
        all(s.get(f) for f in required_fields)
        for s in stages
    ) if stages else False

    return stages_ok, fields_ok, stage_count


def _check_recommendations(recs: list[dict]) -> tuple[bool, bool, int]:
    """返回 (count_ok, fields_ok, rec_count)"""
    rec_count = len(recs)
    count_ok = rec_count >= 1

    required_fields = {"action", "impact_scope", "priority"}
    fields_ok = all(
        required_fields.issubset(r.keys()) and
        all(r.get(f) for f in required_fields)
        for r in recs
    ) if recs else False

    return count_ok, fields_ok, rec_count


# ════════════════════════════════════════════════════════════════════════════
# 主流程
# ════════════════════════════════════════════════════════════════════════════

async def _run() -> bool:
    samples = SCENARIO_A[:5]
    graph = build_soc_graph()
    thread_id = "sprint2-acceptance-001"
    cfg = {"configurable": {"thread_id": thread_id}}

    init_state: SOCState = {
        "raw_events":              samples,
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

    t0 = time.perf_counter()
    error_msg: Optional[str] = None

    try:
        result = await graph.ainvoke(init_state, config=cfg)

        for _ in range(3):
            if "__interrupt__" not in result:
                break
            result = await graph.ainvoke(
                Command(resume={"action": "accepted"}),
                config=cfg,
            )
    except Exception as exc:
        result = {}
        error_msg = str(exc)

    elapsed = time.perf_counter() - t0

    # ── 提取结果 ─────────────────────────────────────────────────────────
    kc   = result.get("kill_chain") or {}
    recs = result.get("recommendations") or []
    har  = result.get("human_approval_required", False)

    # ── 各项检查 ─────────────────────────────────────────────────────────
    stages_ok, fields_ok, stage_count = _check_kill_chain(kc)
    recs_ok, rec_fields_ok, rec_count = _check_recommendations(recs)
    har_ok     = har is True
    latency_ok = elapsed < _P_LATENCY_MAX

    all_pass = all([stages_ok, fields_ok, recs_ok, rec_fields_ok, har_ok, latency_ok])

    # ── 输出报告 ─────────────────────────────────────────────────────────
    print()
    print("── Sprint 2 验收报告 ──────────────────────────────")
    print(f"  {_icon(stages_ok)}  杀伤链阶段数 >= 3          实际: {stage_count} 阶段")
    print(f"  {_icon(fields_ok)}  每阶段字段完整             "
          f"(tactic/technique_id/timestamp/description)")
    print(f"  {_icon(recs_ok)}  响应建议数 >= 1            实际: {rec_count} 条")
    print(f"  {_icon(rec_fields_ok)}  每条建议含影响范围         "
          f"(action/impact_scope/priority)")
    print(f"  {_icon(har_ok)}  human_approval_required=True")
    print(f"  {_icon(latency_ok)}  端到端延迟 < {_P_LATENCY_MAX:.0f}s"
          f"           实际: {elapsed:.1f}s")

    if error_msg:
        print(f"\n  [错误] {error_msg[:120]}")

    print()
    if all_pass:
        print("  最终结论：Sprint 2 门禁 通过 → 可进入 Sprint 3")
    else:
        fails = []
        if not stages_ok:
            fails.append(f"杀伤链阶段数 {stage_count} < 3")
        if not fields_ok:
            fails.append("杀伤链阶段字段不完整")
        if not recs_ok:
            fails.append(f"建议数 {rec_count} < 1")
        if not rec_fields_ok:
            fails.append("建议字段不完整")
        if not har_ok:
            fails.append("human_approval_required 不为 True")
        if not latency_ok:
            fails.append(f"延迟 {elapsed:.1f}s >= {_P_LATENCY_MAX:.0f}s")
        print(f"  最终结论：Sprint 2 门禁 未通过 → {', '.join(fails)}")

    return all_pass


def main() -> None:
    print("── Sprint 2 验收开始 ──────────────────────────────")
    print(f"  使用场景 A 前 5 条样本（连续攻击链）")
    all_pass = asyncio.run(_run())
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
