"""
tests/sprint1_acceptance.py
Sprint 1 MITRE 准确率验收脚本（T1）

测试流程：
  1. 加载全部 30 条合成样本
  2. 每条样本单独通过 LangGraph 图运行一遍
  3. 遇到 interrupt 自动注入 accepted，不需要人工干预
  4. 从 threat_intel["final_mitre_mapping"][0] 取 technique_id
  5. 与样本 ground_truth["technique_id"] 对比
  6. 计算严格准确率 / 宽松准确率 / P95 延迟

运行方式：
  python tests/sprint1_acceptance.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Optional

# ── 路径修正（允许从项目根目录运行）──────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from langgraph.types import Command

from src.graph.soc_graph import SOCState, build_soc_graph

FIXTURES_DIR = Path(__file__).parent / "fixtures"
_TOTAL_TARGET   = 30
_ACC_STRICT_MIN = 0.70   # 严格准确率目标 ≥ 70 %
_ACC_LENIENT_MIN = 0.80  # 宽松准确率目标 ≥ 80 %
_P95_MAX_SEC     = 20.0  # P95 延迟目标 < 20 s

# event_id 前缀 → 场景名
_SCENARIO_PREFIXES: dict[str, str] = {
    "a1b2c3d4": "A",
    "b2c3d4e5": "B",
    "c3d4e5f6": "C",
}


# ════════════════════════════════════════════════════════════════════════════
# 工具函数
# ════════════════════════════════════════════════════════════════════════════

def _load_samples() -> list[dict]:
    path = FIXTURES_DIR / "alerts_synthetic_30.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _get_scenario(event_id: str) -> str:
    prefix = (event_id or "")[:8].lower()
    return _SCENARIO_PREFIXES.get(prefix, "?")


def _norm_tactic(tactic: str) -> str:
    """标准化战术名称：去空格/下划线/连字符，转小写。"""
    return tactic.lower().replace(" ", "").replace("_", "").replace("-", "")


def _tactic_matches(pred: str, true: str) -> bool:
    """战术名称宽松匹配（不区分大小写/空格/下划线）。"""
    if not pred or not true:
        return False
    return _norm_tactic(pred) == _norm_tactic(true)


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = max(0, int(len(s) * 0.95) - 1)
    return s[idx]


# ════════════════════════════════════════════════════════════════════════════
# 单样本运行
# ════════════════════════════════════════════════════════════════════════════

_EMPTY_STATE: SOCState = {
    "raw_events":              [],
    "thread_id":               "",
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


async def _run_sample(
    graph,
    sample: dict,
    idx: int,
) -> dict:
    """
    运行单条样本，自动跳过 interrupt，返回结果字典。
    """
    thread_id = f"sprint1-sample-{idx:03d}"
    cfg = {"configurable": {"thread_id": thread_id}}

    init_state: SOCState = dict(_EMPTY_STATE,  # type: ignore[arg-type]
        raw_events=[sample],
        thread_id=thread_id,
    )

    t0 = time.perf_counter()
    error_msg: Optional[str] = None

    try:
        result = await graph.ainvoke(init_state, config=cfg)

        # 自动跳过 interrupt（最多 3 次，防止死循环）
        for _ in range(3):
            if "__interrupt__" not in result:
                break
            result = await graph.ainvoke(
                Command(resume={"action": "accepted"}),
                config=cfg,
            )

    except Exception as exc:  # noqa: BLE001
        result = {}
        error_msg = str(exc)

    elapsed = time.perf_counter() - t0

    # ── 提取预测结果 ────────────────────────────────────────────────────────
    ti = result.get("threat_intel") or {}
    mapping: list[dict] = ti.get("final_mitre_mapping") or []

    predicted_tid    = mapping[0].get("technique_id", "") if mapping else ""
    predicted_tactic = mapping[0].get("tactic", "")       if mapping else ""

    # ── ground_truth ────────────────────────────────────────────────────────
    gt              = sample.get("ground_truth", {})
    true_tid        = gt.get("technique_id", "")
    true_tactic     = gt.get("tactic", "")

    # ── 评分 ─────────────────────────────────────────────────────────────────
    # technique_id 完全匹配 → 正确
    exact   = bool(predicted_tid) and (predicted_tid == true_tid)
    # 战术名称匹配但 technique_id 不同 → 部分正确（0.5 分）
    partial = (not exact) and _tactic_matches(predicted_tactic, true_tactic)

    return {
        "idx":                 idx,
        "event_id":            sample.get("event_id", ""),
        "scenario":            _get_scenario(sample.get("event_id", "")),
        "predicted_technique": predicted_tid,
        "true_technique":      true_tid,
        "predicted_tactic":    predicted_tactic,
        "true_tactic":         true_tactic,
        "exact":               exact,
        "partial":             partial,
        "elapsed":             elapsed,
        "error":               error_msg,
    }


# ════════════════════════════════════════════════════════════════════════════
# 主流程
# ════════════════════════════════════════════════════════════════════════════

async def _run_all(samples: list[dict]) -> list[dict]:
    """顺序运行全部 30 条样本，共用同一 graph 实例。"""
    graph = build_soc_graph()
    results: list[dict] = []

    print(f"  运行 {len(samples)} 条样本（顺序执行）...\n")
    for idx, sample in enumerate(samples):
        r = await _run_sample(graph, sample, idx)
        tag = "✓" if r["exact"] else ("~" if r["partial"] else "✗")
        err = f"  [ERR: {r['error'][:60]}]" if r["error"] else ""
        print(
            f"  [{idx+1:02d}/{len(samples)}] {tag} "
            f"场景{r['scenario']} "
            f"预期:{r['true_technique']:<12} "
            f"实际:{r['predicted_technique']:<12} "
            f"{r['elapsed']:.2f}s{err}"
        )
        results.append(r)

    return results


def _print_report(results: list[dict]) -> bool:
    """打印验收报告，返回是否门禁通过。"""
    total   = len(results)
    exact_n = sum(1 for r in results if r["exact"])
    part_n  = sum(1 for r in results if r["partial"])
    wrong_n = total - exact_n - part_n

    acc_strict  = exact_n / total
    acc_lenient = (exact_n + part_n * 0.5) / total
    elapsed_list = [r["elapsed"] for r in results]
    p95_latency  = _p95(elapsed_list)

    pass_strict  = acc_strict  >= _ACC_STRICT_MIN
    pass_lenient = acc_lenient >= _ACC_LENIENT_MIN
    pass_p95     = p95_latency < _P95_MAX_SEC
    all_pass     = pass_strict and pass_lenient and pass_p95

    def _icon(ok: bool) -> str:
        return "✓" if ok else "✗"

    print()
    print("── Sprint 1 验收报告 ──────────────────────────────")
    print(f"  总样本数:    {total}")
    print(f"  完全正确:    {exact_n}  条")
    print(f"  部分正确:    {part_n}  条")
    print(f"  完全错误:    {wrong_n}  条")
    print()
    print(
        f"  MITRE 准确率（严格）:  {acc_strict*100:5.1f}%"
        f"   [目标: ≥ {_ACC_STRICT_MIN*100:.0f}%]"
        f"  {_icon(pass_strict)}"
    )
    print(
        f"  MITRE 准确率（宽松）:  {acc_lenient*100:5.1f}%"
        f"   [目标: ≥ {_ACC_LENIENT_MIN*100:.0f}%]"
        f"  {_icon(pass_lenient)}"
    )
    print(
        f"  P95 端到端延迟:  {p95_latency:5.1f}s"
        f"      [目标: < {_P95_MAX_SEC:.0f}s]"
        f"    {_icon(pass_p95)}"
    )

    # 错误样本明细
    wrong_results = [r for r in results if not r["exact"] and not r["partial"]]
    if wrong_results:
        print()
        print("  错误样本明细：")
        for r in wrong_results:
            eid_short = (r["event_id"] or "")[:8]
            err_note  = f"  [错误:{r['error'][:40]}]" if r["error"] else ""
            print(
                f"    [{eid_short}] "
                f"预期: {r['true_technique']:<12} "
                f"实际: {r['predicted_technique'] or '(无)':<12} "
                f"场景: {r['scenario']}{err_note}"
            )

    print()
    if all_pass:
        print("  最终结论：Sprint 1 门禁 通过 → 可进入 Sprint 2")
    else:
        fails = []
        if not pass_strict:
            fails.append(f"严格准确率 {acc_strict*100:.1f}% < {_ACC_STRICT_MIN*100:.0f}%")
        if not pass_lenient:
            fails.append(f"宽松准确率 {acc_lenient*100:.1f}% < {_ACC_LENIENT_MIN*100:.0f}%")
        if not pass_p95:
            fails.append(f"P95延迟 {p95_latency:.1f}s ≥ {_P95_MAX_SEC:.0f}s")
        print(f"  最终结论：Sprint 1 门禁 未通过 → {', '.join(fails)}")

    return all_pass


def main() -> None:
    print("── Sprint 1 验收开始 ──────────────────────────────")
    samples = _load_samples()
    assert len(samples) == _TOTAL_TARGET, \
        f"样本数 {len(samples)} ≠ {_TOTAL_TARGET}"

    results  = asyncio.run(_run_all(samples))
    all_pass = _print_report(results)
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
