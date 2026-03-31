"""
LangGraph 完整分析图 M06（Sprint 2 正式版）

图结构：
  START
    → ingest（归一化 + 初始风险评分）
    → supervisor_router（决定激活哪些子智能体）
    → [network_analyst, endpoint_analyst]（并行，按事件类型激活）
    → threat_intel（汇总归因，输出 final_mitre_mapping）
    → 条件路由（risk_score >= 6.0）：
        高风险 → kill_chain_builder → recommendation_engine → approval_gate
        低风险 → approval_gate
    → 条件路由：
        accepted/auto_approved → openclaw_output → END
        rejected               → END（RLHF 数据已记录）

checkpointer: MemorySaver（Sprint 1/2，不用 PostgreSQL）
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List, Optional

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt
from typing_extensions import TypedDict

from src.agents.endpoint_analyst import endpoint_analyst as _endpoint_analyst
from src.agents.kill_chain_builder import kill_chain_builder as _kill_chain_builder
from src.agents.network_analyst import network_analyst as _network_analyst
from src.agents.recommendation_engine import recommendation_engine as _recommendation_engine
from src.agents.threat_intel import threat_intel as _threat_intel_fn
from src.pipeline.normalizer import normalize_batch


# ════════════════════════════════════════════════════════════════════════════
# 完整 SOCState 定义
# ════════════════════════════════════════════════════════════════════════════

class SOCState(TypedDict):
    # ── 输入 ──────────────────────────────────────────────────────────────
    raw_events:  List[dict]
    thread_id:   str

    # ── 分析过程 ───────────────────────────────────────────────────────────
    enriched_events:  List[dict]
    network_analysis:  Optional[dict]
    endpoint_analysis: Optional[dict]
    threat_intel:      Optional[dict]   # M09 输出

    # ── 推理输出 ───────────────────────────────────────────────────────────
    kill_chain:      Optional[dict]
    recommendations: List[dict]
    risk_score:      float

    # ── 人机协同 ───────────────────────────────────────────────────────────
    human_approval_required: bool
    approval_status: str        # "pending"|"accepted"|"rejected"|"auto_approved"
    rejection_reason: Optional[str]

    # ── RLHF 数据收集 ─────────────────────────────────────────────────────
    rlhf_record: Optional[dict]

    # ── 系统 ──────────────────────────────────────────────────────────────
    error: Optional[str]


# ════════════════════════════════════════════════════════════════════════════
# 节点实现
# ════════════════════════════════════════════════════════════════════════════

def _ingest_node(state: SOCState) -> dict:
    """
    ingest 节点：将 raw_events 归一化为 enriched_events，
    计算初始 risk_score（取所有事件最大值）。
    """
    raw = state.get("raw_events") or []
    enriched = normalize_batch(raw) if raw else []
    scores = [float(e.get("risk_score", 0.0)) for e in enriched if e.get("risk_score") is not None]
    initial_risk = max(scores) if scores else 0.0
    return {
        "enriched_events": enriched,
        "risk_score":      initial_risk,
    }


def supervisor_router(state: SOCState) -> list[str]:
    """
    Supervisor 路由函数（conditional edge 决策函数）。

    - 事件中有 source_type=="network"  → 激活 network_analyst
    - 事件中有 source_type=="endpoint" → 激活 endpoint_analyst
    - 若无相关事件，直接路由到 threat_intel
    """
    events: list[dict] = state.get("enriched_events") or []
    has_network  = any(e.get("source_type") == "network"  for e in events)
    has_endpoint = any(e.get("source_type") == "endpoint" for e in events)

    routes: list[str] = []
    if has_network:
        routes.append("network_analyst")
    if has_endpoint:
        routes.append("endpoint_analyst")

    if not routes:
        routes.append("threat_intel")

    return routes


async def _threat_intel_node(state: SOCState) -> dict:
    """threat_intel 节点包装：调用 M09 并同步更新 risk_score。"""
    result = await _threat_intel_fn(state)
    ti: dict = result.get("threat_intel") or {}
    raw_score = ti.get("final_risk_score")
    try:
        risk_score = float(raw_score)
        risk_score = min(10.0, max(0.0, risk_score))
    except (TypeError, ValueError):
        risk_score = state.get("risk_score", 0.0)

    return {
        "threat_intel": ti,
        "risk_score":   risk_score,
    }


async def _approval_gate_node(state: SOCState) -> dict:
    """
    approval_gate 节点：
    - risk_score >= 6.0 → interrupt() 暂停，等待人工决策
    - risk_score < 6.0  → 自动 auto_approved
    """
    risk = state.get("risk_score", 0.0)

    if risk >= 6.0:
        kc = state.get("kill_chain") or {}

        decision: dict = interrupt({
            "message":            "高风险事件需要人工确认",
            "risk_score":         risk,
            "kill_chain_summary": kc.get("summary", ""),
            "recommendations":    state.get("recommendations", []),
        })

        action           = decision.get("action", "pending")
        rejection_reason = decision.get("rejection_reason")
        analyst_id       = decision.get("analyst_id")

        rlhf_record = {
            "thread_id":        state.get("thread_id", ""),
            "timestamp":        datetime.now(tz=timezone.utc).isoformat(),
            "risk_score":       risk,
            "action":           action,
            "rejection_reason": rejection_reason,
            "analyst_id":       analyst_id,
        }

        return {
            "approval_status":        action,
            "rejection_reason":       rejection_reason,
            "human_approval_required": True,
            "rlhf_record":            rlhf_record,
        }

    return {
        "approval_status":        "auto_approved",
        "human_approval_required": False,
    }


async def _openclaw_output_node(state: SOCState) -> dict:
    """
    OpenClaw bridge 节点（Sprint 2 阶段为存根）。
    确保 recommendations 已由 recommendation_engine 填充。
    """
    # ── OpenClaw bridge 调用占位（Sprint 0 骨架约定，禁止删除）────────────
    # TODO(Sprint 3): await openclaw_client.persist(state)
    # ─────────────────────────────────────────────────────────────────────

    recommendations = state.get("recommendations") or []

    # 若 recommendation_engine 未运行（低风险路径），生成基础建议
    if not recommendations:
        ti = state.get("threat_intel") or {}
        risk_level = ti.get("risk_level", "medium")
        recommendations = [{
            "action":       f"根据威胁情报分析结论（{risk_level}级）执行响应处置",
            "impact_scope": "待评估",
            "priority":     "within_24h",
            "playbook_ref": "",
        }]

    return {"recommendations": recommendations}


# ════════════════════════════════════════════════════════════════════════════
# 条件路由函数
# ════════════════════════════════════════════════════════════════════════════

def _route_after_threat_intel(state: SOCState) -> str:
    """threat_intel 后：高风险走 kill_chain_builder，低风险直接到 approval_gate。"""
    return "kill_chain_builder" if state.get("risk_score", 0.0) >= 6.0 else "approval_gate"


def _route_after_approval(state: SOCState) -> str:
    """approval_gate 后：通过 → openclaw_output，拒绝 → END。"""
    status = state.get("approval_status", "pending")
    return "openclaw_output" if status in ("accepted", "auto_approved") else END


# ════════════════════════════════════════════════════════════════════════════
# 图构建
# ════════════════════════════════════════════════════════════════════════════

def build_soc_graph(checkpointer: Any = None) -> Any:
    """
    构建并编译 SOC 分析图（Sprint 2）。

    Args:
        checkpointer: LangGraph checkpointer 实例，默认使用 MemorySaver。

    Returns:
        编译好的 CompiledGraph，可直接调用 ainvoke / invoke。
    """
    if checkpointer is None:
        checkpointer = MemorySaver()

    g = StateGraph(SOCState)

    # ── 注册节点 ─────────────────────────────────────────────────────────
    g.add_node("ingest",                _ingest_node)
    g.add_node("network_analyst",       _network_analyst)
    g.add_node("endpoint_analyst",      _endpoint_analyst)
    g.add_node("threat_intel",          _threat_intel_node)
    g.add_node("kill_chain_builder",    _kill_chain_builder)
    g.add_node("recommendation_engine", _recommendation_engine)
    g.add_node("approval_gate",         _approval_gate_node)
    g.add_node("openclaw_output",       _openclaw_output_node)

    # ── 边 ───────────────────────────────────────────────────────────────
    g.add_edge(START, "ingest")

    # ingest → fan-out
    g.add_conditional_edges(
        "ingest",
        supervisor_router,
        ["network_analyst", "endpoint_analyst", "threat_intel"],
    )

    # 子智能体 → threat_intel（fan-in）
    g.add_edge("network_analyst",  "threat_intel")
    g.add_edge("endpoint_analyst", "threat_intel")

    # threat_intel → kill_chain_builder（高风险）或 approval_gate（低风险）
    g.add_conditional_edges(
        "threat_intel",
        _route_after_threat_intel,
        {"kill_chain_builder": "kill_chain_builder", "approval_gate": "approval_gate"},
    )

    # kill_chain_builder → recommendation_engine → approval_gate
    g.add_edge("kill_chain_builder",    "recommendation_engine")
    g.add_edge("recommendation_engine", "approval_gate")

    # approval_gate → openclaw_output 或 END
    g.add_conditional_edges(
        "approval_gate",
        _route_after_approval,
        {"openclaw_output": "openclaw_output", END: END},
    )

    g.add_edge("openclaw_output", END)

    return g.compile(checkpointer=checkpointer)


# ── 模块级默认实例 ────────────────────────────────────────────────────────
soc_graph = build_soc_graph()
