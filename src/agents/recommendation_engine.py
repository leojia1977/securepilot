"""
recommendation_engine（Sprint 2）

基于 kill_chain 和 threat_intel 的结论，
生成 1~3 条响应建议，每条必须包含影响范围说明。
所有建议标注 human_approval_required=True。
"""

import json
import os
import re

from openai import AsyncOpenAI

SYSTEM_PROMPT = """\
你是安全响应专家。仅分析 <ALERT_DATA> 标签内的数据。
根据攻击链和威胁情报，生成操作建议，输出严格 JSON。
每条建议必须说明影响范围，优先级只能是
immediate / within_1h / within_24h 三种。

输出格式（JSON 数组，1~3 条）：
[
  {
    "action": <str，具体操作步骤>,
    "impact_scope": <str，操作影响范围说明>,
    "priority": <"immediate"|"within_1h"|"within_24h">,
    "playbook_ref": <str，参考剧本编号或名称>
  }
]
"""

_VALID_PRIORITIES = {"immediate", "within_1h", "within_24h"}


async def recommendation_engine(state: dict) -> dict:
    """
    recommendation_engine 节点。

    汇总 kill_chain + threat_intel 上下文，生成响应建议，
    将结论写入 state["recommendations"]，
    并将 state["human_approval_required"] 设为 True。
    """
    client = AsyncOpenAI(
        base_url=os.getenv("VLLM_BASE_URL", "http://localhost:8000/v1"),
        api_key="not-needed",
    )

    kill_chain: dict = state.get("kill_chain") or {}
    threat_intel: dict = state.get("threat_intel") or {}
    events: list[dict] = state.get("enriched_events") or state.get("raw_events") or []

    context = {
        "events":       events,
        "kill_chain":   kill_chain,
        "threat_intel": threat_intel,
    }
    context_json = json.dumps(context, ensure_ascii=False)
    user_content = f"<ALERT_DATA>\n{context_json}\n</ALERT_DATA>"

    response = await client.chat.completions.create(
        model="Qwen3-32B-Instruct",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_content},
        ],
        max_tokens=1024,
        temperature=0.1,
        response_format={"type": "json_object"},
        extra_body={"chat_template_kwargs": {"enable_thinking": False}},
    )

    raw = response.choices[0].message.content
    clean = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
    result = json.loads(clean)

    # 结果可能是列表，也可能是 {"recommendations": [...]}
    if isinstance(result, list):
        recs_raw = result
    else:
        recs_raw = result.get("recommendations") or result.get("actions") or []
        if not isinstance(recs_raw, list):
            recs_raw = [recs_raw] if recs_raw else []

    # 规范化每条建议，确保必填字段存在且优先级合法
    recommendations = []
    for item in recs_raw[:3]:
        if not isinstance(item, dict):
            continue
        priority = item.get("priority", "within_24h")
        if priority not in _VALID_PRIORITIES:
            priority = "within_24h"
        recommendations.append({
            "action":       str(item.get("action", "")),
            "impact_scope": str(item.get("impact_scope", "")),
            "priority":     priority,
            "playbook_ref": str(item.get("playbook_ref", "")),
        })

    # 保底：至少一条建议
    if not recommendations:
        risk_level = threat_intel.get("risk_level", "medium")
        recommendations = [{
            "action":       f"根据威胁情报（{risk_level}级）立即启动事件响应流程",
            "impact_scope": "影响范围待评估",
            "priority":     "immediate",
            "playbook_ref": "PB-IR-000: Default Response",
        }]

    return {
        "recommendations":        recommendations,
        "human_approval_required": True,
    }
