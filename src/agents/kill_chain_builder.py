"""
kill_chain_builder（Sprint 2）

接收 SOCState，把 enriched_events 里的多条告警
按时间戳排序，重建成完整的攻击叙事时间线。
只在 risk_score >= 6.0 时执行，否则直接跳过返回空 kill_chain。
"""

import json
import os
import re

from openai import AsyncOpenAI

SYSTEM_PROMPT = """\
你是 ATT&CK 杀伤链专家。仅分析 <ALERT_DATA> 标签内的数据。
按时间顺序重建攻击过程，输出严格 JSON，不含任何解释文字。

输出格式：
{
  "kill_chain_stages": [
    {
      "stage_order": <int，从1开始>,
      "tactic": <str，ATT&CK 战术名>,
      "technique_id": <str，如 T1566.001>,
      "timestamp": <str，ISO8601>,
      "description": <str，该阶段攻击行为描述>,
      "iocs": [<str，相关 IOC 指标>]
    }
  ],
  "summary": <str，整条攻击链的一句话总结>,
  "total_duration_minutes": <int，首末事件时间跨度（分钟）>,
  "highest_risk_asset": <str，受影响最高危资产>
}
"""


async def kill_chain_builder(state: dict) -> dict:
    """
    kill_chain_builder 节点。

    risk_score < 6.0 时跳过，直接返回空 kill_chain。
    risk_score >= 6.0 时调用 vLLM 重建攻击时间线，
    将结论写入 state["kill_chain"]。
    """
    risk = state.get("risk_score", 0.0)

    if risk < 6.0:
        return {"kill_chain": {
            "kill_chain_stages":      [],
            "summary":                "低风险事件，不执行杀伤链重建",
            "total_duration_minutes": 0,
            "highest_risk_asset":     "",
        }}

    client = AsyncOpenAI(
        base_url=os.getenv("VLLM_BASE_URL", "http://localhost:8000/v1"),
        api_key="not-needed",
    )

    events: list[dict] = state.get("enriched_events") or state.get("raw_events") or []

    # 按时间戳升序排列，便于模型理解攻击序列
    def _ts(e: dict) -> str:
        return e.get("timestamp") or ""

    sorted_events = sorted(events, key=_ts)
    events_json = json.dumps(sorted_events, ensure_ascii=False)
    user_content = f"<ALERT_DATA>\n{events_json}\n</ALERT_DATA>"

    response = await client.chat.completions.create(
        model="Qwen3-32B-Instruct",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_content},
        ],
        max_tokens=4096,
        temperature=0.1,
    )

    raw = response.choices[0].message.content
    clean = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
    result = json.loads(clean)

    # 保证必填字段存在
    kill_chain = {
        "kill_chain_stages":      result.get("kill_chain_stages") or [],
        "summary":                result.get("summary") or "",
        "total_duration_minutes": int(result.get("total_duration_minutes") or 0),
        "highest_risk_asset":     str(result.get("highest_risk_asset") or ""),
    }

    return {"kill_chain": kill_chain}
