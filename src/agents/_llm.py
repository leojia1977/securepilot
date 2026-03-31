"""
共享 LLM 调用工具

封装对 vLLM /v1/chat/completions 接口的 async 调用，
剥离 <think>...</think> 推理块后返回解析好的 JSON 字典。
"""

import json
import os
import re

import httpx

VLLM_BASE_URL: str = os.environ.get("VLLM_BASE_URL", "http://localhost:8000/v1")
_MODEL = "Qwen3-32B-Instruct"


async def call_llm(
    system_prompt: str,
    user_message: str,
    timeout: float = 10.0,
) -> dict:
    """
    调用 vLLM 推理接口，返回解析后的 JSON 字典。

    Args:
        system_prompt: 系统提示（包含任务说明和安全边界）
        user_message:  用户消息（告警数据应包裹在 <ALERT_DATA> 标签内）
        timeout:       请求超时秒数

    Returns:
        解析后的 JSON 字典

    Raises:
        httpx.HTTPError: 网络错误
        json.JSONDecodeError: 响应无法解析为 JSON
    """
    payload = {
        "model": _MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_message},
        ],
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{VLLM_BASE_URL}/chat/completions",
            json=payload,
            timeout=timeout,
        )
        resp.raise_for_status()

    content: str = resp.json()["choices"][0]["message"]["content"]

    # 剥离 Qwen3 thinking 块 <think>...</think>
    clean = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

    return json.loads(clean)
