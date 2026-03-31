"""
Mock vLLM 推理服务
完全兼容 OpenAI /v1/chat/completions 接口格式
模拟 Qwen3-32B-Instruct Thinking Mode 响应
"""

import os
os.environ["NO_PROXY"] = "localhost,127.0.0.1"
os.environ["no_proxy"] = "localhost,127.0.0.1"

import asyncio
import random
import time
import uuid
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from mock.response_templates import route_to_template

app = FastAPI(title="Mock vLLM Server", version="0.1.0")


# ──────────────────────────── 请求 / 响应模型 ────────────────────────────

class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str = "Qwen3-32B-Instruct"
    messages: List[ChatMessage]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 2048
    stream: Optional[bool] = False


class ChatCompletionChoice(BaseModel):
    index: int
    message: ChatMessage
    finish_reason: str


class UsageInfo(BaseModel):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class ChatCompletionResponse(BaseModel):
    id: str
    object: str
    created: int
    model: str
    choices: List[ChatCompletionChoice]
    usage: UsageInfo


# ──────────────────────────── 端点 ────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/v1/models")
async def list_models():
    return {
        "object": "list",
        "data": [
            {
                "id": "Qwen3-32B-Instruct",
                "object": "model",
                "created": int(time.time()),
                "owned_by": "mock",
            }
        ],
    }


@app.post("/v1/chat/completions", response_model=ChatCompletionResponse)
async def chat_completions(request: ChatCompletionRequest):
    if not request.messages:
        raise HTTPException(status_code=400, detail="messages 不能为空")

    # 取最后一条用户消息作为路由依据
    user_content = ""
    for msg in reversed(request.messages):
        if msg.role == "user":
            user_content = msg.content
            break

    # 模拟推理延迟 0.5 ~ 1.5 秒
    delay = random.uniform(0.5, 1.5)
    await asyncio.sleep(delay)

    content = route_to_template([{"role": m.role, "content": m.content} for m in request.messages])

    # 简单估算 token 数
    prompt_tokens = sum(len(m.content.split()) * 2 for m in request.messages)
    completion_tokens = len(content.split()) * 2

    response = ChatCompletionResponse(
        id=f"chatcmpl-{uuid.uuid4().hex}",
        object="chat.completion",
        created=int(time.time()),
        model=request.model,
        choices=[
            ChatCompletionChoice(
                index=0,
                message=ChatMessage(role="assistant", content=content),
                finish_reason="stop",
            )
        ],
        usage=UsageInfo(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        ),
    )
    return response


# ──────────────────────────── 入口 ────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("vllm_server:app", host="0.0.0.0", port=8000, reload=False)
