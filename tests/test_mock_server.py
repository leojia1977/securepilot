"""
Mock vLLM 服务接口测试
验证全部验收标准
"""

import json
import re
import sys
import os

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

# 将 mock 目录加入 Python 路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mock"))

from vllm_server import app  # noqa: E402


# ──────────────────────────── Fixtures ────────────────────────────

@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


# ──────────────────────────── 辅助函数 ────────────────────────────

def extract_json_from_content(content: str) -> dict:
    """从包含 <think> 标签的响应中提取 JSON 内容"""
    # 移除 <think>...</think> 块
    clean = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
    return json.loads(clean)


# ──────────────────────────── 测试用例 ────────────────────────────

@pytest.mark.asyncio
async def test_health(client):
    """验收：GET /health 返回 {"status":"ok"}"""
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_chat_completions_returns_200(client):
    """POST /v1/chat/completions 应返回 200"""
    payload = {
        "model": "Qwen3-32B-Instruct",
        "messages": [{"role": "user", "content": "分析这条告警"}],
    }
    resp = await client.post("/v1/chat/completions", json=payload)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_response_structure(client):
    """响应结构必须符合 OpenAI 格式"""
    payload = {
        "model": "Qwen3-32B-Instruct",
        "messages": [{"role": "user", "content": "请分析这条安全告警"}],
    }
    resp = await client.post("/v1/chat/completions", json=payload)
    data = resp.json()

    assert "id" in data
    assert data["object"] == "chat.completion"
    assert "created" in data
    assert "model" in data
    assert "choices" in data
    assert len(data["choices"]) > 0
    assert "usage" in data
    assert "prompt_tokens" in data["usage"]
    assert "completion_tokens" in data["usage"]
    assert "total_tokens" in data["usage"]


@pytest.mark.asyncio
async def test_response_contains_think_tag(client):
    """验收：响应 content 必须包含 <think> 标签"""
    payload = {
        "model": "Qwen3-32B-Instruct",
        "messages": [{"role": "user", "content": "请分析这条安全告警"}],
    }
    resp = await client.post("/v1/chat/completions", json=payload)
    content = resp.json()["choices"][0]["message"]["content"]

    assert "<think>" in content
    assert "</think>" in content


@pytest.mark.asyncio
async def test_response_json_has_required_fields(client):
    """验收：解析后的 JSON 必须包含 risk_score 和 mitre_mapping"""
    payload = {
        "model": "Qwen3-32B-Instruct",
        "messages": [{"role": "user", "content": "请分析这条安全告警"}],
    }
    resp = await client.post("/v1/chat/completions", json=payload)
    content = resp.json()["choices"][0]["message"]["content"]
    parsed = extract_json_from_content(content)

    assert "risk_score" in parsed
    assert "mitre_mapping" in parsed
    assert "root_cause" in parsed
    assert "recommendations" in parsed


@pytest.mark.asyncio
async def test_risk_score_is_numeric(client):
    """risk_score 必须是数值类型"""
    payload = {
        "model": "Qwen3-32B-Instruct",
        "messages": [{"role": "user", "content": "分析告警"}],
    }
    resp = await client.post("/v1/chat/completions", json=payload)
    content = resp.json()["choices"][0]["message"]["content"]
    parsed = extract_json_from_content(content)

    assert isinstance(parsed["risk_score"], (int, float))
    assert 0 <= parsed["risk_score"] <= 10


@pytest.mark.asyncio
async def test_kill_chain_routing(client):
    """含 kill/chain/timeline 关键词 → 返回杀伤链模板"""
    payload = {
        "model": "Qwen3-32B-Instruct",
        "messages": [{"role": "user", "content": "请分析这次攻击的 kill chain timeline"}],
    }
    resp = await client.post("/v1/chat/completions", json=payload)
    content = resp.json()["choices"][0]["message"]["content"]
    parsed = extract_json_from_content(content)

    assert "kill_chain_timeline" in parsed


@pytest.mark.asyncio
async def test_mitre_routing(client):
    """含 mitre/att&ck/tactic 关键词 → 返回 MITRE 分析模板"""
    for keyword in ["mitre", "att&ck", "tactic"]:
        payload = {
            "model": "Qwen3-32B-Instruct",
            "messages": [{"role": "user", "content": f"请进行 {keyword} 分析"}],
        }
        resp = await client.post("/v1/chat/completions", json=payload)
        content = resp.json()["choices"][0]["message"]["content"]
        parsed = extract_json_from_content(content)

        assert "apt_correlation" in parsed["mitre_mapping"], f"keyword={keyword} 未路由到 MITRE 模板"


@pytest.mark.asyncio
async def test_recommendation_routing(client):
    """含 recommendation/action 关键词 → 返回建议模板"""
    for keyword in ["recommendation", "action"]:
        payload = {
            "model": "Qwen3-32B-Instruct",
            "messages": [{"role": "user", "content": f"给出安全 {keyword} 建议"}],
        }
        resp = await client.post("/v1/chat/completions", json=payload)
        content = resp.json()["choices"][0]["message"]["content"]
        parsed = extract_json_from_content(content)

        assert "compliance_mapping" in parsed, f"keyword={keyword} 未路由到建议模板"


@pytest.mark.asyncio
async def test_default_routing(client):
    """无特殊关键词 → 返回根因分析模板"""
    payload = {
        "model": "Qwen3-32B-Instruct",
        "messages": [{"role": "user", "content": "这条告警是什么原因"}],
    }
    resp = await client.post("/v1/chat/completions", json=payload)
    content = resp.json()["choices"][0]["message"]["content"]
    parsed = extract_json_from_content(content)

    assert "root_cause_details" in parsed


@pytest.mark.asyncio
async def test_message_role_is_assistant(client):
    """响应消息的 role 必须是 assistant"""
    payload = {
        "model": "Qwen3-32B-Instruct",
        "messages": [{"role": "user", "content": "测试"}],
    }
    resp = await client.post("/v1/chat/completions", json=payload)
    choice = resp.json()["choices"][0]

    assert choice["message"]["role"] == "assistant"
    assert choice["finish_reason"] == "stop"


@pytest.mark.asyncio
async def test_empty_messages_returns_400(client):
    """空 messages 应返回 400"""
    payload = {"model": "Qwen3-32B-Instruct", "messages": []}
    resp = await client.post("/v1/chat/completions", json=payload)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_models_endpoint(client):
    """GET /v1/models 应返回模型列表"""
    resp = await client.get("/v1/models")
    assert resp.status_code == 200
    data = resp.json()
    assert data["object"] == "list"
    assert len(data["data"]) > 0
    assert data["data"][0]["id"] == "Qwen3-32B-Instruct"
