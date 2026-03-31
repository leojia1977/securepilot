"""
tests/test_kafka_consumer.py
pytest tests for M02 Kafka 消费器
所有测试在 KAFKA_MOCK=true 环境下运行，不连接真实 Kafka。
"""

import asyncio
import importlib
import json
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── 强制 Mock 模式，避免任何网络连接 ────────────────────────────────────────
os.environ["KAFKA_MOCK"] = "true"

# 重新加载模块以确保环境变量生效
if "src.pipeline.kafka_consumer" in sys.modules:
    importlib.reload(sys.modules["src.pipeline.kafka_consumer"])

from src.pipeline.kafka_consumer import (
    KAFKA_TOPIC,
    _load_mock_samples,
    _process_and_filter,
    consume_batch,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ════════════════════════════════════════════════════════════════════════════
# 辅助
# ════════════════════════════════════════════════════════════════════════════

def run(coro):
    """同步运行异步函数。"""
    return asyncio.get_event_loop().run_until_complete(coro)


# ════════════════════════════════════════════════════════════════════════════
# Mock 样本加载
# ════════════════════════════════════════════════════════════════════════════

class TestMockSamples:
    def test_load_returns_list(self):
        samples = _load_mock_samples()
        assert isinstance(samples, list)

    def test_load_30_samples(self):
        samples = _load_mock_samples()
        assert len(samples) == 30

    def test_samples_have_required_fields(self):
        samples = _load_mock_samples()
        for s in samples:
            assert "alert_name" in s or "msg" in s

    def test_load_is_cached(self):
        """两次调用返回同一对象（缓存）。"""
        s1 = _load_mock_samples()
        s2 = _load_mock_samples()
        assert s1 is s2


# ════════════════════════════════════════════════════════════════════════════
# _process_and_filter
# ════════════════════════════════════════════════════════════════════════════

class TestProcessAndFilter:
    @pytest.fixture
    def samples(self):
        with open(FIXTURES_DIR / "alerts_synthetic_30.json", encoding="utf-8") as f:
            return json.load(f)

    def test_returns_list(self, samples):
        result = _process_and_filter(samples[:5], min_risk_score=0.0)
        assert isinstance(result, list)

    def test_all_events_have_unified_schema(self, samples):
        result = _process_and_filter(samples[:5], min_risk_score=0.0)
        for event in result:
            assert "event_id" in event
            assert "risk_score" in event
            assert "source_system" in event
            assert "raw_payload" in event

    def test_filter_removes_low_risk(self, samples):
        result = _process_and_filter(samples, min_risk_score=100.0)
        assert result == []

    def test_filter_keeps_high_risk(self, samples):
        result = _process_and_filter(samples, min_risk_score=0.0)
        assert len(result) == 30

    def test_filter_threshold_3_0(self, samples):
        result = _process_and_filter(samples, min_risk_score=3.0)
        for event in result:
            assert event["risk_score"] >= 3.0

    def test_empty_batch_returns_empty(self):
        result = _process_and_filter([], min_risk_score=3.0)
        assert result == []


# ════════════════════════════════════════════════════════════════════════════
# consume_batch — Mock 模式
# ════════════════════════════════════════════════════════════════════════════

class TestConsumeBatchMock:
    def test_returns_list(self):
        result = run(consume_batch())
        assert isinstance(result, list)

    def test_all_events_pass_default_filter(self):
        """默认 min_risk_score=3.0，返回的每条事件都应 >= 3.0。"""
        result = run(consume_batch(min_risk_score=3.0))
        for event in result:
            assert event["risk_score"] >= 3.0

    def test_event_schema_complete(self):
        result = run(consume_batch(min_risk_score=0.0))
        assert len(result) > 0
        required = [
            "event_id", "timestamp", "source_type", "source_system",
            "severity", "risk_score", "alert_name", "alert_description",
            "raw_payload",
        ]
        for event in result:
            for field in required:
                assert field in event, f"缺少字段: {field}"

    def test_batch_size_within_mock_range(self):
        """Mock 每批 5~15 条（未过滤前），max_records 默认 50 不限制。"""
        # 运行多次以提高统计置信度
        sizes_before_filter = []
        for _ in range(10):
            result = run(consume_batch(min_risk_score=0.0))
            sizes_before_filter.append(len(result))
        # 至少有一次在 5~15 范围内
        assert any(5 <= s <= 15 for s in sizes_before_filter)

    def test_max_records_respected(self):
        result = run(consume_batch(max_records=3, min_risk_score=0.0))
        assert len(result) <= 3

    def test_zero_risk_filter_returns_nothing(self):
        result = run(consume_batch(min_risk_score=999.0))
        assert result == []

    def test_no_network_call_in_mock_mode(self):
        """Mock 模式下不应走真实消费路径。"""
        mock_real = AsyncMock(return_value=[])
        with patch("src.pipeline.kafka_consumer._consume_real", mock_real):
            with patch("src.pipeline.kafka_consumer.KAFKA_MOCK", True):
                run(consume_batch())
        mock_real.assert_not_called()

    def test_multiple_calls_return_different_batches(self):
        """随机采样：多次调用结果不应完全相同（极低概率相同）。"""
        results = [
            frozenset(e["event_id"] for e in run(consume_batch(min_risk_score=0.0)))
            for _ in range(5)
        ]
        # 至少有两次结果不同
        assert len(set(results)) > 1

    def test_risk_score_is_float(self):
        result = run(consume_batch(min_risk_score=0.0))
        for event in result:
            assert isinstance(event["risk_score"], float)

    def test_topic_constant(self):
        assert KAFKA_TOPIC == "enriched.alerts"
