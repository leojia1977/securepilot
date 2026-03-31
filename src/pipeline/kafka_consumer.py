"""
Kafka 消费器（M02）

从 Topic "enriched.alerts" 批量消费告警，经归一化器处理后，
过滤低优先级事件，返回可供 LangGraph 图直接使用的事件列表。

环境变量：
  KAFKA_BOOTSTRAP_SERVERS  Kafka 地址，默认 "localhost:9092"
  KAFKA_MOCK               设为 "true" 时启用 Mock 模式，不连接真实 Kafka
"""

import json
import os
import random
from pathlib import Path
from typing import List

from src.pipeline.normalizer import normalize_batch

# ── 配置 ─────────────────────────────────────────────────────────────────────

KAFKA_BOOTSTRAP_SERVERS: str = os.environ.get(
    "KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"
)
KAFKA_TOPIC: str = "enriched.alerts"
KAFKA_MOCK: bool = os.environ.get("KAFKA_MOCK", "").lower() == "true"

_FIXTURES_PATH = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "alerts_synthetic_30.json"

# Mock 模式每批返回条数范围
_MOCK_BATCH_MIN = 5
_MOCK_BATCH_MAX = 15


# ── Mock 数据加载（延迟加载，避免非 Mock 环境开销）────────────────────────────

_mock_samples: list[dict] | None = None


def _load_mock_samples() -> list[dict]:
    global _mock_samples
    if _mock_samples is None:
        with open(_FIXTURES_PATH, encoding="utf-8") as f:
            _mock_samples = json.load(f)
    return _mock_samples


# ── 主接口 ────────────────────────────────────────────────────────────────────

async def consume_batch(
    max_records: int = 50,
    timeout_ms: int = 5000,
    min_risk_score: float = 3.0,
) -> List[dict]:
    """
    从 Kafka 消费一批告警，经归一化处理后返回高风险事件。

    Args:
        max_records:    最多消费条数
        timeout_ms:     超时毫秒（仅真实模式有效）
        min_risk_score: 风险分过滤阈值，低于此值的事件不返回

    Returns:
        经过归一化、过滤后的事件列表；超时或无消息返回空列表。
    """
    if KAFKA_MOCK:
        return await _consume_mock(max_records, min_risk_score)
    return await _consume_real(max_records, timeout_ms, min_risk_score)


# ── Mock 模式 ─────────────────────────────────────────────────────────────────

async def _consume_mock(max_records: int, min_risk_score: float) -> List[dict]:
    """
    Mock 模式：从合成样本文件随机取 5~15 条，经归一化处理后过滤返回。
    不连接任何网络。
    """
    samples = _load_mock_samples()
    batch_size = min(
        max_records,
        random.randint(_MOCK_BATCH_MIN, _MOCK_BATCH_MAX),
    )
    raw_batch = random.sample(samples, min(batch_size, len(samples)))
    return _process_and_filter(raw_batch, min_risk_score)


# ── 真实 Kafka 模式 ───────────────────────────────────────────────────────────

async def _consume_real(
    max_records: int, timeout_ms: int, min_risk_score: float
) -> List[dict]:
    """
    真实 Kafka 消费：同步 KafkaConsumer 封装在 async 接口内。
    超时未拿到消息返回空列表，不抛出异常。
    """
    try:
        from kafka import KafkaConsumer  # type: ignore
        from kafka.errors import KafkaError  # type: ignore

        consumer = KafkaConsumer(
            KAFKA_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            auto_offset_reset="latest",
            enable_auto_commit=True,
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            consumer_timeout_ms=timeout_ms,
            max_poll_records=max_records,
        )

        raw_batch: list[dict] = []
        try:
            for msg in consumer:
                raw_batch.append(msg.value)
                if len(raw_batch) >= max_records:
                    break
        except StopIteration:
            pass  # consumer_timeout_ms 超时正常退出
        finally:
            consumer.close()

        return _process_and_filter(raw_batch, min_risk_score)

    except KafkaError:
        return []
    except Exception:  # noqa: BLE001
        return []


# ── 内部工具 ──────────────────────────────────────────────────────────────────

def _process_and_filter(raw_batch: list[dict], min_risk_score: float) -> List[dict]:
    """归一化批量告警并过滤低风险事件。"""
    normalized = normalize_batch(raw_batch)
    return [e for e in normalized if e.get("risk_score", 0.0) >= min_risk_score]
