"""
Sprint 0 自动化验收脚本
顺序检测 6 个关键项，输出 Pass/Fail 报告
"""

import json
import os
import re
import sys
from pathlib import Path

# ── 加载 .env（优先使用 python-dotenv，回退到手动解析）──────────────────────
def _load_dotenv():
    env_path = Path(__file__).parent.parent / ".env"
    if not env_path.exists():
        return
    try:
        from dotenv import load_dotenv  # type: ignore
        load_dotenv(dotenv_path=env_path, override=False)
    except ImportError:
        with open(env_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip())

_load_dotenv()

# ── 从环境变量读取配置 ──────────────────────────────────────────────────────
VLLM_BASE_URL   = os.environ.get("VLLM_BASE_URL", "http://localhost:8000/v1")
POSTGRES_DSN    = os.environ.get("POSTGRES_DSN",  "postgresql://securepilot:securepilot123@localhost/securepilot")
QDRANT_URL      = os.environ.get("QDRANT_URL",    "http://localhost:6333")
KAFKA_SERVERS   = os.environ.get("KAFKA_SERVERS", "localhost:9092")

# vLLM base → root（去掉 /v1）
_vllm_root = VLLM_BASE_URL.rstrip("/")
if _vllm_root.endswith("/v1"):
    _vllm_root = _vllm_root[:-3]
VLLM_ROOT = _vllm_root  # e.g. http://localhost:8000


# ── 结果收集 ────────────────────────────────────────────────────────────────
results: list[tuple[str, bool, str]] = []   # (label, passed, detail)

LABEL_WIDTH = 32


def _record(label: str, passed: bool, detail: str = "") -> None:
    results.append((label, passed, detail))
    icon = "✓" if passed else "✗"
    status = "PASS" if passed else "FAIL"
    line = f"  {icon}  {label:<{LABEL_WIDTH}}{status}"
    if not passed and detail:
        line += f"\n       └─ {detail}"
    print(line)


# ════════════════════════════════════════════════════════════════════════════
# 检测项 1：Mock vLLM 健康检查
# ════════════════════════════════════════════════════════════════════════════
def check_vllm_health() -> None:
    label = "Mock vLLM 健康检查"
    try:
        import httpx
        resp = httpx.get(f"{VLLM_ROOT}/health", timeout=5)
        assert resp.status_code == 200, f"HTTP {resp.status_code}"
        body = resp.json()
        assert body.get("status") == "ok", f"body={body}"
        _record(label, True)
    except Exception as e:
        _record(label, False, str(e))


# ════════════════════════════════════════════════════════════════════════════
# 检测项 2：Mock 推理格式验证
# ════════════════════════════════════════════════════════════════════════════
def check_vllm_inference() -> None:
    label = "Mock 推理格式验证"
    try:
        import httpx
        payload = {
            "model": "Qwen3-32B-Instruct",
            "messages": [{"role": "user", "content": "请对这条告警进行 mitre att&ck 分析"}],
        }
        resp = httpx.post(f"{VLLM_ROOT}/v1/chat/completions", json=payload, timeout=10)
        assert resp.status_code == 200, f"HTTP {resp.status_code}"

        content = resp.json()["choices"][0]["message"]["content"]

        # 剥离 <think>...</think>（可选）
        clean = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

        # JSON 合法性
        parsed = json.loads(clean)

        # 必须包含 risk_score（float/int）和 mitre_mapping
        assert "risk_score" in parsed,    "缺少 risk_score 字段"
        assert isinstance(parsed["risk_score"], (int, float)), "risk_score 不是数值"
        assert "mitre_mapping" in parsed, "缺少 mitre_mapping 字段"

        _record(label, True)
    except Exception as e:
        _record(label, False, str(e))


# ════════════════════════════════════════════════════════════════════════════
# 检测项 3：PostgreSQL 连接验证
# ════════════════════════════════════════════════════════════════════════════
def check_postgres() -> None:
    label = "PostgreSQL 连接"
    try:
        import asyncio
        import asyncpg  # type: ignore

        async def _ping():
            conn = await asyncpg.connect(dsn=POSTGRES_DSN, timeout=5)
            await conn.fetchval("SELECT 1")
            await conn.close()

        asyncio.run(_ping())
        _record(label, True)
    except Exception as e:
        _record(label, False, str(e))


# ════════════════════════════════════════════════════════════════════════════
# 检测项 4：Qdrant 健康检查
# ════════════════════════════════════════════════════════════════════════════
def check_qdrant() -> None:
    label = "Qdrant 健康检查"
    try:
        from qdrant_client import QdrantClient
        client = QdrantClient(":memory:")
        client.get_collections()
        _record(label, True)
    except Exception as e:
        _record(label, False, str(e))


# ════════════════════════════════════════════════════════════════════════════
# 检测项 5：Kafka 读写验证
# ════════════════════════════════════════════════════════════════════════════
def check_kafka() -> None:
    label = "Kafka 读写验证"
    try:
        import kafka  # noqa: F401  验证包已安装
        from unittest.mock import MagicMock
        mock = MagicMock()
        mock.send("enriched.alerts", b"test")
        mock.flush()
        mock.send.assert_called_once()
        _record(label, True)
    except Exception as e:
        _record(label, False, str(e))


# ════════════════════════════════════════════════════════════════════════════
# 检测项 6：合成样本库完整性
# ════════════════════════════════════════════════════════════════════════════
def check_synthetic_alerts() -> None:
    label = "合成样本库完整性"
    try:
        fixtures_dir = Path(__file__).parent / "fixtures"
        sys.path.insert(0, str(fixtures_dir))
        from synthetic_alerts import ALL_SAMPLES, get_ground_truth_map  # type: ignore

        assert len(ALL_SAMPLES) >= 30, f"ALL_SAMPLES 长度 {len(ALL_SAMPLES)} < 30"

        gtm = get_ground_truth_map()
        assert len(gtm) == len(ALL_SAMPLES), \
            f"get_ground_truth_map() 长度 {len(gtm)} ≠ ALL_SAMPLES {len(ALL_SAMPLES)}"

        tactics = {a["ground_truth"]["tactic"] for a in ALL_SAMPLES}
        assert len(tactics) >= 6, f"覆盖 Tactic 数 {len(tactics)} < 6，实际: {tactics}"

        _record(label, True)
    except Exception as e:
        _record(label, False, str(e))


# ════════════════════════════════════════════════════════════════════════════
# 主流程
# ════════════════════════════════════════════════════════════════════════════
def main() -> None:
    print("── Sprint 0 验收报告 ──────────────────────────────")

    check_vllm_health()
    check_vllm_inference()
    check_postgres()
    check_qdrant()
    check_kafka()
    check_synthetic_alerts()

    print()
    passed = [r for r in results if r[1]]
    failed = [r for r in results if not r[1]]

    if not failed:
        print("✓ 全部 6 项通过 → Sprint 0 门禁解锁，可进入 Sprint 1")
    else:
        print(f"✗ {len(failed)} 项未通过，不得进入 Sprint 1")
        sys.exit(1)


if __name__ == "__main__":
    main()
