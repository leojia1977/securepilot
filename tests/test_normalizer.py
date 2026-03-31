"""
tests/test_normalizer.py
pytest tests for M05 normalizer, field_mappings, scorer
Coverage target: >= 85%
"""

import json
import time
from pathlib import Path

import pytest

from src.pipeline.field_mappings import FIELD_MAPPINGS, SOURCE_TYPE_MAP, KNOWN_SOURCE_SYSTEMS
from src.pipeline.scorer import calculate_risk_score
from src.pipeline.normalizer import normalize, normalize_batch, _normalize_timestamp, _detect_source_system

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ════════════════════════════════════════════════════════════════════════════
# field_mappings
# ════════════════════════════════════════════════════════════════════════════

class TestFieldMappings:
    def test_all_known_systems_have_mappings(self):
        for sys in KNOWN_SOURCE_SYSTEMS:
            assert sys in FIELD_MAPPINGS

    def test_source_type_map_covers_known_systems(self):
        for sys in KNOWN_SOURCE_SYSTEMS:
            assert sys in SOURCE_TYPE_MAP

    def test_snort_mapping_keys(self):
        m = FIELD_MAPPINGS["snort"]
        assert "src" in m and m["src"] == "src_ip"
        assert "dst" in m and m["dst"] == "dst_ip"
        assert "sport" in m and m["sport"] == "src_port"
        assert "dport" in m and m["dport"] == "dst_port"

    def test_zeek_nested_mapping(self):
        m = FIELD_MAPPINGS["zeek"]
        assert "id.orig_h" in m and m["id.orig_h"] == "src_ip"
        assert "id.resp_h" in m and m["id.resp_h"] == "dst_ip"
        assert "id.orig_p" in m and m["id.orig_p"] == "src_port"

    def test_firewall_mapping(self):
        m = FIELD_MAPPINGS["firewall"]
        assert m["source_ip"] == "src_ip"
        assert m["destination_ip"] == "dst_ip"

    def test_edr_mapping(self):
        m = FIELD_MAPPINGS["edr"]
        assert m["hostname"] == "hostname"


# ════════════════════════════════════════════════════════════════════════════
# scorer
# ════════════════════════════════════════════════════════════════════════════

class TestScorer:
    def test_base_score(self):
        score = calculate_risk_score(2, None, None, None, "generic alert")
        assert score == pytest.approx(3.0)

    def test_high_risk_port_445(self):
        score = calculate_risk_score(1, 445, None, None, "alert")
        # 1*1.5 + 2.0 = 3.5
        assert score == pytest.approx(3.5)

    def test_high_risk_port_3389(self):
        score = calculate_risk_score(1, 3389, None, None, "alert")
        assert score == pytest.approx(3.5)

    def test_high_risk_port_4444(self):
        score = calculate_risk_score(1, 4444, None, None, "alert")
        assert score == pytest.approx(3.5)

    def test_internal_movement(self):
        score = calculate_risk_score(1, None, "192.168.1.1", "10.0.0.2", "alert")
        # 1.5 + 1.5 = 3.0
        assert score == pytest.approx(3.0)

    def test_high_risk_keyword_mimikatz(self):
        score = calculate_risk_score(1, None, None, None, "Mimikatz Detected")
        # 1.5 + 2.5 = 4.0
        assert score == pytest.approx(4.0)

    def test_high_risk_keyword_lsass(self):
        score = calculate_risk_score(1, None, None, None, "LSASS Memory Dump")
        assert score == pytest.approx(4.0)

    def test_high_risk_keyword_ransomware(self):
        score = calculate_risk_score(2, None, None, None, "Ransomware Activity")
        # 3.0 + 2.5 = 5.5
        assert score == pytest.approx(5.5)

    def test_high_risk_keyword_lateral(self):
        score = calculate_risk_score(2, None, None, None, "Lateral Movement via SMB")
        assert score == pytest.approx(5.5)

    def test_medium_risk_keyword_scan(self):
        score = calculate_risk_score(1, None, None, None, "Port Scan Detected")
        # 1.5 + 1.0 = 2.5
        assert score == pytest.approx(2.5)

    def test_medium_risk_keyword_brute(self):
        score = calculate_risk_score(1, None, None, None, "Brute Force Login")
        assert score == pytest.approx(2.5)

    def test_max_capped_at_10(self):
        score = calculate_risk_score(5, 445, "192.168.1.1", "10.0.0.2", "lateral mimikatz ransomware")
        assert score == pytest.approx(10.0)

    def test_severity_5_base(self):
        score = calculate_risk_score(5, None, None, None, "alert")
        assert score == pytest.approx(7.5)

    def test_non_high_risk_port(self):
        score = calculate_risk_score(2, 80, None, None, "alert")
        assert score == pytest.approx(3.0)

    def test_one_internal_ip_no_movement_bonus(self):
        score = calculate_risk_score(1, None, "192.168.1.1", "8.8.8.8", "alert")
        assert score == pytest.approx(1.5)

    def test_external_src_internal_dst_no_bonus(self):
        score = calculate_risk_score(1, None, "203.0.113.1", "192.168.1.1", "alert")
        assert score == pytest.approx(1.5)


# ════════════════════════════════════════════════════════════════════════════
# normalizer — 核心功能
# ════════════════════════════════════════════════════════════════════════════

class TestNormalizerSchema:
    """输出 Schema 完整性测试"""

    REQUIRED_FIELDS = [
        "event_id", "timestamp", "source_type", "source_system",
        "severity", "risk_score", "src_ip", "dst_ip",
        "src_port", "dst_port", "protocol", "user", "hostname",
        "alert_name", "alert_description", "raw_payload",
    ]

    def _check_schema(self, result: dict):
        for field in self.REQUIRED_FIELDS:
            assert field in result, f"缺少字段: {field}"

    def test_snort_alert_schema(self):
        raw = {
            "source_system": "snort",
            "src": "10.0.0.5", "dst": "192.168.1.100",
            "sport": 54321, "dport": 445,
            "proto": "tcp",
            "msg": "SMB Exploit Attempt",
            "priority": 1,
            "timestamp": "2024-01-01T10:00:00Z",
        }
        result = normalize(raw)
        self._check_schema(result)
        assert result["src_ip"] == "10.0.0.5"
        assert result["dst_ip"] == "192.168.1.100"
        assert result["dst_port"] == 445
        assert result["protocol"] == "tcp"
        assert result["source_system"] == "snort"
        assert result["source_type"] == "network"

    def test_zeek_alert_schema(self):
        raw = {
            "source_system": "zeek",
            "id.orig_h": "10.1.1.5",
            "id.resp_h": "10.1.1.200",
            "id.orig_p": 12345,
            "id.resp_p": 3389,
            "proto": "tcp",
            "note": "RDP Lateral Movement",
            "ts": "2024-01-01T12:00:00Z",
        }
        result = normalize(raw)
        self._check_schema(result)
        assert result["src_ip"] == "10.1.1.5"
        assert result["dst_ip"] == "10.1.1.200"
        assert result["source_system"] == "zeek"

    def test_firewall_alert_schema(self):
        raw = {
            "source_system": "firewall",
            "source_ip": "172.16.5.1",
            "destination_ip": "172.16.10.50",
            "source_port": 9999,
            "destination_port": 22,
            "protocol": "tcp",
            "action": "SSH Brute Force Blocked",
            "timestamp": "2024-01-01T08:00:00Z",
        }
        result = normalize(raw)
        self._check_schema(result)
        assert result["src_ip"] == "172.16.5.1"
        assert result["dst_ip"] == "172.16.10.50"
        assert result["dst_port"] == 22
        assert result["source_type"] == "network"

    def test_edr_alert_schema(self):
        raw = {
            "source_system": "edr",
            "hostname": "WORKSTATION-001",
            "username": "john.doe",
            "process_name": "mimikatz.exe",
            "alert_name": "Credential Dumping via Mimikatz",
            "description": "Suspected credential theft",
            "timestamp": "2024-01-01T15:00:00Z",
        }
        result = normalize(raw)
        self._check_schema(result)
        assert result["hostname"] == "WORKSTATION-001"
        assert result["user"] == "john.doe"
        assert result["source_type"] == "endpoint"
        # process_name 必须在 raw_payload 中
        assert result["raw_payload"]["process_name"] == "mimikatz.exe"


class TestNormalizerSpecific:
    """具体行为测试"""

    def test_event_id_generated_when_missing(self):
        raw = {"source_system": "snort", "msg": "test", "src": "1.1.1.1", "dst": "2.2.2.2"}
        result = normalize(raw)
        assert result["event_id"]
        assert len(result["event_id"]) > 0

    def test_event_id_preserved(self):
        raw = {
            "source_system": "edr",
            "event_id": "fixed-uuid-1234",
            "alert_name": "test alert",
        }
        result = normalize(raw)
        assert result["event_id"] == "fixed-uuid-1234"

    def test_timestamp_utc_normalization(self):
        raw = {"source_system": "snort", "msg": "t", "timestamp": "2024-06-15T10:30:00Z"}
        result = normalize(raw)
        assert "2024-06-15" in result["timestamp"]
        assert "T" in result["timestamp"]

    def test_timestamp_unix(self):
        raw = {"source_system": "snort", "msg": "t", "timestamp": 1700000000}
        result = normalize(raw)
        assert "2023" in result["timestamp"]

    def test_severity_clamp_high(self):
        raw = {"source_system": "edr", "severity": 99, "alert_name": "test"}
        result = normalize(raw)
        assert result["severity"] == 5

    def test_severity_clamp_low(self):
        raw = {"source_system": "edr", "severity": -1, "alert_name": "test"}
        result = normalize(raw)
        assert result["severity"] == 1

    def test_raw_payload_preserved(self):
        raw = {
            "source_system": "edr",
            "unknown_field_xyz": "should_be_kept",
            "alert_name": "test",
        }
        result = normalize(raw)
        assert result["raw_payload"]["unknown_field_xyz"] == "should_be_kept"

    def test_risk_score_float(self):
        raw = {"source_system": "edr", "severity": 3, "alert_name": "test alert"}
        result = normalize(raw)
        assert isinstance(result["risk_score"], float)
        assert 0.0 <= result["risk_score"] <= 10.0

    def test_risk_score_high_for_lateral_445(self):
        raw = {
            "source_system": "snort",
            "src": "192.168.1.5", "dst": "192.168.1.100",
            "dport": 445,
            "msg": "Lateral Movement via SMB",
            "priority": 1,
        }
        result = normalize(raw)
        # 1.5 (sev=1) + 2.0 (port 445) + 1.5 (内网) + 2.5 (lateral) = 7.5
        assert result["risk_score"] == pytest.approx(7.5)

    def test_dst_port_is_int(self):
        raw = {"source_system": "snort", "dport": "8080", "msg": "test", "src": "1.1.1.1", "dst": "2.2.2.2"}
        result = normalize(raw)
        assert isinstance(result["dst_port"], int)
        assert result["dst_port"] == 8080

    def test_unknown_source_does_not_crash(self):
        raw = {"source_system": "unknown_source", "alert_name": "mystery alert"}
        result = normalize(raw)
        assert "event_id" in result
        assert result["alert_name"] == "mystery alert"

    def test_alert_description_fallback(self):
        raw = {"source_system": "snort", "msg": "Port Scan", "src": "1.1.1.1", "dst": "2.2.2.2"}
        result = normalize(raw)
        assert result["alert_description"] != ""


class TestSourceDetection:
    def test_detect_zeek(self):
        assert _detect_source_system({"id.orig_h": "10.0.0.1"}) == "zeek"

    def test_detect_snort(self):
        assert _detect_source_system({"gid": 1, "sid": 1000, "msg": "test", "src": "1.1.1.1"}) == "snort"

    def test_detect_edr(self):
        assert _detect_source_system({"process_name": "cmd.exe", "hostname": "PC01"}) == "edr"

    def test_detect_firewall(self):
        assert _detect_source_system({"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}) == "firewall"

    def test_explicit_source_system_wins(self):
        assert _detect_source_system({"source_system": "edr", "source_ip": "1.1.1.1"}) == "edr"


# ════════════════════════════════════════════════════════════════════════════
# normalize_batch
# ════════════════════════════════════════════════════════════════════════════

class TestNormalizeBatch:
    def test_batch_returns_all(self):
        raws = [
            {"source_system": "snort", "msg": "alert1", "src": "1.1.1.1", "dst": "2.2.2.2"},
            {"source_system": "edr",   "alert_name": "alert2", "hostname": "PC01"},
        ]
        results = normalize_batch(raws)
        assert len(results) == 2

    def test_batch_schema_complete(self):
        raws = [{"source_system": "firewall", "source_ip": "1.1.1.1",
                 "destination_ip": "2.2.2.2", "action": "blocked"}]
        results = normalize_batch(raws)
        assert "event_id" in results[0]
        assert "risk_score" in results[0]


# ════════════════════════════════════════════════════════════════════════════
# 合成样本库集成测试
# ════════════════════════════════════════════════════════════════════════════

class TestSyntheticAlerts:
    @pytest.fixture(scope="class")
    def samples(self):
        path = FIXTURES_DIR / "alerts_synthetic_30.json"
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def test_all_30_samples_load(self, samples):
        assert len(samples) == 30

    def test_zero_exceptions_on_all_samples(self, samples):
        """处理全部 30 条合成样本，不能抛出任何异常。"""
        results = normalize_batch(samples)
        assert len(results) == 30

    def test_schema_complete_on_all_samples(self, samples):
        required = [
            "event_id", "timestamp", "source_type", "source_system",
            "severity", "risk_score", "raw_payload",
            "alert_name", "alert_description",
        ]
        results = normalize_batch(samples)
        for i, result in enumerate(results):
            for field in required:
                assert field in result, f"样本 {i} 缺少字段: {field}"

    def test_risk_score_in_range(self, samples):
        results = normalize_batch(samples)
        for i, result in enumerate(results):
            assert 0.0 <= result["risk_score"] <= 10.0, \
                f"样本 {i} risk_score 越界: {result['risk_score']}"

    def test_severity_in_range(self, samples):
        results = normalize_batch(samples)
        for i, result in enumerate(results):
            assert 1 <= result["severity"] <= 5, \
                f"样本 {i} severity 越界: {result['severity']}"

    def test_raw_payload_not_empty(self, samples):
        results = normalize_batch(samples)
        for i, result in enumerate(results):
            assert isinstance(result["raw_payload"], dict), \
                f"样本 {i} raw_payload 不是 dict"
            assert len(result["raw_payload"]) > 0, \
                f"样本 {i} raw_payload 为空"

    def test_processing_speed(self, samples):
        """单条平均处理时间 < 5ms（规则评分约束）"""
        t0 = time.perf_counter()
        normalize_batch(samples)
        elapsed_ms = (time.perf_counter() - t0) / len(samples) * 1000
        assert elapsed_ms < 5.0, f"平均处理时间 {elapsed_ms:.2f}ms 超过 5ms 限制"
