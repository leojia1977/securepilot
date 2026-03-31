"""
告警归一化器（M05）

将来自 Snort / Zeek / 防火墙 / EDR 等多来源的原始告警
统一转换为 SecuPilot 内部 Schema，并完成初始风险预评分。
"""

import uuid
from datetime import datetime, timezone
from typing import Any

from src.pipeline.field_mappings import (
    FIELD_MAPPINGS,
    KNOWN_SOURCE_SYSTEMS,
    SOURCE_TYPE_MAP,
)
from src.pipeline.scorer import calculate_risk_score


# ── 统一 Schema 默认值 ───────────────────────────────────────────────────────

_SCHEMA_DEFAULTS: dict[str, Any] = {
    "event_id":          None,
    "timestamp":         None,
    "source_type":       "network",
    "source_system":     "unknown",
    "severity":          1,
    "risk_score":        0.0,
    "src_ip":            None,
    "dst_ip":            None,
    "src_port":          None,
    "dst_port":          None,
    "protocol":          None,
    "user":              None,
    "hostname":          None,
    "alert_name":        "",
    "alert_description": "",
    "raw_payload":       {},
}


def _get_nested(data: dict, dotted_key: str) -> Any:
    """按点号路径读取嵌套字典值，优先尝试平铺键，找不到再按嵌套路径解析。"""
    # 优先：键名本身就含点号（Zeek 平铺日志格式，如 "id.orig_h"）
    if dotted_key in data:
        return data[dotted_key]
    # 回退：递归按点号路径解析嵌套结构
    keys = dotted_key.split(".")
    cur: Any = data
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def _normalize_timestamp(raw: Any) -> str:
    """
    将各种时间格式统一转为 UTC ISO8601 字符串。
    无法解析时返回当前 UTC 时间。
    """
    if isinstance(raw, (int, float)):
        # Unix 时间戳
        dt = datetime.fromtimestamp(raw, tz=timezone.utc)
        return dt.isoformat()
    if isinstance(raw, str):
        raw = raw.strip()
        # 已有 Z 后缀或 +00:00 → 直接返回标准格式
        for fmt in (
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(raw, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc).isoformat()
            except ValueError:
                continue
    # 回退：当前 UTC
    return datetime.now(tz=timezone.utc).isoformat()


def _normalize_severity(raw: Any, source_system: str) -> int:
    """
    将各来源的严重等级归一化为 1~5 整数。
    直接 clamp 到 1~5，不做来源特定的反向映射，
    避免对缺失字段的默认值误判。
    """
    if raw is None:
        return 1
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return 1
    return max(1, min(5, val))


def _detect_source_system(raw: dict) -> str:
    """
    根据原始告警的特征字段自动检测来源系统。
    优先使用 source_system / _source / type 等显式字段。
    """
    for key in ("source_system", "_source", "source", "type", "sensor"):
        val = raw.get(key, "")
        if isinstance(val, str) and val.lower() in KNOWN_SOURCE_SYSTEMS:
            return val.lower()

    # 启发式检测：Zeek 日志通常含 id.orig_h
    if "id.orig_h" in raw or ("id" in raw and isinstance(raw.get("id"), dict)):
        return "zeek"
    # Snort 日志常含 msg / gid / sid
    if "gid" in raw or "sid" in raw or ("msg" in raw and "src" in raw):
        return "snort"
    # EDR 日志常含 process_name / hostname
    if "process_name" in raw or ("hostname" in raw and "alert_name" in raw):
        return "edr"
    # 防火墙日志常含 source_ip / destination_ip
    if "source_ip" in raw or "destination_ip" in raw:
        return "firewall"

    return "unknown"


def normalize(raw: dict) -> dict:
    """
    将单条原始告警转换为 SecuPilot 统一 Schema。

    Args:
        raw: 任意来源的原始告警字典

    Returns:
        符合统一 Schema 的标准化告警字典
    """
    # 完整保留原始字段，放入 raw_payload
    raw_payload: dict = dict(raw)

    # 检测来源
    source_system = _detect_source_system(raw)
    mapping = FIELD_MAPPINGS.get(source_system, {})

    # 初始化输出（从默认值出发）
    out: dict[str, Any] = dict(_SCHEMA_DEFAULTS)
    out["raw_payload"] = raw_payload
    out["source_system"] = source_system
    out["source_type"] = SOURCE_TYPE_MAP.get(source_system, "network")

    # 按映射表提取字段（只填充尚未赋值的字段）
    for raw_key, schema_key in mapping.items():
        val = _get_nested(raw, raw_key)
        if val is not None and not out.get(schema_key):
            out[schema_key] = val

    # 直接映射统一 Schema 字段（已在 raw 中符合规范的告警，如合成样本）
    for field in (
        "event_id", "timestamp", "source_type", "source_system",
        "severity", "risk_score", "src_ip", "dst_ip",
        "src_port", "dst_port", "protocol", "user", "hostname",
        "alert_name", "alert_description",
    ):
        if field in raw and out.get(field) in (None, "", 0, 0.0, _SCHEMA_DEFAULTS.get(field)):
            out[field] = raw[field]

    # 保证 source_system 不被 raw 中的同名字段覆盖为 None
    if out["source_system"] in (None, "unknown") and source_system != "unknown":
        out["source_system"] = source_system

    # event_id：缺失则生成 UUID
    if not out["event_id"]:
        out["event_id"] = str(uuid.uuid4())

    # timestamp：统一转为 UTC ISO8601
    out["timestamp"] = _normalize_timestamp(out.get("timestamp"))

    # severity：归一化到 1~5
    out["severity"] = _normalize_severity(out.get("severity"), source_system)

    # alert_description 回退
    if not out["alert_description"]:
        out["alert_description"] = out.get("alert_name", "")

    # dst_port / src_port：确保 int 或 None
    for port_field in ("src_port", "dst_port"):
        pval = out.get(port_field)
        if pval is not None:
            try:
                out[port_field] = int(pval)
            except (TypeError, ValueError):
                out[port_field] = None

    # risk_score：用规则重新计算（覆盖原始值）
    out["risk_score"] = calculate_risk_score(
        severity=out["severity"],
        dst_port=out.get("dst_port"),
        src_ip=out.get("src_ip"),
        dst_ip=out.get("dst_ip"),
        alert_name=out.get("alert_name", ""),
    )

    return out


def normalize_batch(raws: list[dict]) -> list[dict]:
    """批量归一化，任意单条异常不影响其他条目。"""
    results = []
    for raw in raws:
        try:
            results.append(normalize(raw))
        except Exception as exc:  # noqa: BLE001
            # 保留原始数据，标记错误，不丢弃
            results.append({
                **_SCHEMA_DEFAULTS,
                "event_id":    str(uuid.uuid4()),
                "timestamp":   datetime.now(tz=timezone.utc).isoformat(),
                "raw_payload": raw,
                "alert_name":  "normalization_error",
                "alert_description": str(exc),
            })
    return results
