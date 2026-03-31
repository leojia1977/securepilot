"""
字段映射表：各来源原始字段 → SecuPilot 统一 Schema 字段名
每个来源映射为 {原始字段: 统一字段} 的字典。
嵌套字段用点号表示，例如 "id.orig_h"。
"""

# 各来源到统一 Schema 的字段映射
FIELD_MAPPINGS: dict[str, dict[str, str]] = {
    "snort": {
        "src":   "src_ip",
        "dst":   "dst_ip",
        "sport": "src_port",
        "dport": "dst_port",
        "proto": "protocol",
        "msg":   "alert_name",
    },
    "zeek": {
        "id.orig_h": "src_ip",
        "id.resp_h": "dst_ip",
        "id.orig_p": "src_port",
        "id.resp_p": "dst_port",
        "proto":     "protocol",
        "note":      "alert_name",
        "uid":       "event_id",
    },
    "firewall": {
        "source_ip":      "src_ip",
        "destination_ip": "dst_ip",
        "source_port":    "src_port",
        "destination_port": "dst_port",
        "protocol":       "protocol",
        "action":         "alert_name",
        "user":           "user",
        "hostname":       "hostname",
    },
    "edr": {
        "hostname":     "hostname",
        "username":     "user",
        "src_ip":       "src_ip",
        "dst_ip":       "dst_ip",
        "src_port":     "src_port",
        "dst_port":     "dst_port",
        "protocol":     "protocol",
        "alert_name":   "alert_name",
        "description":  "alert_description",
        # process_name 不映射到顶层，保留在 raw_payload
    },
}

# 来源系统 → source_type 映射
SOURCE_TYPE_MAP: dict[str, str] = {
    "snort":    "network",
    "zeek":     "network",
    "firewall": "network",
    "edr":      "endpoint",
}

# 已知来源系统列表
KNOWN_SOURCE_SYSTEMS: list[str] = list(FIELD_MAPPINGS.keys())
