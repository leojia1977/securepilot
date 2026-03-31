"""
风险评分器：纯规则计算，不调用 LLM，单条 < 5ms。

评分规则：
  基础分 = severity × 1.5
  dst_port 在高危端口列表中          → +2.0
  src_ip 和 dst_ip 都是内网地址       → +1.5（内网横移）
  alert_name 含高危关键词             → +2.5
  alert_name 含中危关键词             → +1.0
  最终 min(10.0, 累计分)
"""

import re

# ── 规则配置区域（禁止硬编码到业务逻辑中）────────────────────────────────

# 高危目标端口（横向移动/远控/C2 常用）
HIGH_RISK_DST_PORTS: set[int] = {445, 3389, 22, 4444, 5985}

# 内网地址前缀
INTERNAL_PREFIXES: tuple[str, ...] = ("10.", "172.16.", "192.168.")

# alert_name 关键词 → 高危加分（+2.5）
HIGH_RISK_KEYWORDS: list[str] = ["lateral", "mimikatz", "lsass", "ransomware"]

# alert_name 关键词 → 中危加分（+1.0）
MEDIUM_RISK_KEYWORDS: list[str] = ["scan", "brute"]

# 各规则加分值
SCORE_HIGH_RISK_PORT    = 2.0
SCORE_INTERNAL_MOVEMENT = 1.5
SCORE_HIGH_RISK_KEYWORD = 2.5
SCORE_MEDIUM_RISK_KEYWORD = 1.0
SCORE_MAX               = 10.0


def _is_internal(ip: str | None) -> bool:
    """判断 IP 是否属于内网地址段。"""
    if not ip:
        return False
    return ip.startswith(INTERNAL_PREFIXES)


def calculate_risk_score(
    severity: int,
    dst_port: int | None,
    src_ip: str | None,
    dst_ip: str | None,
    alert_name: str,
) -> float:
    """
    计算风险评分（纯规则，无 LLM 调用）。

    Args:
        severity:   1~5 的整数严重等级
        dst_port:   目标端口，可为 None
        src_ip:     源 IP，可为 None
        dst_ip:     目标 IP，可为 None
        alert_name: 告警名称（用于关键词匹配）

    Returns:
        float: 0.0~10.0 的风险评分
    """
    score = severity * 1.5  # 基础分

    # 高危端口加分
    if dst_port is not None and dst_port in HIGH_RISK_DST_PORTS:
        score += SCORE_HIGH_RISK_PORT

    # 内网横移加分（src 和 dst 都是内网）
    if _is_internal(src_ip) and _is_internal(dst_ip):
        score += SCORE_INTERNAL_MOVEMENT

    # 告警名称高危关键词加分（不区分大小写）
    name_lower = alert_name.lower()
    if any(kw in name_lower for kw in HIGH_RISK_KEYWORDS):
        score += SCORE_HIGH_RISK_KEYWORD

    # 告警名称中危关键词加分
    if any(kw in name_lower for kw in MEDIUM_RISK_KEYWORDS):
        score += SCORE_MEDIUM_RISK_KEYWORD

    return min(SCORE_MAX, round(score, 2))
