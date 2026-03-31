"""
响应模板模块 - 按场景分类的 Mock 响应内容
模拟 Qwen3-32B-Instruct Thinking Mode 格式
"""

import json
import re

KILL_CHAIN_TEMPLATE = """<think>
分析告警数据中的攻击链条信息...
识别攻击阶段：侦察 → 初始访问 → 执行 → 持久化 → 横向移动 → 数据渗漏
关联多条告警事件，构建完整杀伤链时间线...
评估威胁严重程度：高危
</think>
{
  "risk_score": 9.2,
  "is_true_positive": true,
  "kill_chain_timeline": [
    {
      "phase": "Reconnaissance",
      "timestamp": "2024-01-15T08:12:00Z",
      "event": "端口扫描活动，目标 192.168.1.0/24",
      "mitre_technique": "T1595.002"
    },
    {
      "phase": "Initial Access",
      "timestamp": "2024-01-15T08:45:00Z",
      "event": "利用 CVE-2024-1234 漏洞成功入侵 Web 服务器",
      "mitre_technique": "T1190"
    },
    {
      "phase": "Execution",
      "timestamp": "2024-01-15T09:01:00Z",
      "event": "执行恶意 PowerShell 脚本，建立反向 Shell",
      "mitre_technique": "T1059.001"
    },
    {
      "phase": "Persistence",
      "timestamp": "2024-01-15T09:15:00Z",
      "event": "创建计划任务实现持久化访问",
      "mitre_technique": "T1053.005"
    },
    {
      "phase": "Lateral Movement",
      "timestamp": "2024-01-15T10:30:00Z",
      "event": "使用 Pass-the-Hash 横向移动至域控服务器",
      "mitre_technique": "T1550.002"
    },
    {
      "phase": "Exfiltration",
      "timestamp": "2024-01-15T11:45:00Z",
      "event": "通过 HTTPS 隧道向外部 C2 服务器传输敏感数据",
      "mitre_technique": "T1048.002"
    }
  ],
  "mitre_mapping": {
    "tactics": ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Lateral Movement", "Exfiltration"],
    "techniques": ["T1595.002", "T1190", "T1059.001", "T1053.005", "T1550.002", "T1048.002"]
  },
  "root_cause": "Web 应用存在未修补的高危漏洞（CVE-2024-1234），攻击者利用该漏洞完成完整攻击链",
  "recommendations": [
    "立即隔离受影响的 Web 服务器（192.168.1.100）",
    "紧急修补 CVE-2024-1234 漏洞",
    "重置所有受影响账户凭据",
    "审查并清理所有计划任务和持久化机制",
    "在网络边界部署出站流量过滤规则",
    "开展全面的威胁狩猎活动"
  ],
  "affected_assets": ["192.168.1.100", "DC01.corp.local"],
  "confidence": 0.95
}"""

MITRE_TEMPLATE = """<think>
对告警进行 MITRE ATT&CK 框架映射分析...
识别战术目标和使用的具体技术手段...
评估攻击者的技术能力水平（TTP 复杂度）...
与已知 APT 组织战术库进行比对...
</think>
{
  "risk_score": 8.5,
  "is_true_positive": true,
  "mitre_mapping": {
    "tactics": [
      {
        "id": "TA0001",
        "name": "Initial Access",
        "techniques": [
          {"id": "T1566.001", "name": "Spearphishing Attachment", "confidence": 0.88}
        ]
      },
      {
        "id": "TA0002",
        "name": "Execution",
        "techniques": [
          {"id": "T1059.003", "name": "Windows Command Shell", "confidence": 0.92},
          {"id": "T1204.002", "name": "Malicious File", "confidence": 0.85}
        ]
      },
      {
        "id": "TA0003",
        "name": "Persistence",
        "techniques": [
          {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder", "confidence": 0.90}
        ]
      },
      {
        "id": "TA0005",
        "name": "Defense Evasion",
        "techniques": [
          {"id": "T1027", "name": "Obfuscated Files or Information", "confidence": 0.87},
          {"id": "T1055.001", "name": "DLL Injection", "confidence": 0.82}
        ]
      },
      {
        "id": "TA0010",
        "name": "Exfiltration",
        "techniques": [
          {"id": "T1041", "name": "Exfiltration Over C2 Channel", "confidence": 0.89}
        ]
      }
    ],
    "apt_correlation": {
      "group": "APT29 (Cozy Bear)",
      "similarity_score": 0.73,
      "known_campaigns": ["SolarWinds供应链攻击", "微软邮件系统入侵"]
    }
  },
  "root_cause": "鱼叉式网络钓鱼邮件携带恶意附件，诱导用户执行，触发后续攻击链",
  "recommendations": [
    "加强员工安全意识培训，重点关注钓鱼邮件识别",
    "部署高级邮件安全网关（沙箱分析）",
    "启用应用程序白名单控制",
    "加强端点 EDR 监控，重点关注 T1059 相关行为",
    "实施网络流量深度包检测",
    "审查并强化 PowerShell 执行策略"
  ],
  "threat_actor_profile": "高级持续性威胁（APT），具备丰富的攻击经验和资源支持",
  "confidence": 0.88
}"""

RECOMMENDATION_TEMPLATE = """<think>
基于当前威胁态势生成安全加固建议...
评估现有安全控制措施的有效性...
结合行业最佳实践和合规要求制定改进方案...
优先级排序：紧急 → 高 → 中 → 低
</think>
{
  "risk_score": 6.5,
  "is_true_positive": true,
  "mitre_mapping": {
    "tactics": ["Defense Evasion", "Credential Access"],
    "techniques": ["T1078", "T1110.003"]
  },
  "root_cause": "账户安全策略存在缺陷，弱密码策略和缺乏多因素认证导致凭据暴力破解风险",
  "recommendations": [
    {
      "priority": "紧急",
      "action": "立即为所有特权账户启用多因素认证（MFA）",
      "effort": "低",
      "impact": "极高",
      "deadline": "24小时内"
    },
    {
      "priority": "高",
      "action": "强制重置所有使用弱密码的账户",
      "effort": "中",
      "impact": "高",
      "deadline": "48小时内"
    },
    {
      "priority": "高",
      "action": "实施账户锁定策略：5次失败登录后锁定30分钟",
      "effort": "低",
      "impact": "高",
      "deadline": "72小时内"
    },
    {
      "priority": "中",
      "action": "部署特权访问管理（PAM）解决方案",
      "effort": "高",
      "impact": "极高",
      "deadline": "2周内"
    },
    {
      "priority": "中",
      "action": "启用登录异常检测和实时告警",
      "effort": "中",
      "impact": "中",
      "deadline": "1周内"
    },
    {
      "priority": "低",
      "action": "定期开展渗透测试和红队演练",
      "effort": "高",
      "impact": "高",
      "deadline": "季度性"
    }
  ],
  "compliance_mapping": {
    "ISO27001": ["A.9.4.3", "A.9.3.1"],
    "NIST_CSF": ["PR.AC-1", "PR.AC-3", "DE.CM-1"]
  },
  "confidence": 0.91
}"""

ROOT_CAUSE_TEMPLATE = """<think>
分析告警数据中的异常行为模式...
识别关键字段：源 IP、目标资产、攻击手法、时间序列...
关联历史威胁情报库进行比对验证...
综合评估：确认为真实威胁事件
</think>
{
  "risk_score": 7.8,
  "is_true_positive": true,
  "mitre_mapping": {
    "tactics": ["Discovery", "Collection"],
    "techniques": ["T1083", "T1005", "T1074.001"]
  },
  "root_cause": "内部主机遭受恶意软件感染，攻击者通过文件系统枚举收集敏感数据并暂存于本地，准备后续渗漏",
  "root_cause_details": {
    "trigger_event": "异常的大规模文件访问行为（单小时访问文件数超过正常基线300%）",
    "affected_process": "svchost.exe（PID: 4821）注入可疑 DLL",
    "data_at_risk": "财务报表、客户数据库备份、源代码仓库",
    "attack_vector": "通过受感染的 USB 设备引入恶意软件",
    "dwell_time_estimate": "约 72 小时"
  },
  "evidence": [
    "EDR 日志：异常进程树 explorer.exe → cmd.exe → powershell.exe",
    "网络日志：与已知 C2 IP（45.33.32.156）的周期性通信",
    "文件系统：在 %TEMP% 目录发现混淆的 PowerShell 脚本",
    "注册表：发现新增的 Run Key 持久化条目"
  ],
  "recommendations": [
    "立即隔离受感染主机，防止横向扩散",
    "对受影响系统进行全面取证镜像",
    "追踪并清除所有持久化机制",
    "扫描全网同类 IoC 指标（文件哈希、C2 IP、域名）",
    "审查 USB 设备使用策略并部署端点控制",
    "加强数据分类和访问控制策略"
  ],
  "ioc": {
    "ip": ["45.33.32.156", "198.51.100.42"],
    "domain": ["update-service.malicious.com"],
    "file_hash": ["sha256:a1b2c3d4e5f6..."],
    "registry_key": ["HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\SecurityUpdate"]
  },
  "confidence": 0.89
}"""

# ── 按 ATT&CK 技术的具体模板 ─────────────────────────────────────────────────

T1021_002_TEMPLATE = """<think>
检测到 SMB 横向移动特征：异常管理共享访问，匹配 T1021.002。
</think>
{
  "risk_score": 8.2,
  "is_true_positive": true,
  "confidence": "high",
  "root_cause": "检测到 SMB 横向移动行为",
  "mitre_mapping": [{"tactic": "LateralMovement", "technique_id": "T1021.002",
    "technique_name": "SMB/Windows Admin Shares", "evidence": "异常 SMB 管理共享访问",
    "confidence": 0.9}],
  "affected_assets": [],
  "recommendations": []
}"""

T1059_001_TEMPLATE = """<think>
检测到混淆 PowerShell 执行，匹配 T1059.001。
</think>
{
  "risk_score": 7.5,
  "is_true_positive": true,
  "confidence": "high",
  "root_cause": "混淆 PowerShell 脚本执行",
  "mitre_mapping": [{"tactic": "Execution", "technique_id": "T1059.001",
    "technique_name": "PowerShell", "evidence": "混淆PowerShell执行",
    "confidence": 0.88}],
  "affected_assets": [],
  "recommendations": []
}"""

T1547_001_TEMPLATE = """<think>
检测到注册表 Run 键写入，持久化行为，匹配 T1547.001。
</think>
{
  "risk_score": 7.0,
  "is_true_positive": true,
  "confidence": "high",
  "root_cause": "通过注册表 Run 键实现持久化",
  "mitre_mapping": [{"tactic": "Persistence", "technique_id": "T1547.001",
    "technique_name": "Registry Run Keys / Startup Folder", "evidence": "注册表Run键写入",
    "confidence": 0.90}],
  "affected_assets": [],
  "recommendations": []
}"""

T1003_001_TEMPLATE = """<think>
检测到 LSASS 内存访问，凭据窃取行为，匹配 T1003.001。
</think>
{
  "risk_score": 9.0,
  "is_true_positive": true,
  "confidence": "high",
  "root_cause": "攻击者读取 LSASS 内存窃取凭据",
  "mitre_mapping": [{"tactic": "CredentialAccess", "technique_id": "T1003.001",
    "technique_name": "LSASS Memory", "evidence": "LSASS内存读取",
    "confidence": 0.92}],
  "affected_assets": [],
  "recommendations": []
}"""

T1071_001_TEMPLATE = """<think>
检测到 C2 信标通信或异常出站连接，匹配 T1071.001。
</think>
{
  "risk_score": 8.0,
  "is_true_positive": true,
  "confidence": "high",
  "root_cause": "主机与 C2 服务器建立信标通信",
  "mitre_mapping": [{"tactic": "CommandAndControl", "technique_id": "T1071.001",
    "technique_name": "Web Protocols", "evidence": "C2信标通信",
    "confidence": 0.87}],
  "affected_assets": [],
  "recommendations": []
}"""

T1046_TEMPLATE = """<think>
检测到内网端口扫描行为，匹配 T1046。
</think>
{
  "risk_score": 6.5,
  "is_true_positive": true,
  "confidence": "medium",
  "root_cause": "内网主机发起大规模端口扫描",
  "mitre_mapping": [{"tactic": "Discovery", "technique_id": "T1046",
    "technique_name": "Network Service Discovery", "evidence": "内网端口扫描",
    "confidence": 0.85}],
  "affected_assets": [],
  "recommendations": []
}"""

T1486_TEMPLATE = """<think>
检测到大量文件加密行为，勒索软件特征，匹配 T1486。
</think>
{
  "risk_score": 9.5,
  "is_true_positive": true,
  "confidence": "high",
  "root_cause": "勒索软件批量加密用户文件",
  "mitre_mapping": [{"tactic": "Impact", "technique_id": "T1486",
    "technique_name": "Data Encrypted for Impact", "evidence": "大量文件加密",
    "confidence": 0.95}],
  "affected_assets": [],
  "recommendations": []
}"""

T1195_002_TEMPLATE = """<think>
检测到软件供应链攻击，恶意包注入，匹配 T1195.002。
</think>
{
  "risk_score": 8.8,
  "is_true_positive": true,
  "confidence": "high",
  "root_cause": "构建流水线拉取含恶意代码的第三方包",
  "mitre_mapping": [{"tactic": "InitialAccess", "technique_id": "T1195.002",
    "technique_name": "Compromise Software Supply Chain", "evidence": "恶意软件包注入",
    "confidence": 0.90}],
  "affected_assets": [],
  "recommendations": []
}"""

T1048_002_TEMPLATE = """<think>
检测到大量数据外传行为，匹配 T1048.002。
</think>
{
  "risk_score": 8.5,
  "is_true_positive": true,
  "confidence": "high",
  "root_cause": "通过加密非 C2 协议大规模外传数据",
  "mitre_mapping": [{"tactic": "Exfiltration", "technique_id": "T1048.002",
    "technique_name": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
    "evidence": "大量数据外传", "confidence": 0.88}],
  "affected_assets": [],
  "recommendations": []
}"""

T1566_001_TEMPLATE = """<think>
检测到鱼叉式钓鱼邮件或恶意宏文档，匹配 T1566.001。
</think>
{
  "risk_score": 7.8,
  "is_true_positive": true,
  "confidence": "high",
  "root_cause": "鱼叉式钓鱼邮件携带恶意宏文档诱导用户执行",
  "mitre_mapping": [{"tactic": "InitialAccess", "technique_id": "T1566.001",
    "technique_name": "Spearphishing Attachment", "evidence": "恶意宏文档附件",
    "confidence": 0.88}],
  "affected_assets": [],
  "recommendations": []
}"""


# ── 路由函数 ──────────────────────────────────────────────────────────────────

def get_template(user_message: str) -> str:
    """原有路由函数，保持向后兼容。"""
    msg_lower = user_message.lower()

    if any(kw in msg_lower for kw in ["kill", "chain", "timeline"]):
        return KILL_CHAIN_TEMPLATE
    elif any(kw in msg_lower for kw in ["mitre", "att&ck", "tactic"]):
        return MITRE_TEMPLATE
    elif any(kw in msg_lower for kw in ["recommendation", "action"]):
        return RECOMMENDATION_TEMPLATE
    else:
        return ROOT_CAUSE_TEMPLATE


# ── 精准映射表 ─────────────────────────────────────────────────────────────────

ALERT_NAME_TO_TECHNIQUE: dict[str, tuple[str, str, str]] = {
    # ── 精准优先条目（放最前，防止被下方通用关键词误命中）──────────────────────
    # T1106: "native api credential harvesting" → 须在 "credential"→T1003.001 之前
    "native api credential":    ("T1106",     "Execution",        "Native API"),
    # T1553.004: "self-signed certificate c2 communication" → 须在 "c2 communication"→T1071.001 之前
    "self-signed certificate":  ("T1553.004", "DefenseEvasion",   "Code Signing"),
    # T1041: "continuous c2 channel exfiltration" → 须在 "exfiltration"→T1048.002 之前
    "c2 channel exfiltration":  ("T1041",     "Exfiltration",     "Exfiltration Over C2 Channel"),
    "continuous c2 channel":    ("T1041",     "Exfiltration",     "Exfiltration Over C2 Channel"),
    # T1021.002: "ransomware payload distribution via smb" → 须在 "ransomware"→T1486 之前
    "ransomware payload":       ("T1021.002", "LateralMovement",  "SMB/Windows Admin Shares"),
    # T1491.001: "ransom note file created on multiple hosts" → 无现有关键词匹配
    "ransom note":              ("T1491.001", "Impact",           "Internal Defacement"),
    # T1550.002: "pass-the-hash attack detected" → 原 "pass the hash" 含空格不匹配连字符
    "pass-the-hash":            ("T1550.002", "LateralMovement",  "Pass the Hash"),
    # T1005: "mass data collection before encryption" → 原 "file collection" 不匹配
    "data collection":          ("T1005",     "Collection",       "Data from Local System"),
    # T1074.001: "data staged in temp directory" → 原 "data staging" 不匹配 "data staged"
    "data staged":              ("T1074.001", "Collection",       "Local Data Staging"),
    # T1059.004: "malicious postinstall script execution in ci pipeline"
    "postinstall":              ("T1059.004", "Execution",        "Unix Shell"),
    # T1195.002: "malicious npm package…" / "second malicious dependency package…"
    "malicious npm":            ("T1195.002", "InitialAccess",    "Compromise Software Supply Chain"),
    "malicious dependency":     ("T1195.002", "InitialAccess",    "Compromise Software Supply Chain"),
    "npm package":              ("T1195.002", "InitialAccess",    "Compromise Software Supply Chain"),
    # T1083: "mass file system enumeration" → 原 "file enumeration" 不匹配 "file system enumeration"
    "file system enumeration":  ("T1083",     "Discovery",        "File and Directory Discovery"),
    # ── 原有条目 ────────────────────────────────────────────────────────────────
    "macro":                ("T1566.001", "InitialAccess",       "Spearphishing Attachment"),
    "phishing":             ("T1566.001", "InitialAccess",       "Spearphishing Attachment"),
    "invoice":              ("T1566.001", "InitialAccess",       "Spearphishing Attachment"),
    "powershell":           ("T1059.001", "Execution",           "PowerShell"),
    "encoded powershell":   ("T1059.001", "Execution",           "PowerShell"),
    "registry run":         ("T1547.001", "Persistence",         "Registry Run Keys / Startup Folder"),
    "run key":              ("T1547.001", "Persistence",         "Registry Run Keys / Startup Folder"),
    "scheduled task":       ("T1053.005", "Persistence",         "Scheduled Task"),
    "lsass":                ("T1003.001", "CredentialAccess",    "LSASS Memory"),
    "credential":           ("T1003.001", "CredentialAccess",    "LSASS Memory"),
    "brute force":          ("T1110.003", "CredentialAccess",    "Password Spraying"),
    "password spray":       ("T1110.003", "CredentialAccess",    "Password Spraying"),
    "smb admin share":      ("T1021.002", "LateralMovement",     "SMB/Windows Admin Shares"),
    "admin share":          ("T1021.002", "LateralMovement",     "SMB/Windows Admin Shares"),
    "lateral movement smb": ("T1021.002", "LateralMovement",     "SMB/Windows Admin Shares"),
    "pass the hash":        ("T1550.002", "LateralMovement",     "Pass the Hash"),
    "c2 beacon":            ("T1071.001", "CommandAndControl",   "Web Protocols"),
    "c2 communication":     ("T1071.001", "CommandAndControl",   "Web Protocols"),
    "encrypted c2":         ("T1573.001", "CommandAndControl",   "Encrypted Channel"),
    "port scan":            ("T1046",     "Discovery",           "Network Service Discovery"),
    "network scan":         ("T1046",     "Discovery",           "Network Service Discovery"),
    "file enumeration":     ("T1083",     "Discovery",           "File and Directory Discovery"),
    "share enumeration":    ("T1135",     "Discovery",           "Network Share Discovery"),
    "rdp lateral":          ("T1021.001", "LateralMovement",     "Remote Desktop Protocol"),
    "file collection":      ("T1005",     "Collection",          "Data from Local System"),
    "data staging":         ("T1074.001", "Collection",          "Local Data Staging"),
    "file encrypt":         ("T1486",     "Impact",              "Data Encrypted for Impact"),
    "ransomware":           ("T1486",     "Impact",              "Data Encrypted for Impact"),
    "shadow copy":          ("T1490",     "Impact",              "Inhibit System Recovery"),
    "defacement":           ("T1491.001", "Impact",              "Internal Defacement"),
    "supply chain":         ("T1195.002", "InitialAccess",       "Compromise Software Supply Chain"),
    "malicious package":    ("T1195.002", "InitialAccess",       "Compromise Software Supply Chain"),
    "bash script":          ("T1059.004", "Execution",           "Unix Shell"),
    "native api":           ("T1106",     "Execution",           "Native API"),
    "masquerading":         ("T1036.005", "DefenseEvasion",      "Match Legitimate Name or Location"),
    "code signing":         ("T1553.004", "DefenseEvasion",      "Code Signing"),
    "exfiltration":         ("T1048.002", "Exfiltration",        "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol"),
    "large outbound":       ("T1048.002", "Exfiltration",        "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol"),
    "data transfer":        ("T1041",     "Exfiltration",        "Exfiltration Over C2 Channel"),
}


def extract_alert_names(messages) -> str:
    """从 messages 中解析 <ALERT_DATA> 标签内的 JSON，提取 alert_name 字段（小写）。"""
    for msg in messages:
        content = msg.get("content", "") if isinstance(msg, dict) else getattr(msg, "content", "")
        match = re.search(r"<ALERT_DATA>(.*?)</ALERT_DATA>", content, re.DOTALL)
        if match:
            raw = match.group(1).strip()
            try:
                data = json.loads(raw)
                if isinstance(data, list):
                    data = data[0]
                return str(data.get("alert_name", "")).lower()
            except (json.JSONDecodeError, IndexError, AttributeError):
                pass
    return ""


def build_response_template(tech_id: str, tactic: str, tech_name: str, alert_name: str) -> str:
    """动态构建与现有模板格式一致的 JSON 响应字符串。"""
    payload = {
        "risk_score": 7.5,
        "is_true_positive": True,
        "confidence": "high",
        "root_cause": f"检测到 {tech_name} 相关行为: {alert_name}",
        "mitre_mapping": [{
            "tactic": tactic,
            "technique_id": tech_id,
            "technique_name": tech_name,
            "evidence": f"基于告警 {alert_name} 的分析",
        }],
        "affected_assets": [],
        "recommendations": [{
            "action": "隔离受影响主机并展开调查",
            "impact_scope": "仅影响该主机",
            "priority": "immediate",
        }],
    }
    think_block = f"<think>\n基于告警名称 '{alert_name}' 识别到 {tech_id} ({tactic}) 技术特征。\n</think>"
    return f"{think_block}\n{json.dumps(payload, ensure_ascii=False, indent=2)}"


# ── Sprint 2 Agent 专用模板 ───────────────────────────────────────────────────

KILL_CHAIN_AGENT_TEMPLATE = json.dumps({
    "kill_chain_stages": [
        {
            "stage_order": 1,
            "tactic": "InitialAccess",
            "technique_id": "T1566.001",
            "timestamp": "2024-03-15T08:03:22Z",
            "description": "攻击者通过鱼叉式钓鱼邮件投递恶意宏文档，成功入侵目标工作站",
            "iocs": ["203.0.113.45", "2024薪资调整通知.docm"]
        },
        {
            "stage_order": 2,
            "tactic": "Execution",
            "technique_id": "T1059.001",
            "timestamp": "2024-03-15T08:45:00Z",
            "description": "恶意宏触发混淆 PowerShell 脚本，下载并执行第二阶段 payload",
            "iocs": ["powershell.exe -enc JABz..."]
        },
        {
            "stage_order": 3,
            "tactic": "Persistence",
            "technique_id": "T1547.001",
            "timestamp": "2024-03-15T09:01:00Z",
            "description": "通过注册表 Run 键写入持久化后门",
            "iocs": ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityUpdate"]
        },
        {
            "stage_order": 4,
            "tactic": "LateralMovement",
            "technique_id": "T1021.002",
            "timestamp": "2024-03-15T10:30:00Z",
            "description": "利用 SMB Admin Share 横向移动至域控服务器",
            "iocs": ["192.168.1.1", "ADMIN$"]
        },
        {
            "stage_order": 5,
            "tactic": "Exfiltration",
            "technique_id": "T1048.002",
            "timestamp": "2024-03-15T11:45:00Z",
            "description": "通过 HTTPS 加密通道向 C2 服务器渗漏敏感数据",
            "iocs": ["45.33.32.156", "update-service.malicious.com"]
        }
    ],
    "summary": "APT 组织通过鱼叉钓鱼完成从初始入侵到数据渗漏的完整攻击链，历时约 3.7 小时",
    "total_duration_minutes": 222,
    "highest_risk_asset": "DC01.corp.local"
}, ensure_ascii=False, indent=2)

RECOMMENDATION_AGENT_TEMPLATE = json.dumps([
    {
        "action": "立即隔离受感染主机（WORKSTATION-047、WORKSTATION-053），切断网络访问",
        "impact_scope": "影响约 2 台终端工作站，预计中断 2 名用户工作",
        "priority": "immediate",
        "playbook_ref": "PB-IR-001: Endpoint Isolation"
    },
    {
        "action": "重置所有受影响账户凭据（zhang.wei、li.fang），并强制启用 MFA",
        "impact_scope": "影响 2 个用户账户，需协调 IT 帮助台执行",
        "priority": "within_1h",
        "playbook_ref": "PB-IR-002: Credential Reset"
    },
    {
        "action": "在网络边界封锁 C2 IP（45.33.32.156）及域名，部署出站流量监控规则",
        "impact_scope": "影响全网出站策略，需防火墙管理员配合",
        "priority": "within_1h",
        "playbook_ref": "PB-IR-003: C2 Blocklist"
    }
], ensure_ascii=False, indent=2)


def _get_messages_text(messages) -> str:
    """拼接所有消息内容为小写字符串，用于关键词匹配。"""
    parts = []
    for msg in messages:
        content = msg.get("content", "") if isinstance(msg, dict) else getattr(msg, "content", "")
        parts.append(content.lower())
    return " ".join(parts)


def route_to_template(messages) -> str:
    """精准路由函数。
    优先级：
      1. kill chain / 杀伤链 / timeline → 杀伤链重建模板
      2. recommendation / 建议          → 响应建议模板
      3. alert_name 精准匹配            → 对应 MITRE 模板
      4. fallback                       → T1190
    """
    combined = _get_messages_text(messages)

    # 1. 杀伤链请求
    if any(kw in combined for kw in ["kill chain", "杀伤链", "timeline"]):
        think = "<think>\n按时间序列重建攻击杀伤链...\n</think>"
        return f"{think}\n{KILL_CHAIN_AGENT_TEMPLATE}"

    # 2. 建议请求
    if any(kw in combined for kw in ["recommendation", "建议"]):
        think = "<think>\n基于攻击链结论生成响应建议...\n</think>"
        return f"{think}\n{RECOMMENDATION_AGENT_TEMPLATE}"

    # 3. alert_name 精准匹配
    alert_name = extract_alert_names(messages)
    for keyword, (tech_id, tactic, tech_name) in ALERT_NAME_TO_TECHNIQUE.items():
        if keyword in alert_name:
            return build_response_template(tech_id, tactic, tech_name, alert_name)

    return build_response_template("T1190", "InitialAccess", "Exploit Public-Facing Application", alert_name)
