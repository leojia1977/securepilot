# 任务单 S0-002：ATT&CK 合成告警样本库

## 背景
SecuPilot 尚未接入真实客户日志。需要构建一批覆盖主要 ATT&CK
战术阶段的合成告警，用于 Sprint 1 的 MITRE 归因准确率验收（目标 ≥ 70%）。

## 期望输出文件
- tests/fixtures/synthetic_alerts.py   # 样本数据 + 工具函数
- tests/fixtures/alerts_synthetic_30.json # 导出的 JSON 文件

## 核心需求：构造 30 条合成告警，分三个场景

### 场景 A（12条）：APT 鱼叉钓鱼攻击链
攻击序列：InitialAccess → Execution → Persistence →
           CredentialAccess → LateralMovement → CommandAndControl
真实感要素：
- 用户名用中文拼音（zhang.wei, li.fang）
- 主机名用企业风格（WORKSTATION-047, DC01, FS01）
- IP 用私有地址段（192.168.x.x）
- 包含 PowerShell base64 命令、LSASS 内存读取、SMB 横移等

### 场景 B（10条）：勒索软件内网扩散
攻击序列：Discovery → LateralMovement → Collection → Impact
真实感要素：
- 大规模端口扫描（254个目标）
- 文件批量加密（>.lockbit 扩展名）
- 卷影副本删除
- 勒索说明文件创建

### 场景 C（8条）：软件供应链攻击
攻击序列：InitialAccess(T1195.002) → Execution → DefenseEvasion → Exfiltration
真实感要素：
- 构建服务器拉取恶意 npm 包
- 大量数据外传（500MB+）
- 自签名证书的 C2 通信

## 每条告警必须包含的字段
{
  "event_id": "UUID",
  "timestamp": "ISO8601",
  "source_type": "network|endpoint|auth|web",
  "source_system": "snort|zeek|firewall|edr",
  "severity": 1~5,
  "risk_score": 0.0~10.0,
  "src_ip": "string",
  "dst_ip": "string|null",
  "src_port": "int|null",
  "dst_port": "int|null",
  "protocol": "string|null",
  "user": "string|null",
  "hostname": "string|null",
  "alert_name": "string",
  "alert_description": "string",
  "raw_payload": {},
  "ground_truth": {
    "tactic": "ATT&CK战术名",
    "technique_id": "T####(.###)",
    "technique_name": "string"
  }
}

## 工具函数（必须实现）
- export_to_json(filepath)    # 导出为 JSON 文件
- get_ground_truth_map()      # 返回 {event_id: ground_truth}
- inject_to_kafka(servers)    # 注入到 Kafka Topic: enriched.alerts
- get_scenario(name: "A"|"B"|"C")  # 按场景返回子集

## 验收标准
- [ ] ALL_SAMPLES 长度恰好为 30
- [ ] 覆盖至少 8 个不同的 ATT&CK Tactic
- [ ] 每条告警 ground_truth.technique_id 格式匹配 T\d{4}(\.\d{3})?
- [ ] export_to_json() 执行成功，生成 alerts_synthetic_30.json
- [ ] 三个场景的时间戳连续合理（同一场景内按攻击序列递增）
