# 任务单 S0-003：Sprint 0 自动化验收脚本

## 背景
Sprint 0 完成后需要自动验证全部基础设施就绪，通过后才能解锁
Sprint 1。需要一个脚本对 6 个关键项进行自动检测，输出清晰的
Pass/Fail 报告。

## 期望输出文件
- tests/sprint0_acceptance.py

## 必须检测的 6 个项目（顺序执行）

### 检测项 1：Mock vLLM 健康检查
GET http://localhost:8000/health
期望：status_code=200，body 包含 "status":"ok"

### 检测项 2：Mock 推理格式验证
POST http://localhost:8000/v1/chat/completions
发送包含 "mitre" 关键词的请求
期望：响应 content 包含 <think> 标签（可选），剥离后 JSON 合法
期望 JSON 包含：risk_score（float）、mitre_mapping（list）

### 检测项 3：PostgreSQL 连接验证
连接字符串从环境变量 POSTGRES_DSN 读取
执行 SELECT 1 不报错

### 检测项 4：Qdrant 健康检查
GET http://localhost:6333/health
期望：status_code=200

### 检测项 5：Kafka 读写验证
向 test.topic 发送消息 b"ping"，不抛出异常
Bootstrap servers: localhost:9092

### 检测项 6：合成样本库完整性
导入 tests/fixtures/synthetic_alerts 中的 ALL_SAMPLES 和 get_ground_truth_map
期望：len(ALL_SAMPLES) >= 30
期望：len(get_ground_truth_map()) == len(ALL_SAMPLES)
期望：覆盖的不同 Tactic 数量 >= 6

## 输出格式（必须按此格式打印）
`
── Sprint 0 验收报告 ──────────────────────────────
  ✓  Mock vLLM 健康检查              PASS
  ✓  Mock 推理格式验证               PASS
  ✓  PostgreSQL 连接                 PASS
  ✓  Qdrant 健康检查                 PASS
  ✓  Kafka 读写验证                  PASS
  ✓  合成样本库完整性                PASS

✓ 全部 6 项通过 → Sprint 0 门禁解锁，可进入 Sprint 1
`
如有失败项，打印失败原因，最后打印：
"✗ N 项未通过，不得进入 Sprint 1"
并以 sys.exit(1) 退出。

## 验收标准
- [ ] 脚本在所有服务正常时输出全部 PASS
- [ ] 某个服务未启动时对应项显示 FAIL 并附错误原因
- [ ] 脚本本身的 import 只用标准库 + requirements.txt 中的包
- [ ] 从 .env 文件读取配置，不硬编码连接字符串
