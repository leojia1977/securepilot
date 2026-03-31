# 任务单 S0-001：Mock vLLM 推理服务

## 背景
SecuPilot 项目的 GPU 服务器尚未到位。需要构建一个 Mock 服务来
模拟 Qwen3-32B-Instruct 的 API 响应，使整个产品主链路可以在
普通开发机上端到端跑通。真实 vLLM 到位后，产品代码零改动直接切换。

## 期望输出文件
- mock/vllm_server.py        # FastAPI Mock 服务主体
- mock/response_templates.py # 按场景分类的响应模板
- mock/Dockerfile.mock       # Mock 服务容器镜像
- mock/docker-compose.mock.yml # 完整 Mock 环境启动文件（含 Kafka/PG/Qdrant）
- tests/test_mock_server.py  # Mock 服务接口测试

## 核心需求
1. 完全兼容 OpenAI /v1/chat/completions 接口格式
2. 响应内容模拟 Qwen3 Thinking Mode 格式，包含  标签
3. 根据请求内容中的关键词路由到不同响应模板：
   - 含 "kill/chain/timeline" → 返回杀伤链模板
   - 含 "mitre/att&ck/tactic" → 返回 MITRE 分析模板
   - 含 "recommendation/action" → 返回建议模板
   - 其他 → 返回根因分析模板
4. 模拟推理延迟：0.5~1.5 秒随机延迟
5. 响应 JSON 必须包含字段：risk_score, mitre_mapping, root_cause, recommendations

## 根因分析模板示例（返回格式）
响应 content 格式为：
<think>
分析告警数据中...识别关键字段...
</think>
{"risk_score": 7.8, "is_true_positive": true, ...}

## docker-compose.mock.yml 必须包含服务
- mock-vllm（端口 8000）
- postgres:16-alpine（端口 5432，数据库名 securepilot）
- qdrant/qdrant:v1.9.0（端口 6333）
- redis:7-alpine（端口 6379）
- confluentinc/cp-kafka:7.6.0（端口 9092）
- confluentinc/cp-zookeeper:7.6.0（端口 2181）

## 验收标准
- [ ] GET http://localhost:8000/health 返回 {"status":"ok"}
- [ ] POST http://localhost:8000/v1/chat/completions 返回包含 <think> 标签的响应
- [ ] 解析后的 JSON 包含 risk_score 和 mitre_mapping 字段
- [ ] docker compose up 一条命令启动全部服务无报错
- [ ] pytest tests/test_mock_server.py 全部通过

## 禁止事项
- 不要调用任何外部 API
- 不要使用 GPU 或 CUDA 相关依赖
- 所有敏感配置从环境变量读取，参考项目根目录 .env 文件
