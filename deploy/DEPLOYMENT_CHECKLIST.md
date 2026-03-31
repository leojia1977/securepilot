# SecuPilot PoC 部署验收检查单

## 环境要求

- [ ] 服务器 OS：Linux（Ubuntu 20.04+）或 Windows Server 2019+
- [ ] Python 3.11+
- [ ] Docker 24.0+（生产模式）
- [ ] 内网可访问 Kafka Bootstrap Servers
- [ ] 端口 8080 未被占用
- [ ] 磁盘空间 >= 10GB（含容器镜像）
- [ ] 内存 >= 8GB（Mock 模式 4GB 可用）
- [ ] 防火墙允许内网访问 8080 端口

---

## 部署步骤

### Mock 模式（演示/PoC）

1. 克隆仓库并进入目录
2. 运行 `python deploy/setup.py`，选择 `[1] Mock 模式`
3. 在另一个终端启动 Mock vLLM：
   ```
   uvicorn mock.vllm_server:app --host 0.0.0.0 --port 8000 --reload
   ```
4. 在主终端启动 FastAPI：
   ```
   uvicorn src.api.main:app --host 0.0.0.0 --port 8080 --reload
   ```
5. 运行演示数据注入：`python demo/inject_demo_data.py`
6. 浏览器打开 `src/dashboard/index.html`

### 生产模式

1. 配置 `.env` 文件，填入真实 `VLLM_BASE_URL` 和 `KAFKA_BOOTSTRAP_SERVERS`
2. 运行 `docker compose -f deploy/docker-compose.prod.yml up -d`
3. 确认所有容器健康：`docker compose ps`

---

## 部署验证

- [ ] 运行 `python deploy/setup.py` 无报错
- [ ] 浏览器访问 `http://[服务器IP]:8080/health` 返回 `{"status":"ok"}`
- [ ] 浏览器访问 `http://[服务器IP]:8080/docs` 可看到 API 文档页面

---

## 功能验证

- [ ] 打开 `src/dashboard/index.html`，顶部状态栏显示绿色"正常运行"
- [ ] 调用 `POST /api/trigger` 触发分析，15 秒内 `GET /api/events` 返回结果
- [ ] 事件详情页显示杀伤链时间线（至少 3 个阶段）
- [ ] ATT&CK 战术标签正确显示（如 InitialAccess、Execution、Persistence）
- [ ] 审批操作：点击 Accept 后事件状态变为 `accepted`
- [ ] 审批操作：点击 Reject 并填写原因后状态变为 `rejected`
- [ ] `GET /api/metrics/mtta` 返回合理数字（MTTA 均值、接受率等）
- [ ] 钉钉告警（如已配置 DINGTALK_WEBHOOK）：高危事件触发推送

---

## 性能验证

- [ ] 单事件分析端到端延迟 < 20 秒（Mock 模式）
- [ ] Dashboard 页面加载 < 3 秒
- [ ] `GET /api/events` 响应时间 < 500ms
- [ ] `GET /api/metrics/mtta` 响应时间 < 500ms

---

## 安全验证

- [ ] 服务运行期间无外部网络请求
  验证方法：在防火墙日志中检查服务器出口流量
- [ ] `.env` 文件不提交至 Git（确认 `.gitignore` 包含 `.env`）
- [ ] `INTERNAL_TOKEN` 已修改为非默认值（生产模式）

---

## 常见问题

**Q: FastAPI 启动报 `ModuleNotFoundError`**
A: 确认已运行 `pip install -r requirements.txt`，且从项目根目录启动。

**Q: 验收脚本报 "Connection refused"**
A: 确认 FastAPI 已在 8080 端口运行，Mock vLLM 已在 8000 端口运行。

**Q: Dashboard 显示 "API 不可达"**
A: 检查 `index.html` 顶部 `API_BASE` 是否与实际地址一致。

**Q: 分析结果为空（kill_chain 空、recommendations 空）**
A: Mock vLLM 可能未正确启动，检查 8000 端口是否有响应。

---

## 验收签字

| 角色 | 姓名 | 日期 |
|------|------|------|
| 客户代表 | ________________ | ________________ |
| 实施工程师 | ________________ | ________________ |
| 项目经理 | ________________ | ________________ |
