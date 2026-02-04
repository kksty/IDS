# IDS Dashboard（Python + FastAPI + Vue）

一个入侵检测系统（IDS）演示项目：支持抓包解析、规则匹配、告警持久化、实时 WebSocket 推送，以及基于 Prometheus 的指标暴露与前端仪表盘展示。

## 功能概览

- **抓包与解析**：默认启动嗅探器，对流量做协议解析（项目中包含 HTTP 解析与适配层）。
- **规则引擎**：支持关键字/多模式匹配（Aho–Corasick），支持规则启用/禁用、热更新、批量导入。
- **Snort3 规则导入**：上传 `.rules` 文件解析并导入为系统规则。
- **告警与持久化**：命中规则后写入 PostgreSQL，并通过 WebSocket 实时推送到前端。
- **行为与关联分析**：对可疑攻击者进行聚合与评分，提供查询接口。
- **可观测性**：`/metrics` 暴露 Prometheus 指标，`/health` 提供健康检查。

## 快速开始（后端）

### 1) 依赖

- Linux（推荐）
- Python 3.11+（项目内已有 `myvenv/` 示例虚拟环境）
- PostgreSQL（必需：启动时会校验 `IDS_DATABASE_URL`）

安装依赖：

```bash
./myvenv/bin/pip install -r requirements.txt
```

### 2) 配置环境变量

最少需要：

```bash
export IDS_DATABASE_URL='postgresql+psycopg2://user:pass@127.0.0.1:5432/ids'
```

常用可选项：

```bash
export IDS_NETWORK_INTERFACE='lo'   # 默认 lo
export IDS_HOST='0.0.0.0'           # 默认 0.0.0.0
export IDS_PORT='8000'              # 默认 8000
export IDS_LOG_LEVEL='INFO'         # 默认 INFO
export IDS_LOG_TO_FILE='false'      # 默认 false（写入 logs/ids.log）
export IDS_RELOAD='true'            # 开发模式自动重载
```

提示：如果启动时报错 `IDS_DATABASE_URL is required`，说明没配置数据库连接字符串。

### 3) 启动 API 服务

开发（推荐用 uvicorn）：

```bash
sudo ./myvenv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

或直接运行模块（不带 uvicorn 热重载）：

```bash
./myvenv/bin/python -m app.main
```

启动后默认会：

- 初始化数据库表（`init_db()`）
- 从数据库加载规则到内存引擎
- **默认启动嗅探器** 与 **默认启动关联监控**（见应用生命周期日志）

## 权限说明（抓包）

抓包通常需要 root 权限或 `cap_net_raw/cap_net_admin` 能力。

- 简单方式：使用 `sudo` 启动后端（如上示例）。
- 更细粒度方式：可以给虚拟环境内的 Python 可执行文件配置 capabilities（按你的发行版策略自行选择）。

## 前端（Vue + Vite）

前端位于 `frontend/`，开发模式默认端口为 `3000`，并已配置代理到后端（`/api`、`/health`、`/config`、`/ws`）。

```bash
cd frontend
npm install
npm run dev
```

访问：`http://localhost:3000`

## 主要接口

FastAPI 自带文档：

- Swagger UI：`/docs`
- ReDoc：`/redoc`

基础：

- `GET /`：服务存活提示
- `GET /health`：健康检查（包含数据库连通性）
- `GET /metrics`：Prometheus 指标
- `GET /config`：调试用配置回显

WebSocket：

- `WS /ws/alerts`：实时告警推送

规则管理（部分）：

- `GET /api/rules/`：分页/搜索/筛选规则
- `POST /api/rules/`：创建规则
- `PUT /api/rules/{rule_id}`：更新规则
- `DELETE /api/rules/{rule_id}`：删除规则
- `DELETE /api/rules/batch`：批量删除
- `POST /api/rules/bulk-import`：上传 `.rules` 批量导入 Snort3 规则
- `GET /api/rules/snort-variables`：查看 Snort 变量
- `PUT /api/rules/snort-variables/{VAR}`：更新 Snort 变量

告警查询：

- `GET /api/alerts/`：最近告警（支持 src_ip/rule_id/时间范围筛选）
- `GET /api/alerts/stats`：聚合统计（按时间桶 + Top rules/IPs）
- `DELETE /api/alerts/`：清空告警

系统控制：

- `GET /api/system/status`：系统运行状态
- `POST /api/system/sniffer/start`：启动嗅探器
- `POST /api/system/sniffer/stop`：停止嗅探器

关联分析：

- `GET /api/correlation/attackers`：可疑攻击者列表
- `GET /api/correlation/stats`：关联分析统计

## 运行测试

```bash
./myvenv/bin/pytest -q
```

## 目录结构

- `app/`：后端（FastAPI 路由、服务、规则引擎、嗅探、关联/行为分析）
- `frontend/`：前端（Vue + Element Plus + Vite）
- `tests/`：pytest 用例
- `logs/`：运行日志目录（可选写文件）
- `README.md/`：项目过程文档与设计笔记（开发阶段文档）

## 常见问题

- **启动即失败：**多半是未配置 `IDS_DATABASE_URL`，或 PostgreSQL 不可达。
- **没有实时告警：**检查前端是否连上 `WS /ws/alerts`，以及嗅探是否在运行（`GET /api/system/status`）。
- **抓不到包：**检查网卡名 `IDS_NETWORK_INTERFACE`，并确认有抓包权限（root/capabilities）。
