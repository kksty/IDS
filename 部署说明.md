# 部署说明

目的：说明如何在一台 Linux 服务器上部署并运行此 IDS 后端，以及如何接入前端（Vue）。

先决条件

- 一台可用的 Linux 服务器（Debian/Ubuntu/CentOS 均可）
- 已安装 PostgreSQL（或提供可访问的 Postgres 实例）
- Python 3.11/3.12/3.13，以及 `pip`
- 推荐使用虚拟环境（项目已包含 `myvenv` 的示例）

环境变量

- `IDS_DATABASE_URL`：Postgres 连接字符串，例如：
  `IDS_DATABASE_URL=postgresql+psycopg2://user:password@localhost:5432/ids`
- `IDS_LOG_LEVEL`：可选，`DEBUG|INFO|WARN|ERROR`

安装与准备

1. 克隆代码并进入项目目录

2. 创建并激活虚拟环境（如果未提供）

```bash
python -m venv myvenv
source myvenv/bin/activate
```

3. 安装依赖

```bash
./myvenv/bin/pip install -r requirements.txt
```

4. 配置环境变量（建议写入 `.env` 或 systemd 环境文件）
   建立数据库用户并建立ids库

```bash
export IDS_DATABASE_URL='postgresql://user:pass@127.0.0.1:5432/ids'
export IDS_LOG_LEVEL=INFO
```

5. 初始化数据库表（服务启动时会调用 `init_db()`，也可手动运行）

```bash
# 使用 python 启动会自动调用 init_db() 并创建表
./myvenv/bin/python -m app.main
```

启动服务（开发/测试）

```bash
IDS_LOG_LEVEL=DEBUG ./myvenv/bin/python -m app.main
```

在生产中以 systemd 管理（示例）

1. 创建 systemd 单元 `/etc/systemd/system/ids-backend.service`

```
[Unit]
Description=IDS Backend
After=network.target

[Service]
Type=simple
User=idsuser
Group=idsuser
WorkingDirectory=/path/to/IDS
Environment=IDS_DATABASE_URL=postgresql://user:pass@127.0.0.1:5432/idsdb
Environment=IDS_LOG_LEVEL=INFO
ExecStart=/path/to/IDS/myvenv/bin/python -m app.main
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

2. 启用并启动

```bash
sudo systemctl daemon-reload
sudo systemctl enable ids-backend
sudo systemctl start ids-backend
sudo journalctl -u ids-backend -f
```

指标与监控

- Prometheus 可抓取 `http://<host>:8000/metrics`（项目已提供 `/metrics` 路由）。
- 推荐监控项：`ids_packets_processed_total`、`ids_matches_found_total`、`ids_alerts_emitted_total`、`ids_engine_rebuild_seconds`、`ids_engine_ready`

前端（Vue）接入建议

- 两种方式：
  1. 独立部署 Vue 静态站点（推荐：使用 Nginx/Netlify/Vercel），通过 CORS 调用后端 API 和 WebSocket（后端已允许 CORS 开发阶段为 `*`）。
  2. 将构建好的静态文件放到后端同一个主机并由 Nginx/后端静态路由提供（需要配置 Nginx 将 `/` 静态目录与 `/api` 转发区分）。
- WebSocket 地址：`ws://<host>:8000/ws/alerts`（或通过 `wss://` 在 HTTPS 下）。

规则管理 API

- 已提供基本 CRUD：
  - `GET /api/rules` 列表
  - `POST /api/rules` 新建
  - `PUT /api/rules/{rule_id}` 更新
  - `DELETE /api/rules/{rule_id}` 删除

告警持久化

- 每次触发时告警会由 `app/services/alerter.py` 的 `_persist()` 写入数据库，表结构见 [app/models/db_models.py](app/models/db_models.py)。前端收到的告警由 `alerter` 广播。

安全与生产注意事项（简要）

- 不要以 root 运行服务；创建专用低权限用户运行。
- 在生产中使用 HTTPS（反向代理 Nginx + TLS），并使用 `wss://` 保护 WebSocket。
- 如果需要检测 HTTPS 流量，请采用 TAP/SSL 终端或部署在边车/代理（如 mitmproxy）上进行流量解密测试（注意合法合规）。
- 配置数据库备份与日志轮转。

下一步建议

- 我可以为你：
  1. 脚手架一个最小的 Vue 项目并把 `test.html` 的功能迁移为可交互的页面；
  2. 或者把 `test.html` 作为静态资源由后端或 Nginx 提供（我可以添加 FastAPI 的静态路由示例）。

文件： [app/services/alerter.py](app/services/alerter.py) 中的 `_persist()` 会把 Alert 写入数据库；告警模型在 [app/models/db_models.py](app/models/db_models.py)。
