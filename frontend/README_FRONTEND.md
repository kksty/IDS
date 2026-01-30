# IDS Dashboard 前端说明

位置：`frontend/`

快速开始：

1. 进入目录并安装依赖：

```bash
cd frontend
npm install
```

2. 启动开发服务器（默认 3000）：

```bash
npm run dev
```

3. 访问 `http://localhost:3000`，前端会通过 `ws://localhost:8000/ws/alerts` 订阅告警。

说明：前端是一个极简示例，包含三个组件：`AlertCounter`、`RecentAlerts`、`TrafficChart`。生产中请使用更完善的状态管理（Pinia/Vuex）和图表库（Chart.js / ECharts）。
