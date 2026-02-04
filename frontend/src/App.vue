<template>
  <div class="app-root">
    <header class="app-header">
      <div class="header-left">
        <h1>IDS Dashboard</h1>
        <div class="ws-status">
          <span class="dot" :class="wsStatusClass"></span>
          <span class="ws-text">实时通道：{{ wsStatusText }}</span>
        </div>
      </div>
      <nav class="nav-actions">
        <a
          v-for="item in navItems"
          :key="item.id"
          :href="'#/' + item.id"
          class="nav-link"
          :class="{ active: page === item.id }"
        >
          {{ item.label }}
        </a>
      </nav>
    </header>
    <main
      class="app-main"
      :class="{ 'full-width': page === 'alerts' || page === 'rules' }"
    >
      <section class="main-left">
        <alert-counter v-if="page !== 'stats'" />
        <div v-if="page === 'home'" class="page-content">
          <recent-alerts />
        </div>
        <div
          v-else-if="page === 'alerts'"
          class="page-content page-content-wide"
        >
          <alerts-table />
        </div>
        <div
          v-else-if="page === 'rules'"
          class="page-content page-content-wide"
        >
          <rules-page />
        </div>
        <div v-else-if="page === 'stats'" class="page-content">
          <stats-page />
        </div>
        <div v-else-if="page === 'correlation'" class="page-content">
          <suspected-attackers />
        </div>
        <div v-else-if="page === 'system'" class="page-content">
          <system-status />
        </div>
      </section>
      <aside class="main-right">
        <traffic-chart />
      </aside>
    </main>
  </div>
</template>

<script>
import { ref, computed, onMounted, onBeforeUnmount } from "vue";
import AlertCounter from "./components/AlertCounter.vue";
import RecentAlerts from "./components/RecentAlerts.vue";
import AlertsTable from "./components/AlertsTable.vue";
import RulesPage from "./components/RulesPage.vue";
import StatsPage from "./components/StatsPage.vue";
import SuspectedAttackers from "./components/SuspectedAttackers.vue";
import TrafficChart from "./components/TrafficChart.vue";
import SystemStatus from "./components/SystemStatus.vue";
import bus from "./ws";

export default {
  components: {
    AlertCounter,
    RecentAlerts,
    AlertsTable,
    RulesPage,
    StatsPage,
    SuspectedAttackers,
    TrafficChart,
    SystemStatus,
  },
  setup() {
    const page = ref("home");
    const wsStatus = ref("connecting"); // open / closed / error / connecting

    function setPageFromHash() {
      const h = (window.location.hash || "").replace(/^#\/?/, "");
      if (!h) {
        page.value = "home";
      } else if (
        h === "alerts" ||
        h === "rules" ||
        h === "stats" ||
        h === "correlation" ||
        h === "system" ||
        h === "home"
      ) {
        page.value = h;
      } else {
        // unknown hash -> default to home
        page.value = "home";
      }
    }

    function navigate(p) {
      window.location.hash = `#/${p}`;
    }

    function onHashChange() {
      setPageFromHash();
    }

    function onWsStatus(ev) {
      const s = (ev.detail || "").toString();
      if (s === "open") wsStatus.value = "open";
      else if (s === "closed") wsStatus.value = "closed";
      else if (s === "error") wsStatus.value = "error";
      else wsStatus.value = "connecting";
    }

    const wsStatusText = computed(() => {
      switch (wsStatus.value) {
        case "open":
          return "已连接";
        case "closed":
          return "已断开";
        case "error":
          return "异常";
        default:
          return "连接中...";
      }
    });

    const wsStatusClass = computed(() => {
      return {
        "dot-open": wsStatus.value === "open",
        "dot-closed": wsStatus.value === "closed",
        "dot-error": wsStatus.value === "error",
      };
    });

    const navItems = [
      { id: "home", label: "仪表盘" },
      { id: "alerts", label: "告警列表" },
      { id: "rules", label: "规则管理" },
      { id: "stats", label: "数据统计" },
      { id: "correlation", label: "关联分析" },
      { id: "system", label: "系统状态" },
    ];

    onMounted(() => {
      // 使用 try-catch 保护初始化，防止错误阻塞渲染
      try {
        setPageFromHash();
      } catch (e) {
        console.error("Error setting page from hash:", e);
        page.value = "home";
      }

      // 为 hashchange 事件添加包装器，允许点击导航链接
      const handleHashChange = () => {
        try {
          onHashChange();
        } catch (e) {
          console.error("Error in onHashChange:", e);
        }
      };
      window.addEventListener("hashchange", handleHashChange);

      // 为 WebSocket 状态事件添加包装器
      const handleWsStatus = (ev) => {
        try {
          onWsStatus(ev);
        } catch (e) {
          console.error("Error in onWsStatus:", e);
        }
      };
      bus.addEventListener("status", handleWsStatus);

      // 保存引用以便 cleanup
      window.__handleHashChange = handleHashChange;
      window.__handleWsStatus = handleWsStatus;
    });

    onBeforeUnmount(() => {
      // 移除事件监听器，使用存储的引用
      if (window.__handleHashChange) {
        window.removeEventListener("hashchange", window.__handleHashChange);
        delete window.__handleHashChange;
      }
      if (window.__handleWsStatus) {
        bus.removeEventListener("status", window.__handleWsStatus);
        delete window.__handleWsStatus;
      }
    });

    return { page, navigate, wsStatusText, wsStatusClass, navItems };
  },
};
</script>

<style>
/* global layout styles */
body {
  background: #f0f2f5;
  margin: 0;
  font-family:
    -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue",
    Arial, sans-serif;
}
.app-root {
  padding: 24px 28px;
  max-width: 100%;
  width: 100%;
  min-width: 0;
  margin: 0 auto;
  min-height: 100vh;
  box-sizing: border-box;
}
.app-header {
  position: relative;
  z-index: 11050;
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  margin-bottom: 20px;
  flex-wrap: wrap;
  gap: 12px;
  background: #f0f2f5;
  margin-left: -28px;
  margin-right: -28px;
  margin-top: -24px;
  padding: 24px 28px 20px;
}
.app-header h1 {
  margin: 0 0 8px 0;
  font-size: 22px;
  font-weight: 600;
  color: #1a1a2e;
}
.header-left {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.ws-status {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  color: #64748b;
}
.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #facc15;
  flex-shrink: 0;
}
.dot-open {
  background: #22c55e;
}
.dot-closed {
  background: #94a3b8;
}
.dot-error {
  background: #ef4444;
}
.nav-actions {
  display: flex;
  align-items: center;
  gap: 4px;
  flex-wrap: wrap;
}
.nav-link {
  padding: 8px 14px;
  border-radius: 8px;
  font-size: 14px;
  color: #475569;
  text-decoration: none;
  transition:
    background 0.2s,
    color 0.2s;
}
.nav-link:hover {
  background: #e2e8f0;
  color: #1e293b;
}
.nav-link.active {
  background: #3b82f6;
  color: #fff;
}
.app-main {
  display: flex;
  gap: 24px;
  align-items: flex-start;
}
.main-left {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 20px;
  min-width: 0;
}
.main-right {
  width: 380px;
  flex-shrink: 0;
}
.app-main.full-width .main-right {
  display: none;
}
.app-main.full-width .main-left {
  max-width: 100%;
}
.page-content {
  min-height: 320px;
}
.page-content-wide {
  width: 100%;
  max-width: 100%;
  min-width: 0;
  overflow: visible;
}
@media (max-width: 900px) {
  .main-right {
    width: 100%;
  }
  .app-main {
    flex-direction: column;
  }
  .app-main.full-width .main-right {
    display: block;
  }
}
.el-card {
  background: #fff;
  border-radius: 12px;
}
</style>
