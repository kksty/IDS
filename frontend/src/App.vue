<template>
  <div class="app-root">
    <header class="app-header">
      <h1>IDS Dashboard</h1>
      <div class="nav-actions">
        <el-button type="text" @click="navigate('home')">仪表盘</el-button>
        <el-button type="text" @click="navigate('alerts')">告警列表</el-button>
        <el-button type="text" @click="navigate('rules')">规则管理</el-button>
        <el-button type="text" @click="navigate('stats')">数据统计</el-button>
      </div>
    </header>
    <main class="app-main">
      <section class="main-left">
        <alert-counter v-if="page !== 'stats'" />
        <div v-if="page === 'home'">
          <recent-alerts />
        </div>
        <div v-else-if="page === 'alerts'">
          <alerts-table />
        </div>
        <div v-else-if="page === 'rules'">
          <rules-page />
        </div>
        <div v-else-if="page === 'stats'">
          <stats-page />
        </div>
      </section>
      <aside class="main-right">
        <traffic-chart />
      </aside>
    </main>
  </div>
</template>

<script>
import { ref, onMounted, onBeforeUnmount } from "vue";
import AlertCounter from "./components/AlertCounter.vue";
import RecentAlerts from "./components/RecentAlerts.vue";
import AlertsTable from "./components/AlertsTable.vue";
import RulesPage from "./components/RulesPage.vue";
import StatsPage from "./components/StatsPage.vue";
import TrafficChart from "./components/TrafficChart.vue";
import "./ws";

export default {
  components: {
    AlertCounter,
    RecentAlerts,
    AlertsTable,
    RulesPage,
    StatsPage,
    TrafficChart,
  },
  setup() {
    const page = ref("home");

    function setPageFromHash() {
      const h = (window.location.hash || "").replace(/^#\/?/, "");
      if (!h) {
        page.value = "home";
      } else if (
        h === "alerts" ||
        h === "rules" ||
        h === "stats" ||
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

    onMounted(() => {
      setPageFromHash();
      window.addEventListener("hashchange", onHashChange);
    });

    onBeforeUnmount(() => {
      window.removeEventListener("hashchange", onHashChange);
    });

    return { page, navigate };
  },
};
</script>

<style>
/* global layout styles */
body {
  background: #f6f7fb;
  margin: 0;
  font-family: Arial, Helvetica, sans-serif;
}
.app-root {
  padding: 20px;
  max-width: 1200px;
  margin: 0 auto;
}
.app-header h1 {
  margin: 0 0 12px 0;
  font-size: 20px;
  color: #222;
}
.app-main {
  display: flex;
  gap: 20px;
  align-items: flex-start;
}
.main-left {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.main-right {
  width: 420px;
}
.app-root {
  padding: 28px;
  max-width: 1400px;
  margin: 0 auto;
}
.app-header h1 {
  margin: 0 0 16px 0;
  font-size: 22px;
  color: #111;
}
.app-main {
  display: flex;
  gap: 28px;
  align-items: flex-start;
}
.main-left {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 20px;
}
.main-right {
  width: 520px;
}

/* make cards (like recent alerts) sit on white background */
.el-card {
  background: #fff;
}
</style>
