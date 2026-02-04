<template>
  <el-card class="alert-counter-card" shadow="hover">
    <div class="counter-header">
      <div class="title-row">
        <el-icon class="title-icon"><Bell /></el-icon>
        <span class="title">告警统计</span>
        <a
          href="#/alerts"
          class="link-to-alerts"
          @click.prevent="goToAlerts"
        >
          查看列表
          <el-icon><ArrowRight /></el-icon>
        </a>
      </div>
      <div class="total-row">
        <span class="total-label">总告警数</span>
        <span class="total-value">{{ total }}</span>
      </div>
    </div>
    <div class="severity-cards">
      <div class="sev-card high">
        <div class="sev-icon-wrap">
          <el-icon class="sev-icon"><WarningFilled /></el-icon>
        </div>
        <div class="sev-body">
          <span class="sev-label">高</span>
          <span class="sev-value">{{ counts.high }}</span>
        </div>
      </div>
      <div class="sev-card medium">
        <div class="sev-icon-wrap">
          <el-icon class="sev-icon"><Warning /></el-icon>
        </div>
        <div class="sev-body">
          <span class="sev-label">中</span>
          <span class="sev-value">{{ counts.medium }}</span>
        </div>
      </div>
      <div class="sev-card low">
        <div class="sev-icon-wrap">
          <el-icon class="sev-icon"><InfoFilled /></el-icon>
        </div>
        <div class="sev-body">
          <span class="sev-label">低</span>
          <span class="sev-value">{{ counts.low }}</span>
        </div>
      </div>
    </div>
    <div class="footer-hint">
      <span class="dot live"></span>
      实时 + 持久化统计
    </div>
  </el-card>
</template>

<script>
import bus from "../ws";
import { reactive, ref, onMounted, onBeforeUnmount } from "vue";
import { Bell, ArrowRight, WarningFilled, Warning, InfoFilled } from "@element-plus/icons-vue";

export default {
  components: { Bell, ArrowRight, WarningFilled, Warning, InfoFilled },
  setup() {
    const counts = reactive({ high: 0, medium: 0, low: 0 });
    const total = ref(0);

    function onAlert(e) {
      const a = e.detail || {};
      const sev = (a.severity || "low").toLowerCase();
      if (sev === "high") counts.high++;
      else if (sev === "medium") counts.medium++;
      else counts.low++;
      total.value++;
    }

    function goToAlerts() {
      window.location.hash = "#/alerts";
    }

    onMounted(() => {
      bus.addEventListener("alert", onAlert);
      fetch("/api/alerts/count")
        .then((r) => r.json())
        .then((j) => {
          if (j && typeof j.total === "number") total.value = j.total;
        })
        .catch(() => {});
    });
    onBeforeUnmount(() => bus.removeEventListener("alert", onAlert));

    return { counts, total, goToAlerts };
  },
};
</script>

<style scoped>
.alert-counter-card {
  border-radius: 12px;
  overflow: hidden;
  border: none;
  background: linear-gradient(180deg, #ffffff 0%, #fafbfc 100%);
}
.alert-counter-card :deep(.el-card__body) {
  padding: 18px 20px;
}
.counter-header {
  margin-bottom: 16px;
}
.title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 10px;
}
.title-icon {
  font-size: 18px;
  color: #409eff;
  margin-right: 6px;
}
.title {
  font-size: 16px;
  font-weight: 600;
  color: #303133;
  flex: 1;
}
.link-to-alerts {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 13px;
  color: #409eff;
  text-decoration: none;
}
.link-to-alerts:hover {
  color: #66b1ff;
}
.total-row {
  display: flex;
  align-items: baseline;
  gap: 8px;
}
.total-label {
  font-size: 13px;
  color: #909399;
}
.total-value {
  font-size: 26px;
  font-weight: 700;
  color: #303133;
  letter-spacing: -0.5px;
}
.severity-cards {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
}
.sev-card {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 14px;
  border-radius: 10px;
  border: 1px solid transparent;
}
.sev-card.high {
  background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%);
  border-color: rgba(239, 68, 68, 0.2);
}
.sev-card.medium {
  background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%);
  border-color: rgba(245, 158, 11, 0.2);
}
.sev-card.low {
  background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
  border-color: rgba(34, 197, 94, 0.2);
}
.sev-icon-wrap {
  width: 36px;
  height: 36px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
}
.sev-card.high .sev-icon-wrap {
  background: rgba(239, 68, 68, 0.15);
}
.sev-card.high .sev-icon {
  color: #dc2626;
  font-size: 18px;
}
.sev-card.medium .sev-icon-wrap {
  background: rgba(245, 158, 11, 0.15);
}
.sev-card.medium .sev-icon {
  color: #d97706;
  font-size: 18px;
}
.sev-card.low .sev-icon-wrap {
  background: rgba(34, 197, 94, 0.15);
}
.sev-card.low .sev-icon {
  color: #16a34a;
  font-size: 18px;
}
.sev-body {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.sev-label {
  font-size: 12px;
  color: #606266;
}
.sev-value {
  font-size: 20px;
  font-weight: 700;
  color: #303133;
}
.footer-hint {
  margin-top: 12px;
  font-size: 12px;
  color: #909399;
  display: flex;
  align-items: center;
  gap: 6px;
}
.dot.live {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #22c55e;
  animation: pulse 1.5s ease-in-out infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}
</style>
