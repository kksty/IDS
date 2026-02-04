<template>
  <div class="system-status">
    <el-card class="status-card" shadow="hover" v-loading="loading">
      <template #header>
        <div class="header-wrapper">
          <div class="header-title">
            <el-icon class="title-icon"><Monitor /></el-icon>
            <span>系统状态总览</span>
          </div>
          <div class="header-actions">
            <el-button size="small" type="primary" @click="reload">
              <el-icon><Refresh /></el-icon>
              刷新
            </el-button>
          </div>
        </div>
      </template>

      <el-row :gutter="16">
        <el-col :md="8" :sm="24">
          <el-card shadow="never" class="info-card">
            <div class="card-title">运行状态</div>
            <div class="kv-row">
              <span class="kv-label">健康状态</span>
              <span class="kv-value">
                <el-tag
                  :type="healthTagType"
                  size="small"
                >
                  {{ healthStatusText }}
                </el-tag>
              </span>
            </div>
            <div class="kv-row">
              <span class="kv-label">数据库</span>
              <span class="kv-value">
                <el-tag
                  :type="
                    health.database && String(health.database).startsWith('connected')
                      ? 'success'
                      : 'danger'
                  "
                  size="small"
                >
                  {{ health.database || "未知" }}
                </el-tag>
              </span>
            </div>
            <div class="kv-row">
              <span class="kv-label">配置校验</span>
              <span class="kv-value">
                <el-tag
                  :type="
                    health.configuration &&
                    String(health.configuration).startsWith('valid')
                      ? 'success'
                      : 'warning'
                  "
                  size="small"
                >
                  {{ health.configuration || "未知" }}
                </el-tag>
              </span>
            </div>
            <div class="kv-row">
              <span class="kv-label">服务版本</span>
              <span class="kv-value">{{ health.version || "-" }}</span>
            </div>
          </el-card>
        </el-col>

        <el-col :md="8" :sm="24">
          <el-card shadow="never" class="info-card">
            <div class="card-title">网络与抓包</div>
            <div class="kv-row">
              <span class="kv-label">监听地址</span>
              <span class="kv-value">{{ config.host || '-' }}:{{ config.port || '-' }}</span>
            </div>
            <div class="kv-row">
              <span class="kv-label">抓包网卡</span>
              <span class="kv-value">{{
                config.network_interface ? config.network_interface : "未配置"
              }}</span>
            </div>
            <div class="kv-row">
              <span class="kv-label">数据库配置</span>
              <span class="kv-value">
                <el-tag
                  :type="config.database_configured ? 'success' : 'info'"
                  size="small"
                >
                  {{ config.database_configured ? "已配置" : "未配置" }}
                </el-tag>
              </span>
            </div>
            <div class="kv-row">
              <span class="kv-label">日志级别</span>
              <span class="kv-value">{{ config.log_level || "-" }}</span>
            </div>
          </el-card>
        </el-col>

        <el-col :md="8" :sm="24">
          <el-card shadow="never" class="info-card">
            <div class="card-title">系统状态</div>
            <div class="kv-row">
              <span class="kv-label">嗅探器</span>
              <span class="kv-value">
                <el-tag
                  :type="systemStatus.sniffer_active ? 'success' : 'info'"
                  size="small"
                >
                  {{ systemStatus.sniffer_active ? "活跃" : "停止" }}
                </el-tag>
              </span>
            </div>
            <div class="kv-row">
              <span class="kv-label">关联监控</span>
              <span class="kv-value">
                <el-tag
                  :type="
                    systemStatus.correlation_monitor_active ? 'success' : 'info'
                  "
                  size="small"
                >
                  {{
                    systemStatus.correlation_monitor_active ? "活跃" : "停止"
                  }}
                </el-tag>
              </span>
            </div>
            <div class="control-row">
              <div class="switch-item">
                <span class="switch-label">抓包控制</span>
                <el-switch
                  v-model="snifferRunning"
                  :loading="snifferLoading"
                  @change="toggleSniffer"
                  active-text="启动"
                  inactive-text="停止"
                  :active-value="true"
                  :inactive-value="false"
                />
              </div>
            </div>
          </el-card>
        </el-col>
      </el-row>
    </el-card>
  </div>
</template>

<script>
import { ref, reactive, computed, onMounted } from "vue";
import { Monitor, Refresh } from "@element-plus/icons-vue";
import { ElMessage } from "element-plus";

export default {
  components: { Monitor, Refresh },
  setup() {
    const loading = ref(false);
    const health = reactive({});
    const config = reactive({
      host: "",
      port: "",
      network_interface: "",
      log_level: "",
      database_configured: false,
    });
    const totals = reactive({
      alerts: 0,
      rules: 0,
      enabledRules: 0,
    });
    const loopInfo = ref("默认");
    const systemStatus = reactive({
      sniffer_active: false,
      correlation_monitor_active: false,
    });
    const snifferRunning = ref(false);
    const snifferLoading = ref(false);

    async function fetchHealth() {
      try {
        const res = await fetch("/health");
        if (res.ok) {
          const j = await res.json();
          Object.assign(health, j || {});
        } else {
          health.status = "unreachable";
          health.database = "request failed";
          health.configuration = "-";
        }
      } catch (e) {
        health.status = "unreachable";
        health.database = "network error";
        health.configuration = "-";
      }
    }

    async function fetchConfig() {
      try {
        const res = await fetch("/config");
        if (res.ok) {
          const j = await res.json();
          config.host = j.host != null ? String(j.host) : "0.0.0.0";
          config.port = j.port != null ? Number(j.port) : 8000;
          config.network_interface = (j.network_interface != null && String(j.network_interface).trim()) ? String(j.network_interface).trim() : "";
          config.log_level = j.log_level != null ? String(j.log_level) : "";
          config.database_configured = !!j.database_configured;
        }
      } catch (e) {
        config.host = "-";
        config.port = "-";
        config.network_interface = "";
      }
    }

    async function fetchTotals() {
      try {
        const a = await fetch("/api/alerts/count");
        if (a.ok) {
          const j = await a.json();
          totals.alerts = typeof j.total === "number" ? j.total : 0;
        }
      } catch (e) {
        // ignore
      }

      try {
        const r = await fetch("/api/rules/");
        if (r.ok) {
          const list = await r.json();
          if (Array.isArray(list)) {
            totals.rules = list.length;
            totals.enabledRules = list.filter((x) => x.enabled).length;
          } else if (list && Array.isArray(list.rules)) {
            totals.rules = list.rules.length;
            totals.enabledRules = list.rules.filter((x) => x.enabled).length;
          }
        }
      } catch (e) {
        // ignore
      }
    }

    async function fetchSystemStatus() {
      try {
        const res = await fetch("/api/system/status");
        if (res.ok) {
          const status = await res.json();
          Object.assign(systemStatus, status);
          snifferRunning.value = status.sniffer_active;
        }
      } catch (e) {
        console.error("Failed to fetch system status:", e);
      }
    }

    async function toggleSniffer(value) {
      // 防止重复点击
      if (snifferLoading.value) {
        return;
      }

      snifferLoading.value = true;
      try {
        const endpoint = value
          ? "/api/system/sniffer/start"
          : "/api/system/sniffer/stop";
        const res = await fetch(endpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
        });

        if (res.ok) {
          const result = await res.json();
          console.log(result.message || "操作成功");
          // 重新获取状态
          await fetchSystemStatus();
        } else {
          const error = await res.json();
          console.error(error.detail || "操作失败");
          // 恢复开关状态
          snifferRunning.value = !value;
          ElMessage.error(error.detail || "操作失败");
        }
      } catch (e) {
        console.error("Failed to toggle sniffer:", e);
        ElMessage.error("操作失败");
        // 恢复开关状态
        snifferRunning.value = !value;
      } finally {
        snifferLoading.value = false;
      }
    }

    async function reload() {
      loading.value = true;
      await Promise.all([
        fetchHealth(),
        fetchConfig(),
        fetchTotals(),
        fetchSystemStatus(),
      ]);
      loading.value = false;
    }

    const healthStatusText = computed(() => {
      const s = health.status;
      if (!s) return "加载中...";
      if (s === "healthy") return "正常";
      if (s === "degraded") return "降级";
      if (s === "unhealthy") return "异常";
      if (s === "unreachable") return "不可达";
      return String(s);
    });

    const healthTagType = computed(() => {
      const s = health.status;
      if (s === "healthy") return "success";
      if (s === "degraded") return "warning";
      if (s === "unreachable" || s === "unhealthy") return "danger";
      return "info";
    });

    onMounted(() => {
      reload();
    });

    return {
      loading,
      health,
      config,
      totals,
      loopInfo,
      systemStatus,
      snifferRunning,
      snifferLoading,
      healthStatusText,
      healthTagType,
      reload,
      toggleSniffer,
    };
  },
};
</script>

<style scoped>
.system-status {
  width: 100%;
}
.status-card {
  border: none;
  border-radius: 12px;
}
.header-wrapper {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.header-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 18px;
  font-weight: 600;
  color: #303133;
}
.title-icon {
  color: #409eff;
}
.header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}
.info-card {
  border-radius: 10px;
  min-height: 180px;
}
.card-title {
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 10px;
  color: #303133;
}
.kv-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 6px;
  font-size: 13px;
}
.kv-label {
  color: #909399;
}
.kv-value {
  color: #303133;
  font-weight: 500;
}
.kv-value.strong {
  font-size: 18px;
  font-weight: 700;
}
.control-row {
  margin-top: 15px;
  display: flex;
  justify-content: center;
}
.switch-group {
  display: flex;
  flex-direction: column;
  gap: 12px;
  width: 100%;
}
.switch-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.switch-label {
  font-size: 13px;
  color: #909399;
  font-weight: 500;
}
@media (max-width: 768px) {
  .status-card {
    margin-top: 10px;
  }
}
</style>
