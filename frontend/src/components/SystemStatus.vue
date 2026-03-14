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
                <el-tag :type="healthTagType" size="small">
                  {{ healthStatusText }}
                </el-tag>
              </span>
            </div>
            <div class="kv-row">
              <span class="kv-label">数据库</span>
              <span class="kv-value">
                <el-tag
                  :type="
                    health.database &&
                    String(health.database).startsWith('connected')
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
              <span class="kv-label">后端地址</span>
              <span class="kv-value"
                >{{ config.host || "-" }}:{{ config.port || "-" }}</span
              >
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
            <div class="kv-row">
              <span class="kv-label">行为分析</span>
              <span class="kv-value">
                <el-tag
                  :type="systemStatus.behavior_enabled ? 'success' : 'info'"
                  size="small"
                >
                  {{ systemStatus.behavior_enabled ? "活跃" : "停止" }}
                </el-tag>
              </span>
            </div>
            <div class="control-row">
              <div class="switch-group">
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
                <div class="switch-item">
                  <span class="switch-label">行为分析</span>
                  <el-switch
                    v-model="behaviorRunning"
                    :loading="behaviorLoading"
                    @change="toggleBehavior"
                    active-text="开启"
                    inactive-text="关闭"
                    :active-value="true"
                    :inactive-value="false"
                  />
                </div>
              </div>
            </div>
          </el-card>
        </el-col>
      </el-row>

      <el-card shadow="never" class="info-card pcap-card">
        <div class="card-title">离线 PCAP 分析</div>
        <div class="pcap-form">
          <el-input
            v-model="pcapPath"
            placeholder="PCAP 文件路径（服务器本地路径）"
            class="pcap-input"
          />
          <el-input
            v-model.number="pcapMaxPackets"
            type="number"
            placeholder="最大包数（可选）"
            class="pcap-input"
          />
          <el-button type="primary" :loading="pcapLoading" @click="analyzePcap">
            开始分析
          </el-button>
          <el-button
            v-if="pcapJobId && pcapRunning"
            type="danger"
            :loading="pcapStopLoading"
            @click="stopPcap"
          >
            停止
          </el-button>
        </div>
        <div class="pcap-hint">
          说明：这里填写的是服务器本地路径；离线分析会复用规则引擎并推送告警。
        </div>
        <div v-if="pcapJobId" class="pcap-status">
          <div class="pcap-status-row">状态：{{ pcapStatusText }}</div>
          <div class="pcap-status-row">
            已处理：{{ pcapProcessed.toLocaleString() }} 包
            <span class="pcap-sep">|</span>
            速率：{{ pcapRateText }} pkt/s
          </div>
          <el-progress
            :percentage="pcapProgressPercent"
            :indeterminate="pcapRunning"
            :status="pcapProgressStatus"
          />
        </div>
      </el-card>
    </el-card>
  </div>
</template>

<script>
import { ref, reactive, computed, onMounted, onBeforeUnmount } from "vue";
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
      behavior_enabled: true,
    });
    const snifferRunning = ref(false);
    const snifferLoading = ref(false);
    const behaviorRunning = ref(true);
    const behaviorLoading = ref(false);
    const pcapPath = ref("");
    const pcapMaxPackets = ref(null);
    const pcapLoading = ref(false);
    const pcapStopLoading = ref(false);
    const pcapJobId = ref("");
    const pcapStatus = ref("");
    const pcapProcessed = ref(0);
    const pcapRate = ref(0);
    let pcapPollTimer = null;

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
          config.network_interface =
            j.network_interface != null && String(j.network_interface).trim()
              ? String(j.network_interface).trim()
              : "";
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
          behaviorRunning.value = !!status.behavior_enabled;
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

    async function toggleBehavior(value) {
      if (behaviorLoading.value) return;
      behaviorLoading.value = true;
      try {
        const endpoint = value
          ? "/api/system/behavior/start"
          : "/api/system/behavior/stop";
        const res = await fetch(endpoint, { method: "POST" });
        if (res.ok) {
          await fetchSystemStatus();
        } else {
          const error = await res.json().catch(() => ({}));
          behaviorRunning.value = !value;
          ElMessage.error(error.detail || "操作失败");
        }
      } catch (e) {
        behaviorRunning.value = !value;
        ElMessage.error("操作失败");
      } finally {
        behaviorLoading.value = false;
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

    async function analyzePcap() {
      if (!pcapPath.value || !String(pcapPath.value).trim()) {
        ElMessage.warning("请填写 PCAP 文件路径");
        return;
      }
      if (pcapLoading.value) return;
      pcapLoading.value = true;
      try {
        const res = await fetch("/api/system/pcap/analyze", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            path: String(pcapPath.value).trim(),
            max_packets:
              pcapMaxPackets.value === null || pcapMaxPackets.value === ""
                ? null
                : Number(pcapMaxPackets.value),
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          ElMessage.error(data.detail || "PCAP 分析失败");
          return;
        }
        const jobId = data.job_id || "";
        if (!jobId) {
          ElMessage.error("PCAP 任务启动失败");
          return;
        }
        pcapJobId.value = jobId;
        localStorage.setItem("pcap_job_id", jobId);
        pcapStatus.value = "running";
        pcapProcessed.value = 0;
        pcapRate.value = 0;
        startPcapPolling(jobId);
        ElMessage.success("PCAP 分析已启动");
      } catch (e) {
        ElMessage.error("PCAP 分析失败");
      } finally {
        pcapLoading.value = false;
      }
    }

    async function fetchPcapStatus(jobId) {
      try {
        const res = await fetch(`/api/system/pcap/status/${jobId}`);
        if (!res.ok) {
          return null;
        }
        return await res.json();
      } catch (e) {
        return null;
      }
    }

    function stopPcapPolling() {
      if (pcapPollTimer) {
        clearInterval(pcapPollTimer);
        pcapPollTimer = null;
      }
    }

    async function startPcapPolling(jobId) {
      stopPcapPolling();
      const update = async () => {
        const status = await fetchPcapStatus(jobId);
        if (!status) {
          return;
        }
        pcapStatus.value = status.status || "unknown";
        pcapProcessed.value = Number(status.processed || 0);
        pcapRate.value = Number(status.rate || 0);
        if (["completed", "failed", "stopped"].includes(pcapStatus.value)) {
          stopPcapPolling();
          localStorage.removeItem("pcap_job_id");
        }
      };
      await update();
      pcapPollTimer = setInterval(update, 2000);
    }

    async function stopPcap() {
      if (!pcapJobId.value || pcapStopLoading.value) return;
      pcapStopLoading.value = true;
      try {
        const res = await fetch(`/api/system/pcap/stop/${pcapJobId.value}`, {
          method: "POST",
        });
        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          ElMessage.error(data.detail || "停止失败");
          return;
        }
        ElMessage.success("已请求停止");
      } catch (e) {
        ElMessage.error("停止失败");
      } finally {
        pcapStopLoading.value = false;
      }
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

    const pcapRunning = computed(() => pcapStatus.value === "running");

    const pcapStatusText = computed(() => {
      const s = pcapStatus.value;
      if (!s) return "未开始";
      if (s === "running") return "分析中";
      if (s === "completed") return "已完成";
      if (s === "stopped") return "已停止";
      if (s === "failed") return "失败";
      return String(s);
    });

    const pcapProgressPercent = computed(() => {
      if (pcapStatus.value === "completed") return 100;
      return 0;
    });

    const pcapProgressStatus = computed(() => {
      if (pcapStatus.value === "failed") return "exception";
      if (pcapStatus.value === "completed") return "success";
      return "";
    });

    const pcapRateText = computed(() => {
      const v = Number(pcapRate.value || 0);
      return v.toFixed(1);
    });

    onMounted(() => {
      reload();
      const lastJobId = localStorage.getItem("pcap_job_id");
      if (lastJobId) {
        pcapJobId.value = lastJobId;
        startPcapPolling(lastJobId);
      }
    });

    onBeforeUnmount(() => {
      stopPcapPolling();
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
      behaviorRunning,
      behaviorLoading,
      pcapPath,
      pcapMaxPackets,
      pcapLoading,
      pcapStopLoading,
      pcapJobId,
      pcapStatusText,
      pcapProcessed,
      pcapRateText,
      pcapProgressPercent,
      pcapProgressStatus,
      pcapRunning,
      healthStatusText,
      healthTagType,
      reload,
      toggleSniffer,
      toggleBehavior,
      analyzePcap,
      stopPcap,
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
.pcap-card {
  margin-top: 16px;
  min-height: 0;
}
.pcap-form {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
}
.pcap-input {
  flex: 1 1 240px;
  min-width: 220px;
}
.pcap-hint {
  margin-top: 8px;
  font-size: 12px;
  color: #909399;
}
.pcap-status {
  margin-top: 12px;
}
.pcap-status-row {
  font-size: 12px;
  color: #606266;
  margin-bottom: 6px;
}
.pcap-sep {
  margin: 0 6px;
  color: #c0c4cc;
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
