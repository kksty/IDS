<template>
  <el-card :class="{ 'is-fullscreen': fullScreen }" class="recent-card">
    <div class="header">
      <h3 class="title">最近告警（屏幕视图）</h3>
      <div class="header-meta">
        <div class="hint">最多显示 50 条 · 实时/持久化</div>
        <el-switch
          v-model="fullScreen"
          active-text="全屏"
          inactive-text="窗口"
        ></el-switch>
      </div>
    </div>

    <div ref="logRef" class="log">
      <div class="log-inner">
        <div v-for="item in alerts" :key="item._local_id" class="log-entry">
          <div class="entry-top">
            <div class="entry-left">
              <div class="time-row">
                <span class="ts">{{ fmtFull(item.timestamp) }}</span>
                <span class="rel">{{ fmtRelative(item.timestamp) }}</span>
              </div>
              <div class="badge-row">
                <span class="sev-badge" :class="severityClass(item)">
                  {{ severityText(severityForItem(item)) }}
                </span>
                <span class="type-badge" :class="typeClass(item)">
                  {{ typeText(item) }}
                </span>
                <span class="proto-chip">{{
                  formatProtocol(item.protocol)
                }}</span>
              </div>
            </div>
            <button
              class="action-btn"
              @click.stop="copyPayload(item)"
              title="复制"
            >
              📋
            </button>
          </div>

          <div class="entry-mid">
            <span class="rule-chip">{{ getRuleId(item) || "-" }}</span>
            <span class="ips">
              {{ item.src_ip || "-" }} → {{ item.dst_ip || "-" }}
            </span>
          </div>

          <div class="entry-match">
            <span class="label">规则:</span>
            <span class="value">{{
              truncateOneLine(payloadSummary(item), 180)
            }}</span>
          </div>

          <div v-if="item.packet_summary" class="entry-summary">
            {{ truncateOneLine(item.packet_summary, 180) }}
          </div>
        </div>
      </div>
    </div>
  </el-card>
</template>

<script>
import bus from "../ws";
import { reactive, onMounted, onBeforeUnmount, ref, nextTick } from "vue";

export default {
  setup() {
    const alerts = reactive([]);
    const logRef = ref(null);
    const fullScreen = ref(false);
    let id = 1;

    function scrollToTop() {
      nextTick(() => {
        try {
          if (logRef.value) logRef.value.scrollTop = 0;
        } catch (e) {}
      });
    }

    function fmtFull(ts) {
      if (!ts) return "";
      try {
        const d = new Date(ts);
        if (isNaN(d.getTime())) return ts;
        return d.toLocaleString();
      } catch (e) {
        return ts;
      }
    }

    function fmtRelative(ts) {
      if (!ts) return "";
      let d = null;
      try {
        d = new Date(ts);
      } catch (e) {
        return ts;
      }
      if (isNaN(d.getTime())) return ts;
      const diff = Date.now() - d.getTime();
      if (diff < 1000 * 60) return Math.floor(diff / 1000) + "秒前";
      if (diff < 1000 * 60 * 60)
        return Math.floor(diff / (1000 * 60)) + "分钟前";
      if (diff < 1000 * 60 * 60 * 24)
        return Math.floor(diff / (1000 * 60 * 60)) + "小时前";
      return d.toLocaleString();
    }

    function truncateOneLine(s, max = 120) {
      if (!s && s !== 0) return "";
      const str = String(s);
      if (str.length > max) return str.slice(0, max) + "…";
      return str;
    }

    function normalizeRuleId(rid) {
      if (rid === null || rid === undefined) return "";
      return String(rid).trim();
    }

    function getRuleId(item) {
      if (!item) return "";
      return normalizeRuleId(
        item.match_rule || item.rule_id || item.rule || item.ruleId || "",
      );
    }

    function severityForItem(item) {
      if (!item) return "low";
      if (item.severity) {
        const s = String(item.severity).toLowerCase();
        if (s.includes("high")) return "high";
        if (s.includes("medium")) return "medium";
        if (s.includes("low")) return "low";
      }
      if (item.priority !== undefined && item.priority !== null) {
        const pr = Number(item.priority);
        if (!Number.isNaN(pr)) {
          if (pr <= 1) return "high";
          if (pr === 2) return "medium";
          return "low";
        }
      }
      const rid = getRuleId(item);
      if (rid.startsWith("behavior:")) {
        if (
          rid.includes("high") ||
          rid.includes("brute") ||
          rid.includes("suspicious")
        )
          return "high";
        if (
          rid.includes("medium") ||
          rid.includes("port_scan") ||
          rid.includes("oversized")
        )
          return "medium";
      }
      return "low";
    }

    function severityText(sev) {
      if (sev === "high") return "高";
      if (sev === "medium") return "中";
      return "低";
    }

    function severityClass(item) {
      const sev = severityForItem(item);
      if (sev === "high") return "sev-high";
      if (sev === "medium") return "sev-medium";
      return "sev-low";
    }

    function typeText(item) {
      const rid = getRuleId(item);
      if (rid.startsWith("behavior:")) return "行为";
      if (rid.startsWith("correlation:")) return "关联";
      return "规则";
    }

    function typeClass(item) {
      const rid = getRuleId(item);
      if (rid.startsWith("behavior:")) return "type-behavior";
      if (rid.startsWith("correlation:")) return "type-correlation";
      return "type-rule";
    }

    function formatProtocol(p) {
      if (!p) return "-";
      return String(p).trim().toUpperCase();
    }

    function copyPayload(item) {
      const text = item.match_text || item.payload_preview || "";
      try {
        navigator.clipboard.writeText(text);
      } catch (e) {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try {
          document.execCommand("copy");
        } catch (err) {}
        document.body.removeChild(ta);
      }
    }

    function getPayloadText(item) {
      if (!item) return "";
      return item.match_text || item.payload_preview || "-";
    }

    function splitPayload(text) {
      const s = String(text || "");
      const idx = s.indexOf(" | ");
      if (idx === -1) return { summary: s, detailsRaw: "" };
      const summary = s.slice(0, idx).trim();
      const detailsRaw = s.slice(idx + 3).trim();
      if (!detailsRaw.startsWith("{") && !detailsRaw.startsWith("[")) {
        return { summary: s, detailsRaw: "" };
      }
      return { summary, detailsRaw };
    }

    function payloadSummary(item) {
      return splitPayload(getPayloadText(item)).summary || "-";
    }

    function payloadDetailsRaw(item) {
      return splitPayload(getPayloadText(item)).detailsRaw || "";
    }

    function payloadDetailsPretty(item) {
      const raw = payloadDetailsRaw(item);
      if (!raw) return "";
      try {
        const obj = JSON.parse(raw);
        return JSON.stringify(obj, null, 2);
      } catch (e) {
        return raw;
      }
    }

    function onAlert(e) {
      const a = Object.assign({}, e.detail || {});
      if (!a.timestamp) a.timestamp = new Date().toISOString();
      a.match_rule = normalizeRuleId(a.match_rule || a.rule_id || "");
      a._local_id = id++;
      alerts.unshift(a);
      if (alerts.length > 50) alerts.pop();
      scrollToTop();
    }

    onMounted(async () => {
      bus.addEventListener("alert", onAlert);
      try {
        const res = await fetch("/api/alerts?limit=50");
        if (res.ok) {
          const rows = await res.json();
          for (const r of rows.reverse()) {
            const item = {
              timestamp: r.created_at || "",
              protocol: " DB",
              packet_summary: r.payload_preview || "",
              match_rule: normalizeRuleId(r.rule_id),
              match_text: r.match_text,
              payload_preview: r.payload_preview,
              src_ip: r.src_ip,
              dst_ip: r.dst_ip,
              priority: r.priority,
              severity: r.severity,
              _local_id: id++,
            };
            alerts.unshift(item);
            if (alerts.length > 50) alerts.pop();
          }
          scrollToTop();
        }
      } catch (err) {
        console.warn("failed to load recent alerts", err);
      }
    });

    onBeforeUnmount(() => bus.removeEventListener("alert", onAlert));

    return {
      alerts,
      logRef,
      fullScreen,
      fmtFull,
      fmtRelative,
      truncateOneLine,
      getRuleId,
      severityForItem,
      severityText,
      severityClass,
      typeText,
      typeClass,
      formatProtocol,
      getPayloadText,
      payloadSummary,
      payloadDetailsRaw,
      payloadDetailsPretty,
      copyPayload,
    };
  },
};
</script>

<style scoped>
.recent-card {
  margin-top: 12px;
}
.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}
.title {
  margin: 0;
  font-size: 18px;
  color: #111;
}
.header-meta {
  display: flex;
  align-items: center;
  gap: 12px;
}
.hint {
  font-size: 12px;
  color: #666;
}
.log {
  background: transparent;
  padding: 0;
  height: 640px;
  overflow-y: auto;
}
.log-inner {
  display: flex;
  flex-direction: column;
  gap: 18px;
  padding: 20px;
  background: #fff;
  border-radius: 10px;
  box-shadow: 0 4px 12px rgba(16, 24, 40, 0.06);
}
.log-entry {
  background: linear-gradient(180deg, #ffffff 0%, #fbfbff 100%);
  padding: 16px;
  border-radius: 10px;
  box-shadow: 0 6px 16px rgba(16, 24, 40, 0.06);
  border: 1px solid rgba(15, 23, 42, 0.06);
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.entry-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.entry-left {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.time-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 600;
  font-size: 13px;
  color: #111827;
}
.ts {
  color: #6b7280;
}
.rel {
  color: #9ca3af;
  font-weight: 500;
}
.badge-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.proto-chip {
  font-size: 12px;
  color: #0ea5e9;
  background: #e0f2fe;
  border: 1px solid #bae6fd;
  padding: 2px 8px;
  border-radius: 999px;
}
.sev-badge,
.type-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 12px;
  padding: 2px 8px;
  border-radius: 999px;
  border: 1px solid transparent;
  margin-right: 8px;
  line-height: 16px;
}
.sev-badge.sev-high {
  color: #b42318;
  background: #fee4e2;
  border-color: #fecdca;
}
.sev-badge.sev-medium {
  color: #b54708;
  background: #ffead5;
  border-color: #fed7aa;
}
.sev-badge.sev-low {
  color: #027a48;
  background: #d1fadf;
  border-color: #a6f4c5;
}
.type-badge.type-rule {
  color: #1f6feb;
  background: rgba(31, 111, 235, 0.1);
  border-color: rgba(31, 111, 235, 0.3);
}
.type-badge.type-behavior {
  color: #7a2e0e;
  background: #ffe7d6;
  border-color: #f9dbc0;
}
.type-badge.type-correlation {
  color: #6b21a8;
  background: #f3e8ff;
  border-color: #e9d5ff;
}
.entry-mid {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.rule-chip {
  font-size: 12px;
  color: #1f2937;
  background: #f3f4f6;
  border: 1px solid #e5e7eb;
  padding: 2px 8px;
  border-radius: 999px;
}
.ips {
  font-size: 13px;
  color: #6b7280;
}
.entry-match {
  display: flex;
  align-items: baseline;
  gap: 8px;
  font-size: 13px;
  color: #374151;
}
.entry-match .label {
  color: #64748b;
  font-weight: 600;
}
.entry-summary {
  font-size: 13px;
  color: #475569;
  background: #f8fafc;
  border: 1px dashed #e2e8f0;
  padding: 8px 10px;
  border-radius: 8px;
}
.action-btn {
  background: transparent;
  border: none;
  padding: 6px 8px;
  border-radius: 6px;
  cursor: pointer;
  color: #374151;
  font-size: 14px;
}
.action-btn:hover {
  background: rgba(0, 0, 0, 0.04);
}
.is-fullscreen {
  position: fixed;
  top: 12px;
  left: 12px;
  right: 12px;
  bottom: 12px;
  z-index: 12000; /* 确保全屏时不会被顶部导航遮挡，方便点击切换回窗口模式 */
  margin: 0;
  border-radius: 8px;
}
.is-fullscreen .log {
  height: calc(100vh - 140px);
}
</style>
