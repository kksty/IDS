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
          <div class="line1">
            <span class="ts">[{{ fmtFull(item.timestamp) }}]</span>
            <span class="rel">({{ fmtRelative(item.timestamp) }})</span>
            <span class="proto">{{ item.protocol }}</span>
            <span class="summary">{{ item.packet_summary }}</span>
          </div>

          <div class="line2">
            <span class="ips"
              >{{ item.src_ip || "-" }} → {{ item.dst_ip || "-" }}</span
            >
            <span class="rule">Rule: {{ item.match_rule || "-" }}</span>
          </div>

          <div class="line3" :class="{ expanded: isExpanded(item._local_id) }">
            <div class="payload-head">
              <strong class="payload-label">payload：</strong>
              <div class="actions">
                <button
                  class="action-btn"
                  @click.stop="copyPayload(item)"
                  title="复制"
                >
                  📋
                </button>
                <button
                  class="action-btn"
                  @click.stop="toggleExpand(item._local_id)"
                  title="展开/收起"
                >
                  🔍
                </button>
              </div>
            </div>

            <div class="payload-body">
              <span v-if="!isExpanded(item._local_id)">{{
                truncateOneLine(item.match_text || item.payload_preview || "-")
              }}</span>
              <pre v-else class="expanded-pre">{{
                item.match_text || item.payload_preview || "-"
              }}</pre>
            </div>
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
    const expanded = reactive({});
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

    function isExpanded(key) {
      return !!expanded[key];
    }

    function toggleExpand(key) {
      expanded[key] = !expanded[key];
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

    function onAlert(e) {
      const a = Object.assign({}, e.detail || {});
      if (!a.timestamp) a.timestamp = new Date().toISOString();
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
              protocol: "DB",
              packet_summary: r.payload_preview || "",
              match_rule: r.rule_id,
              match_text: r.match_text,
              payload_preview: r.payload_preview,
              src_ip: r.src_ip,
              dst_ip: r.dst_ip,
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
      isExpanded,
      toggleExpand,
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
  background: #fff;
  padding: 16px;
  border-radius: 8px;
  box-shadow: 0 2px 6px rgba(16, 24, 40, 0.04);
  border: 1px solid rgba(0, 0, 0, 0.04);
}
.line1 {
  font-weight: 700;
  font-size: 14px;
}
.ts {
  color: #6b7280;
  margin-right: 10px;
}
.proto {
  color: #0ea5e9;
  margin-right: 10px;
}
.summary {
  color: #111;
  font-size: 15px;
}
.line2 {
  font-size: 13px;
  color: #6b7280;
  margin-top: 8px;
}
.rule {
  color: #b7791f;
  margin-left: 12px;
}
.line3 {
  margin-top: 10px;
  color: #374151;
  background: #fafafa;
  padding: 10px;
  border-radius: 8px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.line3.expanded {
  white-space: normal;
}
.expanded-pre {
  margin: 0;
  white-space: pre-wrap;
  font-family: Menlo, Monaco, monospace;
}
.payload-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.actions {
  display: flex;
  gap: 8px;
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
  z-index: 9999;
  margin: 0;
  border-radius: 8px;
}
.is-fullscreen .log {
  height: calc(100vh - 140px);
}
</style>
