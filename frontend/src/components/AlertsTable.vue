<template>
  <div class="alerts-table">
    <el-card class="table-card" shadow="hover">
      <div class="toolbar">
        <el-select
          v-model="selectedRule"
          placeholder="规则筛选"
          clearable
          class="toolbar-select rule-select"
        >
          <el-option
            v-for="r in ruleOptions"
            :key="r.rule_id"
            :label="r.rule_id + (r.name ? ' · ' + r.name : '')"
            :value="r.rule_id"
          />
        </el-select>
        <el-select
          v-model="selectedSeverity"
          placeholder="严重度"
          clearable
          class="toolbar-select"
        >
          <el-option label="高" value="high" />
          <el-option label="中" value="medium" />
          <el-option label="低" value="low" />
        </el-select>
        <el-select
          v-model="alertType"
          placeholder="告警类型"
          clearable
          class="toolbar-select"
        >
          <el-option label="所有类型" value="all" />
          <el-option label="规则告警" value="rule" />
          <el-option label="行为告警" value="behavior" />
          <el-option label="关联告警" value="correlation" />
        </el-select>
        <el-input
          v-model="srcIp"
          placeholder="源 IP"
          clearable
          class="toolbar-input"
        >
          <template #prefix>
            <el-icon><Location /></el-icon>
          </template>
        </el-input>
        <el-input
          v-model="q"
          placeholder="搜索 payload / rule"
          clearable
          class="toolbar-input search-input"
        >
          <template #prefix>
            <el-icon><Search /></el-icon>
          </template>
        </el-input>
        <el-button type="primary" icon="Refresh" @click="reload"
          >刷新</el-button
        >
        <el-button type="danger" icon="Delete" @click="confirmClearAll"
          >清空</el-button
        >
        <el-button plain icon="Upload" @click="exportFiltered">导出</el-button>
      </div>

      <div class="table-wrapper">
        <el-table
          :data="paged"
          class="data-table"
          stripe
          size="small"
          empty-text="暂无告警数据"
          :row-key="(row) => row.id"
        >
          <el-table-column prop="created_at" label="时间" min-width="160">
            <template #default="scope">{{
              fmtFull(scope.row.created_at)
            }}</template>
          </el-table-column>
          <el-table-column prop="src_ip" label="源 IP" min-width="120">
            <template #default="scope">{{ scope.row.src_ip || "-" }}</template>
          </el-table-column>
          <el-table-column prop="dst_ip" label="目的 IP" min-width="120">
            <template #default="scope">{{ scope.row.dst_ip || "-" }}</template>
          </el-table-column>
          <el-table-column prop="rule_id" label="规则名称" min-width="200">
            <template #default="scope">
              <span
                class="rule-badge"
                :class="badgeClass(getRuleId(scope.row))"
                >{{ badgeText(getRuleId(scope.row)) }}</span
              >
              <span class="rule-id-text">{{
                getRuleId(scope.row) || "-"
              }}</span>
            </template>
          </el-table-column>
          <el-table-column
            prop="match_text"
            label="规则"
            min-width="220"
            show-overflow-tooltip
          >
            <template #default="scope">{{
              truncateOneLine(scope.row.match_text)
            }}</template>
          </el-table-column>
          <el-table-column
            prop="payload_preview"
            label="攻击上下文"
            min-width="200"
            show-overflow-tooltip
          >
            <template #default="scope">{{
              truncateOneLine(scope.row.payload_preview)
            }}</template>
          </el-table-column>
          <el-table-column label="操作" width="160" align="center">
            <template #default="scope">
              <el-button
                type="primary"
                link
                size="small"
                @click="openDetail(scope.row)"
                >详情</el-button
              >
              <el-button
                type="primary"
                link
                size="small"
                @click="copyPreview(scope.row)"
                >复制</el-button
              >
              <el-button
                type="danger"
                link
                size="small"
                @click="confirmDelete(scope.row)"
                >删除</el-button
              >
            </template>
          </el-table-column>
        </el-table>
      </div>

      <el-dialog v-model="detailVisible" title="告警详情" width="720px">
        <div v-if="detailRow" class="detail-grid">
          <div class="detail-item">
            <span class="detail-label">时间</span>
            <span class="detail-value">{{
              fmtFull(detailRow.created_at)
            }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">源 IP</span>
            <span class="detail-value">{{ detailRow.src_ip || "-" }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">目的 IP</span>
            <span class="detail-value">{{ detailRow.dst_ip || "-" }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">规则 ID</span>
            <span class="detail-value">{{ getRuleId(detailRow) || "-" }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">告警类型</span>
            <span class="detail-value">{{
              badgeText(getRuleId(detailRow))
            }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">严重度</span>
            <span class="detail-value">{{
              severityText(severityForAlert(detailRow))
            }}</span>
          </div>
          <div class="detail-item detail-full">
            <span class="detail-label">匹配内容</span>
            <pre class="detail-pre">{{ detailRow.match_text || "-" }}</pre>
          </div>
          <div class="detail-item detail-full">
            <span class="detail-label">攻击上下文</span>
            <pre class="detail-pre">{{ detailRow.payload_preview || "-" }}</pre>
          </div>
        </div>
      </el-dialog>

      <div class="pager">
        <el-pagination
          background
          layout="total, sizes, prev, pager, next, jumper"
          v-model:page-size="pageSize"
          v-model:current-page="page"
          :page-sizes="[10, 20, 50, 100]"
          :total="filtered.length"
        />
      </div>
    </el-card>
  </div>
</template>

<script>
import {
  ref,
  reactive,
  computed,
  watch,
  onMounted,
  onBeforeUnmount,
} from "vue";
import {
  Location,
  Search,
  Refresh,
  Delete,
  Upload,
  CopyDocument,
} from "@element-plus/icons-vue";

export default {
  components: {
    Location,
    Search,
    Refresh,
    Delete,
    Upload,
    CopyDocument,
  },
  setup() {
    const alerts = ref([]);
    const rules = ref([]);
    const ruleMap = reactive({});

    const detailVisible = ref(false);
    const detailRow = ref(null);

    const q = ref("");
    const srcIp = ref("");
    const selectedRule = ref(null);
    const selectedSeverity = ref(null);
    const alertType = ref("all");

    const page = ref(1);
    const pageSize = ref(20);

    // 控制异步加载状态
    let abortController = null;

    function fmtFull(ts) {
      if (!ts) return "";
      try {
        return new Date(ts).toLocaleString();
      } catch (e) {
        return ts;
      }
    }

    function truncateOneLine(s, max = 100) {
      if (!s && s !== 0) return "";
      const t = String(s);
      return t.length > max ? t.slice(0, max) + "…" : t;
    }

    function normalizeRuleId(rid) {
      if (rid === null || rid === undefined) return "";
      return String(rid).trim();
    }

    function getRuleId(row) {
      if (!row) return "";
      return normalizeRuleId(
        row.rule_id || row.match_rule || row.rule || row.ruleId || "",
      );
    }

    function isBehavior(rule_id) {
      return typeof rule_id === "string" && rule_id.startsWith("behavior:");
    }

    function isCorrelation(rule_id) {
      return typeof rule_id === "string" && rule_id.startsWith("correlation:");
    }

    function badgeText(rule_id) {
      if (isBehavior(rule_id)) return "行为";
      if (isCorrelation(rule_id)) return "关联";
      return "规则";
    }

    function badgeClass(rule_id) {
      if (isBehavior(rule_id)) return "behavior";
      if (isCorrelation(rule_id)) return "correlation";
      return "rule";
    }

    function severityForAlert(row) {
      if (!row) return "low";
      const rid = getRuleId(row);
      const r = ruleMap[rid] || ruleMap[rid.toLowerCase()];
      if (r && typeof r.priority === "number") {
        // 规则优先级：1=高, 2=中, 3=低
        if (r.priority <= 1) return "high";
        if (r.priority === 2) return "medium";
        return "low";
      }
      if (row.priority !== undefined && row.priority !== null) {
        const pr = Number(row.priority);
        if (!Number.isNaN(pr)) {
          if (pr <= 1) return "high";
          if (pr === 2) return "medium";
          return "low";
        }
      }
      if (row.severity) {
        const s = String(row.severity).toLowerCase();
        if (s.includes("high")) return "high";
        if (s.includes("medium")) return "medium";
        if (s.includes("low")) return "low";
      }
      if (isBehavior(rid)) {
        if (
          String(rid).includes("high") ||
          String(rid).includes("brute") ||
          String(rid).includes("suspicious")
        )
          return "high";
        if (
          String(rid).includes("medium") ||
          String(rid).includes("port_scan") ||
          String(rid).includes("oversized")
        )
          return "medium";
        return "low";
      }
      return "low";
    }

    function severityText(sev) {
      if (sev === "high") return "高";
      if (sev === "medium") return "中";
      return "低";
    }

    function openDetail(row) {
      detailRow.value = row;
      detailVisible.value = true;
    }

    function tagTextFor(rule_id) {
      // 行为告警：直接从 rule_id/文本映射（后端也会附带 severity，但 DB 列表接口不返��该字段）
      if (isBehavior(rule_id)) {
        // 默认中等，可按需扩展：behavior:high_* => 高
        if (
          String(rule_id).includes("high") ||
          String(rule_id).includes("brute") ||
          String(rule_id).includes("suspicious")
        )
          return "高";
        if (
          String(rule_id).includes("medium") ||
          String(rule_id).includes("port_scan") ||
          String(rule_id).includes("oversized")
        )
          return "中";
        return "低";
      }

      const key = normalizeRuleId(rule_id);
      const r = ruleMap[key] || ruleMap[key.toLowerCase()];
      const pr = r && typeof r.priority === "number" ? r.priority : 3;
      if (pr <= 1) return "高";
      if (pr === 2) return "中";
      return "低";
    }

    function tagTypeFor(rule_id) {
      const t = tagTextFor(rule_id);
      if (t === "高") return "danger";
      if (t === "中") return "warning";
      return "success";
    }

    function copyPreview(row) {
      const txt = row.payload_preview || row.match_text || row.rule_id || "";
      if (navigator.clipboard)
        navigator.clipboard.writeText(txt).catch(() => {});
    }

    function exportFiltered() {
      const rows = filtered.value;
      let csv = "time,src_ip,dst_ip,rule_id,severity,message,summary\n";
      rows.forEach((r) => {
        const sev = tagTextFor(getRuleId(r));
        const msg = (r.match_text || "").replace(/"/g, '""');
        const sum = (r.payload_preview || "").replace(/"/g, '""');
        csv += `${fmtFull(r.created_at)},${r.src_ip || ""},${r.dst_ip || ""},${getRuleId(r)},${sev},"${msg}","${sum}"\n`;
      });
      const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `alerts-filtered.csv`;
      link.click();
    }

    const ruleOptions = computed(() => {
      const seen = new Set();
      const out = [];
      (alerts.value || []).forEach((a) => {
        const rid = normalizeRuleId(getRuleId(a));
        if (!rid || seen.has(rid)) return;
        seen.add(rid);
        const r = ruleMap[rid] || ruleMap[rid.toLowerCase()];
        out.push({ rule_id: rid, name: r ? r.name : "" });
      });
      return out;
    });

    async function deleteAlertById(id) {
      try {
        const res = await fetch(`/api/alerts/${id}`, { method: "DELETE" });
        if (!res.ok) throw new Error("delete failed: " + res.status);
        const j = await res.json();
        if (j.status === "deleted") {
          // remove locally
          alerts.value = alerts.value.filter((a) => a.id !== id);
          // detail dialog removed
        } else {
          console.warn("delete response", j);
        }
      } catch (e) {
        console.error("delete error", e);
      }
    }

    function confirmDelete(row) {
      if (window.confirm(`确认删除告警 ID=${row.id} ?`)) {
        deleteAlertById(row.id);
      }
    }

    async function clearAllAlerts() {
      try {
        const res = await fetch("/api/alerts/", { method: "DELETE" });
        if (!res.ok) throw new Error("clear failed: " + res.status);
        const j = await res.json();
        if (j.status === "cleared") {
          // 清空本地数据
          alerts.value = [];
          alert(`成功清空了 ${j.deleted_count} 条告警记录`);
        } else {
          alert("清空失败: " + (j.message || "未知错误"));
        }
      } catch (e) {
        console.error("clear error", e);
        alert("清空告警失败: " + e.message);
      }
    }

    function confirmClearAll() {
      const count = alerts.value.length;
      if (
        window.confirm(`确认清空所有 ${count} 条告警记录？此操作不可撤销！`)
      ) {
        clearAllAlerts();
      }
    }

    const filtered = computed(() => {
      try {
        // 防御性检查：确保 alerts.value 是数组
        if (!Array.isArray(alerts.value)) {
          console.warn("alerts.value is not an array:", alerts.value);
          return [];
        }
        let arr = alerts.value.slice();

        // 告警类型过滤
        if (alertType.value !== "all") {
          arr = arr.filter((a) => {
            if (alertType.value === "rule")
              return !isBehavior(a.rule_id) && !isCorrelation(a.rule_id);
            if (alertType.value === "behavior") return isBehavior(a.rule_id);
            if (alertType.value === "correlation")
              return isCorrelation(a.rule_id);
            return true;
          });
        }

        if (selectedRule.value)
          arr = arr.filter((a) => getRuleId(a) === selectedRule.value);
        if (srcIp.value)
          arr = arr.filter((a) => (a.src_ip || "").includes(srcIp.value));
        if (q.value) {
          const qq = q.value.toLowerCase();
          arr = arr.filter(
            (a) =>
              (a.payload_preview || a.match_text || "")
                .toLowerCase()
                .includes(qq) ||
              (getRuleId(a) || "").toLowerCase().includes(qq),
          );
        }
        // severity filter: map rule priority -> severity (priority<=2 high, <=4 medium else low)
        if (selectedSeverity.value) {
          arr = arr.filter(
            (a) => selectedSeverity.value === severityForAlert(a),
          );
        }
        return arr;
      } catch (e) {
        console.error("Error in filtered computed:", e);
        return [];
      }
    });

    const paged = computed(() => {
      try {
        const size = pageSize.value || 20;
        const p = page.value || 1;
        const start = (p - 1) * size;
        // 防御性检查：确保 filtered.value 是数组
        if (!Array.isArray(filtered.value)) {
          console.warn("filtered.value is not an array:", filtered.value);
          return [];
        }
        return filtered.value.slice(start, start + size);
      } catch (e) {
        console.error("Error in paged computed:", e);
        return [];
      }
    });

    async function loadData() {
      // 取消前一个加载请求（如果还在进行）
      if (abortController) {
        abortController.abort();
      }
      abortController = new AbortController();
      const signal = abortController.signal;

      try {
        const r1 = await fetch("/api/alerts?limit=2000", { signal });
        if (r1.ok) {
          const data = await r1.json();
          alerts.value = Array.isArray(data)
            ? data.map((row) => ({
                ...row,
                rule_id: normalizeRuleId(
                  row.rule_id || row.match_rule || row.rule || row.ruleId || "",
                ),
              }))
            : [];
        }
      } catch (e) {
        if (e.name !== "AbortError") {
          console.warn("load alerts failed", e);
        }
        alerts.value = [];
      }
      try {
        const r2 = await fetch("/api/rules/", { signal });
        if (r2.ok) {
          const data = await r2.json();
          const list = Array.isArray(data) ? data : data.rules || [];
          rules.value = list;
          rules.value.forEach((x) => {
            const key = normalizeRuleId(x.rule_id);
            ruleMap[key] = x;
            ruleMap[key.toLowerCase()] = x;
          });
        }
      } catch (e) {
        if (e.name !== "AbortError") {
          console.warn("load rules failed", e);
        }
      }
    }

    function reload() {
      loadData();
    }

    // showDetail removed; view action replaced with copy/delete

    watch(pageSize, () => {
      page.value = 1;
    });

    onMounted(() => {
      loadData();
    });

    onBeforeUnmount(() => {
      // 组件卸载时取消所有加载请求
      if (abortController) {
        abortController.abort();
      }
    });

    return {
      alerts,
      rules,
      ruleOptions,
      ruleMap,
      detailVisible,
      detailRow,
      q,
      srcIp,
      selectedRule,
      selectedSeverity,
      page,
      pageSize,
      paged,
      filtered,
      fmtFull,
      truncateOneLine,
      getRuleId,
      badgeText,
      badgeClass,
      severityForAlert,
      severityText,
      openDetail,
      reload,
      // showDetail,
      copyPreview,
      isBehavior,
      tagTextFor,
      tagTypeFor,
      exportFiltered,
      // detail, detailVisible removed
      confirmDelete,
      deleteAlertById,
      confirmClearAll,
      clearAllAlerts,
      alertType,
    };
  },
};
</script>

<style scoped>
.alerts-table {
  width: 100%;
  min-width: 0;
  display: block;
  position: relative;
  z-index: auto;
}
.table-card {
  border-radius: 12px;
  overflow: hidden;
}
.table-card :deep(.el-card__body) {
  overflow: auto;
}
.toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  margin-bottom: 16px;
}
.toolbar-select {
  width: 200px;
  min-width: 140px;
}
.toolbar-select.rule-select {
  width: 200px;
  min-width: 160px;
}
.toolbar-input {
  width: 160px;
  min-width: 120px;
}
.toolbar-input.search-input {
  width: 260px;
  min-width: 200px;
}
.toolbar .el-button {
  display: inline-flex;
  align-items: center;
  flex-shrink: 0;
}
.table-wrapper {
  width: 100%;
  overflow-x: auto;
  overflow-y: auto;
  min-height: 200px;
}
.data-table {
  width: 100%;
  min-width: 900px;
}
.pager {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
  align-items: center;
  gap: 12px;
  position: relative;
  z-index: 1;
}
.rule-badge {
  display: inline-block;
  font-size: 12px;
  padding: 1px 6px;
  border-radius: 10px;
  border: 1px solid;
  line-height: 18px;
  margin-right: 6px;
}
.rule-id-text {
  word-break: break-all;
}
.rule-badge.rule {
  color: #1f6feb;
  border-color: rgba(31, 111, 235, 0.4);
  background: rgba(31, 111, 235, 0.08);
}
.rule-badge.behavior {
  color: #b54708;
  border-color: rgba(181, 71, 8, 0.4);
  background: rgba(181, 71, 8, 0.08);
}
.rule-badge.correlation {
  color: #a21caf;
  border-color: rgba(162, 28, 175, 0.4);
  background: rgba(162, 28, 175, 0.08);
}

.detail-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px 20px;
  padding-top: 4px;
}
.detail-item {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.detail-item.detail-full {
  grid-column: 1 / -1;
}
.detail-label {
  font-size: 12px;
  color: #6b7280;
}
.detail-value {
  font-size: 14px;
  color: #111827;
  word-break: break-all;
}
.detail-pre {
  margin: 0;
  padding: 10px;
  background: #f9fafb;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: Menlo, Monaco, monospace;
}
</style>
