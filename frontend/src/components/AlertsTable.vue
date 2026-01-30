<template>
  <div class="alerts-table">
    <div class="toolbar">
      <el-select
        v-model="selectedRule"
        placeholder="规则筛选"
        clearable
        style="width: 220px"
      >
        <el-option
          v-for="r in rules"
          :key="r.rule_id"
          :label="r.rule_id + (r.name ? ' · ' + r.name : '')"
          :value="r.rule_id"
        />
      </el-select>

      <el-select
        v-model="selectedSeverity"
        placeholder="严重度"
        clearable
        style="width: 140px"
      >
        <el-option label="高" value="high" />
        <el-option label="中" value="medium" />
        <el-option label="低" value="low" />
      </el-select>

      <el-input
        v-model="srcIp"
        placeholder="源 IP 过滤"
        clearable
        style="width: 180px"
      >
        <template #prefix>
          <el-icon><Location /></el-icon>
        </template>
      </el-input>

      <el-input
        v-model="q"
        placeholder="搜索（payload / rule）"
        clearable
        style="width: 320px"
      >
        <template #prefix>
          <el-icon><Search /></el-icon>
        </template>
      </el-input>

      <el-button type="primary" icon="Refresh" @click="reload">刷新</el-button>
      <el-button type="danger" icon="Delete" @click="confirmClearAll"
        >清空所有</el-button
      >
      <el-button plain icon="Upload" @click="exportFiltered">导出</el-button>
    </div>

    <el-table :data="paged" style="width: 100%" stripe size="small">
      <el-table-column prop="created_at" label="时间" width="180">
        <template #default="{ row }">{{ fmtFull(row.created_at) }}</template>
      </el-table-column>
      <el-table-column prop="src_ip" label="源 IP" width="140" />
      <el-table-column prop="dst_ip" label="目的 IP" width="140" />
      <el-table-column prop="rule_id" label="Rule" width="160" />
      <!-- severity column removed per request -->
      <el-table-column prop="payload_preview" label="摘要">
        <template #default="{ row }">{{
          truncateOneLine(row.payload_preview)
        }}</template>
      </el-table-column>

      <el-table-column label="操作" width="160">
        <template #default="{ row }">
          <el-button type="text" size="small" @click="copyPreview(row)">
            <el-icon><CopyDocument /></el-icon>
          </el-button>
          <el-button type="text" size="small" @click="confirmDelete(row)">
            <el-icon><Delete /></el-icon>
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <div
      class="pager"
      style="
        margin-top: 12px;
        display: flex;
        justify-content: flex-end;
        align-items: center;
        gap: 12px;
      "
    >
      <el-pagination
        background
        layout="prev, pager, next"
        :page-size="pageSize"
        :current-page.sync="page"
        :total="filtered.length"
      />
    </div>

    <!-- 详情对话框已移除，查看操作改为复制/删除 -->
  </div>
</template>

<script>
import { ref, reactive, computed, onMounted } from "vue";

export default {
  setup() {
    const alerts = ref([]);
    const rules = ref([]);
    const ruleMap = reactive({});

    const q = ref("");
    const srcIp = ref("");
    const selectedRule = ref(null);
    const selectedSeverity = ref(null);

    const page = ref(1);
    const pageSize = 20;

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

    function tagTextFor(rule_id) {
      const r = ruleMap[rule_id];
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
      const txt = row.payload_preview || row.match_text || "";
      if (navigator.clipboard)
        navigator.clipboard.writeText(txt).catch(() => {});
    }

    function exportFiltered() {
      const rows = filtered.value;
      let csv = "time,src_ip,dst_ip,rule_id,severity,summary\n";
      rows.forEach((r) => {
        const sev = tagTextFor(r.rule_id);
        csv += `${fmtFull(r.created_at)},${r.src_ip || ""},${r.dst_ip || ""},${r.rule_id},${sev},"${(r.payload_preview || r.match_text || "").replace(/"/g, '""')}"\n`;
      });
      const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `alerts-filtered.csv`;
      link.click();
    }

    async function deleteAlertById(id) {
      try {
        const res = await fetch(`/api/alerts/${id}`, { method: "DELETE" });
        if (!res.ok) throw new Error("delete failed: " + res.status);
        const j = await res.json();
        if (j.status === "deleted") {
          // remove locally
          alerts.value = alerts.value.filter((a) => a.id !== id);
          // close dialog if showing
          if (detail.value && detail.value.id === id) {
            detailVisible.value = false;
          }
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
      let arr = alerts.value.slice();
      if (selectedRule.value)
        arr = arr.filter((a) => a.rule_id === selectedRule.value);
      if (srcIp.value)
        arr = arr.filter((a) => (a.src_ip || "").includes(srcIp.value));
      if (q.value) {
        const qq = q.value.toLowerCase();
        arr = arr.filter(
          (a) =>
            (a.payload_preview || a.match_text || "")
              .toLowerCase()
              .includes(qq) || (a.rule_id || "").toLowerCase().includes(qq),
        );
      }
      // severity filter: map rule priority -> severity (priority<=2 high, <=4 medium else low)
      if (selectedSeverity.value) {
        arr = arr.filter((a) => {
          const r = ruleMap[a.rule_id];
          const pr = r && typeof r.priority === "number" ? r.priority : 3;
          // Unified mapping: priority<=1 => high, ==2 => medium, >=3 => low
          let sev = "low";
          if (pr <= 1) sev = "high";
          else if (pr === 2) sev = "medium";
          else sev = "low";
          return selectedSeverity.value === sev;
        });
      }
      return arr;
    });

    const paged = computed(() => {
      const start = (page.value - 1) * pageSize;
      return filtered.value.slice(start, start + pageSize);
    });

    async function loadData() {
      try {
        const r1 = await fetch("/api/alerts?limit=1000");
        if (r1.ok) alerts.value = await r1.json();
      } catch (e) {
        console.warn("load alerts failed", e);
      }
      try {
        const r2 = await fetch("/api/rules");
        if (r2.ok) {
          rules.value = await r2.json();
          rules.value.forEach((x) => (ruleMap[x.rule_id] = x));
        }
      } catch (e) {
        console.warn("load rules failed", e);
      }
    }

    function reload() {
      loadData();
    }

    // showDetail removed; view action replaced with copy/delete

    onMounted(() => {
      loadData();
    });

    return {
      alerts,
      rules,
      ruleMap,
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
      reload,
      // showDetail,
      copyPreview,
      tagTextFor,
      tagTypeFor,
      exportFiltered,
      // detail, detailVisible removed
      confirmDelete,
      deleteAlertById,
      confirmClearAll,
      clearAllAlerts,
    };
  },
};
</script>

<style scoped>
.toolbar {
  display: flex;
  gap: 12px;
  align-items: center;
  margin-bottom: 12px;
}
.detail-pre {
  background: #f7f7f8;
  padding: 12px;
  border-radius: 6px;
  white-space: pre-wrap;
}
.el-table .el-table__row:hover td {
  background: #fbfdff;
}

.toolbar .el-button {
  display: inline-flex;
  align-items: center;
}
</style>
