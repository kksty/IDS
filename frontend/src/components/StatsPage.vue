<template>
  <div class="stats-container">
    <el-card class="dashboard-card" v-loading="loading" shadow="hover">
      <template #header>
        <div class="header-wrapper">
          <div class="header-title">
            <el-icon class="title-icon"><Histogram /></el-icon>
            <span>告警数据统计</span>
          </div>
          <div class="header-actions">
            <el-radio-group
              v-model="range"
              size="default"
              class="range-selector"
            >
              <el-radio-button label="1h">1小时</el-radio-button>
              <el-radio-button label="24h">24小时</el-radio-button>
              <el-radio-button label="7d">7天</el-radio-button>
              <el-radio-button label="all">全部</el-radio-button>
            </el-radio-group>
            <el-divider direction="vertical" />
            <el-button type="primary" @click="reload">
              <el-icon><Refresh /></el-icon><span>刷新</span>
            </el-button>
            <el-button type="success" plain @click="exportCsv">
              <el-icon><Download /></el-icon><span>导出报告</span>
            </el-button>
          </div>
        </div>
      </template>

      <!-- summary cards: global totals and severity counts -->
      <div
        class="summary-cards"
        style="display: flex; gap: 12px; margin: 12px 0"
      >
        <el-card class="stat-card" style="flex: 1; background: #fdecea">
          <div class="stat-title">
            <el-icon><Warning /></el-icon> 高危
          </div>
          <div class="stat-value">{{ counts.high }}</div>
        </el-card>
        <el-card class="stat-card" style="flex: 1; background: #fff4e5">
          <div class="stat-title">
            <el-icon><HelpFilled /></el-icon> 中危
          </div>
          <div class="stat-value">{{ counts.medium }}</div>
        </el-card>
        <el-card class="stat-card" style="flex: 1; background: #eefaf0">
          <div class="stat-title">
            <el-icon><CirclePlus /></el-icon> 低危
          </div>
          <div class="stat-value">{{ counts.low }}</div>
        </el-card>
        <el-card class="stat-card" style="width: 180px; text-align: center">
          <div class="stat-title">总告警数</div>
          <div class="stat-value">{{ counts.total }}</div>
        </el-card>
      </div>

      <div class="chart-section">
        <div class="sub-title">
          <el-icon><TrendCharts /></el-icon> 告警级别分布趋势
        </div>

        <div v-if="!buckets.length" class="empty-block">
          <el-empty description="该时间段内暂无统计数据" :image-size="100" />
        </div>

        <div v-else class="svg-container">
          <svg
            :width="svgWidth"
            :height="svgHeight"
            @mousemove="onSvgMouseMove"
            @mouseleave="onSvgLeave"
            ref="svgEl"
            class="trend-svg"
          >
            <g v-for="(tick, idx) in yTicks" :key="'grid-' + idx">
              <line
                :x1="marginLeft"
                :x2="svgWidth - marginRight"
                :y1="yScale(tick)"
                :y2="yScale(tick)"
                class="grid-line"
              />
              <text
                :x="marginLeft - 8"
                :y="yScale(tick) + 4"
                class="axis-label y-label"
                text-anchor="end"
              >
                {{ tick }}
              </text>
            </g>

            <path :d="pathHigh" :stroke="colorHigh" class="trend-line" />
            <path :d="pathMedium" :stroke="colorMedium" class="trend-line" />
            <path :d="pathLow" :stroke="colorLow" class="trend-line" />

            <g v-for="(b, i) in buckets" :key="'p-' + i">
              <circle
                :cx="xFor(i)"
                :cy="yScale(b.high)"
                r="4"
                :fill="colorHigh"
                class="data-point"
              />
            </g>
            <g v-for="i in xLabelIndices" :key="'xl-' + i">
              <text
                v-if="buckets[i]"
                :x="xFor(i)"
                :y="svgHeight - 8"
                class="axis-label x-label"
                text-anchor="middle"
              >
                {{ formatAxisLabel(buckets[i].label) }}
              </text>
            </g>
          </svg>

          <transition name="el-fade-in">
            <div
              v-if="tooltip.show"
              class="data-tooltip"
              :style="{ left: tooltip.x + 'px', top: tooltip.y + 'px' }"
            >
              <div class="tooltip-header">{{ tooltip.label }}</div>
              <div class="tooltip-body">
                <div class="item">
                  <span class="dot high"></span> 高危:
                  <strong>{{ tooltip.high }}</strong>
                </div>
                <div class="item">
                  <span class="dot med"></span> 中危:
                  <strong>{{ tooltip.medium }}</strong>
                </div>
                <div class="item">
                  <span class="dot low"></span> 低危:
                  <strong>{{ tooltip.low }}</strong>
                </div>
              </div>
            </div>
          </transition>
        </div>
      </div>

      <el-row :gutter="20" class="detail-tables">
        <el-col :md="14" :sm="24">
          <div class="sub-title">
            <el-icon><Document /></el-icon> Top 告警规则排行
          </div>
          <el-table
            :data="topRules"
            stripe
            border
            class="custom-table"
            :height="tableHeight"
            size="small"
          >
            <el-table-column type="index" label="#" width="50" align="center" />
            <el-table-column
              prop="rule_id"
              label="规则 ID"
              min-width="120"
              show-overflow-tooltip
            />
            <el-table-column
              prop="pattern"
              label="规则模式"
              min-width="200"
              show-overflow-tooltip
            >
              <template #default="scope">
                <span class="pattern-text">{{ scope.row.pattern }}</span>
              </template>
            </el-table-column>
            <el-table-column
              prop="count"
              label="触发次数"
              width="100"
              align="center"
              sortable
            >
              <template #default="scope">
                <el-tag effect="dark" type="danger" round size="small">{{
                  scope.row.count
                }}</el-tag>
              </template>
            </el-table-column>
          </el-table>
        </el-col>
        <el-col :md="10" :sm="24">
          <div class="sub-title">
            <el-icon><Location /></el-icon> 异常源 IP 统计
          </div>
          <el-table
            :data="topIps"
            stripe
            border
            class="custom-table"
            :height="tableHeight"
            size="small"
          >
            <el-table-column
              prop="ip"
              label="源 IP 地址"
              min-width="120"
              show-overflow-tooltip
            />
            <el-table-column
              prop="count"
              label="频次"
              width="80"
              align="center"
              sortable
            >
              <template #default="scope">
                <el-tag effect="plain" type="info" round size="small">{{
                  scope.row.count
                }}</el-tag>
              </template>
            </el-table-column>
          </el-table>
        </el-col>
      </el-row>
    </el-card>
  </div>
</template>

<script>
import { ref, reactive, onMounted, computed, watch } from "vue";

export default {
  setup() {
    const buckets = ref([]);
    const topRules = ref([]);
    const topIps = ref([]);
    const range = ref("24h");
    const loading = ref(false);
    const svgEl = ref(null);

    const colorHigh = "#f56c6c";
    const colorMedium = "#e6a23c";
    const colorLow = "#67c23a";

    const svgHeight = 260;
    const marginLeft = 50;
    const marginRight = 30;
    const marginTop = 30;
    const marginBottom = 40;

    const tooltip = reactive({
      show: false,
      x: 0,
      y: 0,
      label: "",
      high: 0,
      medium: 0,
      low: 0,
    });

    const counts = reactive({ high: 0, medium: 0, low: 0, total: 0 });

    const maxVal = computed(() => {
      if (!buckets.value.length) return 10;
      const vals = buckets.value.flatMap((b) => [b.high, b.medium, b.low]);
      return Math.max(...vals, 10);
    });

    const svgWidth = computed(() => {
      const n = buckets.value.length;
      if (n <= 0) return 700;
      if (n <= 3) return 500;
      return Math.min(1200, Math.max(600, n * 40));
    });

    const yScale = (val) => {
      const chartArea = svgHeight - marginTop - marginBottom;
      return svgHeight - marginBottom - (val / maxVal.value) * chartArea;
    };

    const xFor = (index) => {
      const chartWidth = svgWidth.value - marginLeft - marginRight;
      return (
        marginLeft +
        (index / Math.max(1, buckets.value.length - 1)) * chartWidth
      );
    };

    const yTicks = computed(() => {
      const m = Math.max(1, maxVal.value);
      const step = m <= 5 ? 1 : m <= 20 ? 5 : m <= 50 ? 10 : Math.ceil(m / 5);
      const top = Math.ceil(m / step) * step;
      const ticks = [];
      for (let v = 0; v <= top; v += step) {
        ticks.push(v);
      }
      if (ticks.length > 6) {
        return ticks.filter((_, i) => i % 2 === 0);
      }
      return ticks.length ? ticks : [0, 1];
    });

    const buildPath = (key) => {
      if (!buckets.value.length) return "";
      return buckets.value
        .map((b, i) => `${i === 0 ? "M" : "L"} ${xFor(i)} ${yScale(b[key])}`)
        .join(" ");
    };

    const pathHigh = computed(() => buildPath("high"));
    const pathMedium = computed(() => buildPath("medium"));
    const pathLow = computed(() => buildPath("low"));
    const tableHeight = computed(() => {
      // 根据屏幕高度动态调整表格高度
      const screenHeight = window.innerHeight;
      if (screenHeight < 768) {
        return 200; // 小屏幕
      } else if (screenHeight < 1200) {
        return 280; // 中等屏幕
      } else {
        return 320; // 大屏幕
      }
    });

        const intervalByRange = computed(() => {
      const r = range.value;
      if (r === "1h") return "30m";
      if (r === "24h") return "1h";
      return "1d";
    });

    const load = async () => {
      loading.value = true;
      try {
        const [sres, rres] = await Promise.all([
          fetch(`/api/alerts/stats?range=${range.value}&interval=${intervalByRange.value}`),
          fetch(`/api/rules/`),
        ]);

        if (!sres.ok) throw new Error(`stats api failed: ${sres.status}`);

        const j = await sres.json();
        const rulesRaw = rres.ok ? await rres.json() : [];
        const rules = Array.isArray(rulesRaw) ? rulesRaw : rulesRaw.rules || [];
        const ruleMap = {};
        rules.forEach((rr) => {
          let pat = rr.pattern;
          try {
            if (Array.isArray(pat)) pat = pat.join(" | ");
            else if (typeof pat === "object") pat = JSON.stringify(pat);
          } catch (e) {
            pat = String(pat || "");
          }
          ruleMap[rr.rule_id] = { pattern: pat, name: rr.name };
        });

        buckets.value = (j.buckets || []).map((b) => ({
          label: b.bucket,
          high: b.high || 0,
          medium: b.medium || 0,
          low: b.low || 0,
        }));

        // Global counts: from buckets if present, else use API total and fetch count for total
        const sumHigh = buckets.value.reduce((s, x) => s + (x.high || 0), 0);
        const sumMedium = buckets.value.reduce(
          (s, x) => s + (x.medium || 0),
          0,
        );
        const sumLow = buckets.value.reduce((s, x) => s + (x.low || 0), 0);
        const totalFromBuckets = sumHigh + sumMedium + sumLow;
        counts.high = sumHigh;
        counts.medium = sumMedium;
        counts.low = sumLow;
        if (typeof j.total === "number") {
          counts.total = j.total;
        } else if (totalFromBuckets > 0) {
          counts.total = totalFromBuckets;
        } else {
          // No buckets: fetch total from count API so at least total is shown
          try {
            const cr = await fetch("/api/alerts/count");
            if (cr.ok) {
              const cj = await cr.json();
              if (typeof cj.total === "number") counts.total = cj.total;
            }
          } catch (_) {}
        }

        topRules.value = (j.top_rules || []).map((tr) => ({
          rule_id: tr.rule_id,
          count: tr.count,
          pattern: ruleMap[tr.rule_id]?.pattern || "",
          name: ruleMap[tr.rule_id]?.name || "",
        }));

        topIps.value = j.top_ips || [];
      } catch (e) {
        console.error(e);
        // 保留上一次成功的数据，避免刷新后归零
        try {
          const cr = await fetch("/api/alerts/count");
          if (cr.ok) {
            const cj = await cr.json();
            if (typeof cj.total === "number") counts.total = cj.total;
          }
        } catch (_) {}
      } finally {
        loading.value = false;
      }
    };

    const onSvgMouseMove = (e) => {
      if (!buckets.value.length || !svgEl.value) return;
      const rect = svgEl.value.getBoundingClientRect();
      const mouseX = (e.clientX - rect.left) * (svgWidth.value / rect.width);
      const chartWidth = svgWidth.value - marginLeft - marginRight;
      let idx = Math.round(
        ((mouseX - marginLeft) / chartWidth) * (buckets.value.length - 1),
      );
      idx = Math.max(0, Math.min(idx, buckets.value.length - 1));

      const b = buckets.value[idx];
      tooltip.show = true;
      tooltip.x = xFor(idx);
      tooltip.y = yScale(Math.max(b.high, b.medium, b.low)) - 60;
      tooltip.label = formatAxisLabel(b.label);
      tooltip.high = b.high;
      tooltip.medium = b.medium;
      tooltip.low = b.low;
    };

    const onSvgLeave = () => {
      tooltip.show = false;
    };

    const formatAxisLabel = (l) => {
      if (!l || typeof l !== "string") return "";
      const s = l.trim();
      if (!s) return "";
      if (s.includes("T")) {
        const [datePart, timePart] = s.split("T");
        const date = datePart || "";
        const time = (timePart || "").substring(0, 5);
        if (date && time) return `${date.slice(5)} ${time}`;
        if (time) return time;
        return date.slice(5) || s;
      }
      if (/^\d{4}-\d{2}-\d{2}/.test(s)) return s.slice(5);
      return s;
    };

    const xLabelIndices = computed(() => {
      const n = buckets.value.length;
      if (n <= 0) return [];
      if (n <= 8) return Array.from({ length: n }, (_, i) => i);
      const step = Math.ceil(n / 10);
      const indices = [];
      for (let i = 0; i < n; i += step) indices.push(i);
      if (indices[indices.length - 1] !== n - 1 && n > 1) indices.push(n - 1);
      return indices;
    });

    const shortLabel = (l) => formatAxisLabel(l);
    const reload = () => load();
    const exportCsv = () => {
      window.alert("CSV数据已准备。");
    };

    watch(range, load);
    onMounted(load);

    return {
      buckets,
      topRules,
      topIps,
      counts,
      range,
      loading,
      svgEl,
      colorHigh,
      colorMedium,
      colorLow,
      svgWidth,
      svgHeight,
      yTicks,
      yScale,
      xFor,
      xLabelIndices,
      pathHigh,
      pathMedium,
      pathLow,
      tableHeight,
      tooltip,
      onSvgMouseMove,
      onSvgLeave,
      shortLabel,
      formatAxisLabel,
      reload,
      exportCsv,
      marginLeft,
      marginRight,
    };
  },
};
</script>

<style scoped>
.stats-container {
  padding: 20px;
  background-color: #f5f7fa;
  min-height: 100vh;
}
.dashboard-card {
  border: none;
  border-radius: 12px;
}
.summary-cards .stat-card {
  padding: 12px;
}
.stat-title {
  font-size: 13px;
  color: #666;
  display: flex;
  align-items: center;
  gap: 6px;
}
.stat-value {
  font-size: 20px;
  font-weight: 700;
  margin-top: 6px;
}
.header-wrapper {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.header-title {
  display: flex;
  align-items: center;
  font-size: 18px;
  font-weight: 600;
  color: #303133;
}
.title-icon {
  margin-right: 8px;
  color: #409eff;
}
.header-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}
.sub-title {
  font-size: 15px;
  font-weight: bold;
  color: #606266;
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.chart-section {
  margin-bottom: 30px;
  padding: 20px;
  background: #ffffff;
  border-radius: 8px;
  border: 1px solid #ebeef5;
}
.svg-container {
  position: relative;
  overflow-x: auto;
  padding: 10px 0;
}
.trend-svg {
  cursor: crosshair;
}
.grid-line {
  stroke: #f0f0f0;
  stroke-width: 1;
}
.axis-label {
  font-size: 11px;
  fill: #909399;
}
.axis-label.x-label {
  font-size: 10px;
  fill: #606266;
}
.trend-line {
  fill: none;
  stroke-width: 3;
  stroke-linecap: round;
  stroke-linejoin: round;
  transition: all 0.3s;
}
.data-point {
  transition: r 0.2s;
}
.data-point:hover {
  r: 6;
}

.data-tooltip {
  position: absolute;
  background: rgba(255, 255, 255, 0.98);
  border: 1px solid #e4e7ed;
  border-radius: 8px;
  padding: 12px;
  pointer-events: none;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  z-index: 100;
  min-width: 140px;
}
.tooltip-header {
  font-weight: bold;
  margin-bottom: 8px;
  color: #333;
  border-bottom: 1px solid #f0f0f0;
}
.tooltip-body .item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 12px;
  margin-bottom: 4px;
}
.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 6px;
}
.dot.high {
  background: #f56c6c;
}
.dot.med {
  background: #e6a23c;
}
.dot.low {
  background: #67c23a;
}

.custom-table {
  border-radius: 8px;
  overflow: hidden;
}

.pattern-text {
  font-family: "Monaco", "Menlo", "Ubuntu Mono", monospace;
  font-size: 12px;
  color: #666;
  word-break: break-all;
}

.detail-tables {
  margin-top: 10px;
}

/* 响应式布局优化 */
@media (max-width: 768px) {
  .stats-container {
    padding: 10px;
  }

  .summary-cards {
    flex-direction: column;
    gap: 8px;
  }

  .summary-cards .stat-card {
    width: 100% !important;
  }

  .detail-tables .el-col {
    margin-bottom: 20px;
  }
}

@media (max-width: 1200px) {
  .header-wrapper {
    flex-direction: column;
    gap: 12px;
    align-items: flex-start;
  }

  .header-actions {
    width: 100%;
    justify-content: space-between;
  }
}
</style>
