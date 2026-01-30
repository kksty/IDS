<template>
  <el-card>
    <h3>告警计数</h3>
    <div style="margin-bottom: 8px">
      总告警数：<strong>{{ total }}</strong>
    </div>
    <div style="display: flex; gap: 12px">
      <el-card style="flex: 1; background: #fdecea">
        <div style="font-size: 14px; color: #c0392b">高</div>
        <div style="font-size: 20px; font-weight: 700">{{ counts.high }}</div>
      </el-card>
      <el-card style="flex: 1; background: #fff4e5">
        <div style="font-size: 14px; color: #e67e22">中</div>
        <div style="font-size: 20px; font-weight: 700">{{ counts.medium }}</div>
      </el-card>
      <el-card style="flex: 1; background: #eefaf0">
        <div style="font-size: 14px; color: #27ae60">低</div>
        <div style="font-size: 20px; font-weight: 700">{{ counts.low }}</div>
      </el-card>
    </div>
  </el-card>
</template>

<script>
import bus from "../ws";
import { reactive, ref, onMounted, onBeforeUnmount } from "vue";

export default {
  setup() {
    const counts = reactive({ high: 0, medium: 0, low: 0 });
    const total = ref(0);
    function onAlert(e) {
      const a = e.detail || {};
      const sev = (a.severity || "low").toLowerCase();
      if (sev === "high") counts.high++;
      else if (sev === "medium") counts.medium++;
      else counts.low++;
      // 增加总告警计数（持久化计数在刷新后从后端读取）
      total.value++;
    }
    onMounted(() => {
      bus.addEventListener("alert", onAlert);
      // 获取后端持久化的总告警数
      fetch("/api/alerts/count")
        .then((r) => r.json())
        .then((j) => {
          if (j && typeof j.total === "number") total.value = j.total;
        })
        .catch(() => {});
    });
    onBeforeUnmount(() => bus.removeEventListener("alert", onAlert));
    return { counts, total };
  },
};
</script>
