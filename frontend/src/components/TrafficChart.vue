<template>
  <el-card shadow="hover" class="rate-card">
    <div class="rate-content">
      <div class="icon-section">
        <div class="icon-bg" :class="{ 'is-active': rate > 0 }">
          <el-icon :class="{ 'pulse-animation': rate > 0 }">
            <Timer />
          </el-icon>
        </div>
      </div>

      <div class="data-section">
        <div class="label-group">
          <span class="main-label">实时告警速率</span>
          <el-tag
            v-if="rate > 0"
            type="success"
            size="small"
            effect="plain"
            round
            class="live-tag"
          >
            LIVE
          </el-tag>
        </div>

        <div class="value-wrapper">
          <span class="rate-number">{{ formattedRate }}</span>
          <span class="rate-unit">req / min</span>
        </div>

        <div class="rate-footer">
          <el-icon><InfoFilled /></el-icon>
          <span>基于最近 60 秒接收频率计算</span>
        </div>
      </div>
    </div>
  </el-card>
</template>

<script>
import bus from "../ws";
import { ref, onMounted, onBeforeUnmount, computed } from "vue";

export default {
  setup() {
    // 使用隐藏的数组记录时间戳
    const entries = [];
    const rate = ref(0);
    let timer = null;

    function onAlert() {
      const now = Date.now();
      entries.push(now);
      // 收到消息时立即重新计算，增强实时感
      pruneAndCompute();
    }

    function pruneAndCompute() {
      const cutoff = Date.now() - 60000;
      while (entries.length && entries[0] < cutoff) entries.shift();
      rate.value = entries.length;
    }

    onMounted(() => {
      bus.addEventListener("alert", onAlert);
      pruneAndCompute();
      // 定期清理过期数据（防止无新消息时数值不归零）
      timer = setInterval(pruneAndCompute, 1000);
    });

    onBeforeUnmount(() => {
      bus.removeEventListener("alert", onAlert);
      clearInterval(timer);
    });

    const formattedRate = computed(() => {
      return rate.value.toLocaleString();
    });

    return { rate, formattedRate };
  },
};
</script>

<style scoped>
.rate-card {
  border-radius: 12px;
  border: 1px solid #ebeef5;
  transition: all 0.3s ease;
  background: linear-gradient(135deg, #ffffff 0%, #f9faff 100%);
}

.rate-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08);
}

.rate-content {
  display: flex;
  align-items: center;
  gap: 20px;
  padding: 4px;
}

/* 图标区域样式 */
.icon-section {
  flex-shrink: 0;
}

.icon-bg {
  width: 56px;
  height: 56px;
  border-radius: 16px;
  background: #f4f4f5;
  color: #909399;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 28px;
  transition: all 0.5s ease;
}

.icon-bg.is-active {
  background: #ecf5ff;
  color: #409eff;
}

/* 数据区域样式 */
.data-section {
  flex-grow: 1;
}

.label-group {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
}

.main-label {
  font-size: 13px;
  color: #909399;
  font-weight: 500;
}

.live-tag {
  height: 18px;
  padding: 0 6px;
  font-weight: bold;
  font-size: 10px;
}

.value-wrapper {
  display: flex;
  align-items: baseline;
  gap: 6px;
  margin-bottom: 4px;
}

.rate-number {
  font-size: 32px;
  font-weight: 800;
  color: #303133;
  font-family: "Helvetica Neue", Helvetica, "PingFang SC", sans-serif;
}

.rate-unit {
  font-size: 14px;
  color: #909399;
  font-weight: 400;
}

.rate-footer {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  color: #a8abb2;
}

/* 呼吸动画：当有请求时图标跳动 */
.pulse-animation {
  animation: pulse 2s infinite ease-in-out;
}

@keyframes pulse {
  0% {
    transform: scale(1);
    opacity: 1;
  }
  50% {
    transform: scale(1.15);
    opacity: 0.7;
  }
  100% {
    transform: scale(1);
    opacity: 1;
  }
}

/* 适配移动端 */
@media (max-width: 768px) {
  .rate-number {
    font-size: 24px;
  }
  .icon-bg {
    width: 44px;
    height: 44px;
    font-size: 22px;
  }
}
</style>
