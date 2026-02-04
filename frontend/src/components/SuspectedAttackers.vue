<template>
  <div class="suspected-attackers">
    <div class="header">
      <h3>可疑攻击者监控</h3>
      <el-button type="primary" icon="Refresh" @click="loadData" :loading="loading">
        刷新
      </el-button>
    </div>

    <el-table :data="attackers" style="width: 100%" stripe size="small" v-loading="loading">
      <el-table-column prop="src_ip" label="源 IP" width="140">
        <template #default="{ row }">
          <span class="ip-address">{{ row.src_ip }}</span>
        </template>
      </el-table-column>
      
      <el-table-column prop="severity" label="威胁级别" width="120">
        <template #default="{ row }">
          <el-tag :type="getSeverityType(row.severity)" size="small">
            {{ getSeverityText(row.severity) }}
          </el-tag>
        </template>
      </el-table-column>
      
      <el-table-column prop="first_seen" label="首次发现" width="180">
        <template #default="{ row }">{{ formatTime(row.first_seen) }}</template>
      </el-table-column>
      
      <el-table-column prop="description" label="活动描述">
        <template #default="{ row }">{{ row.description }}</template>
      </el-table-column>
      
      <el-table-column label="操作" width="120">
        <template #default="{ row }">
          <el-button type="text" size="small" @click="viewDetails(row)">
            <el-icon><View /></el-icon>
            详情
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 详情对话框 -->
    <el-dialog v-model="detailVisible" :title="`攻击者详情 - ${selectedAttacker?.src_ip}`" width="600px">
      <div v-if="selectedAttacker" class="attacker-details">
        <div class="detail-item">
          <label>IP地址:</label>
          <span>{{ selectedAttacker.src_ip }}</span>
        </div>
        <div class="detail-item">
          <label>威胁级别:</label>
          <el-tag :type="getSeverityType(selectedAttacker.severity)">
            {{ getSeverityText(selectedAttacker.severity) }}
          </el-tag>
        </div>
        <div class="detail-item">
          <label>首次发现:</label>
          <span>{{ formatTime(selectedAttacker.first_seen) }}</span>
        </div>
        <div class="detail-item">
          <label>活动描述:</label>
          <span>{{ selectedAttacker.description }}</span>
        </div>
        
        <el-divider />
        <h4>相关告警</h4>
        <div v-if="relatedAlerts.length === 0" class="no-alerts">
          暂无相关告警记录
        </div>
        <div v-else class="related-alerts">
          <div v-for="alert in relatedAlerts" :key="alert.id" class="alert-item">
            <span class="alert-time">{{ formatTime(alert.created_at) }}</span>
            <span class="alert-rule">{{ alert.rule_id }}</span>
            <span class="alert-text">{{ alert.match_text }}</span>
          </div>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { ref, onMounted } from "vue";
import { ElMessage } from "element-plus";

export default {
  name: 'SuspectedAttackers',
  setup() {
    const attackers = ref([]);
    const loading = ref(false);
    const detailVisible = ref(false);
    const selectedAttacker = ref(null);
    const relatedAlerts = ref([]);

    const getSeverityType = (severity) => {
      switch (severity) {
        case 'high': return 'danger';
        case 'medium': return 'warning';
        default: return 'info';
      }
    };

    const getSeverityText = (severity) => {
      switch (severity) {
        case 'high': return '高危';
        case 'medium': return '中危';
        default: return '低危';
      }
    };

    const formatTime = (timestamp) => {
      if (!timestamp) return '';
      try {
        return new Date(timestamp).toLocaleString();
      } catch (e) {
        return timestamp;
      }
    };

    const loadData = async () => {
      loading.value = true;
      try {
        const response = await fetch('/api/correlation/attackers');
        if (response.ok) {
          attackers.value = await response.json();
        } else {
          ElMessage.error('获取可疑攻击者列表失败');
        }
      } catch (error) {
        console.error('加载可疑攻击者数据失败:', error);
        ElMessage.error('加载数据失败');
      } finally {
        loading.value = false;
      }
    };

    const viewDetails = async (attacker) => {
      selectedAttacker.value = attacker;
      detailVisible.value = true;
      
      // 加载相关告警
      try {
        const response = await fetch(`/api/alerts?src_ip=${attacker.src_ip}&limit=50`);
        if (response.ok) {
          relatedAlerts.value = await response.json();
        }
      } catch (error) {
        console.error('加载相关告警失败:', error);
        relatedAlerts.value = [];
      }
    };

    onMounted(() => {
      loadData();
    });

    return {
      attackers,
      loading,
      detailVisible,
      selectedAttacker,
      relatedAlerts,
      getSeverityType,
      getSeverityText,
      formatTime,
      loadData,
      viewDetails
    };
  }
};
</script>

<style scoped>
.suspected-attackers {
  padding: 20px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.header h3 {
  margin: 0;
  color: #303133;
}

.ip-address {
  font-family: monospace;
  font-weight: bold;
}

.attacker-details .detail-item {
  display: flex;
  margin-bottom: 12px;
  align-items: center;
}

.attacker-details .detail-item label {
  font-weight: bold;
  width: 80px;
  margin-right: 12px;
  color: #606266;
}

.related-alerts {
  max-height: 300px;
  overflow-y: auto;
}

.alert-item {
  padding: 8px;
  border-bottom: 1px solid #ebeef5;
  display: flex;
  align-items: center;
}

.alert-item:last-child {
  border-bottom: none;
}

.alert-time {
  width: 160px;
  font-size: 12px;
  color: #909399;
}

.alert-rule {
  width: 180px;
  font-weight: 500;
  margin: 0 12px;
  font-size: 12px;
}

.alert-text {
  flex: 1;
  font-size: 12px;
  color: #606266;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.no-alerts {
  text-align: center;
  color: #909399;
  padding: 20px;
}
</style>
