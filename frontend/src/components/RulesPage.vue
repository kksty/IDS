<template>
  <div class="rules-container">
    <el-card class="rules-card" shadow="hover">
      <template #header>
        <div class="header-wrapper">
          <div class="header-title">
            <el-icon class="title-icon"><DocumentAdd /></el-icon>
            <span>规则管理</span>
          </div>
          <div class="header-actions">
            <el-button type="primary" @click="handleCreateRule">
              <el-icon><Plus /></el-icon><span>创建规则</span>
            </el-button>
            <el-button type="success" @click="showImportDialog = true">
              <el-icon><Upload /></el-icon><span>导入规则</span>
            </el-button>
            <el-button type="info" @click="loadRules">
              <el-icon><Refresh /></el-icon><span>刷新</span>
            </el-button>
          </div>
        </div>
      </template>

      <!-- 规则列表 -->
      <el-table
        :data="rules"
        stripe
        border
        class="rules-table"
        :height="tableHeight"
        v-loading="loading"
      >
        <el-table-column type="index" label="#" width="60" align="center" />
        <el-table-column
          prop="rule_id"
          label="规则 ID"
          min-width="120"
          show-overflow-tooltip
        />
        <el-table-column
          prop="name"
          label="规则名称"
          min-width="150"
          show-overflow-tooltip
        />
        <el-table-column
          prop="category"
          label="类别"
          width="100"
          align="center"
        >
          <template #default="scope">
            <el-tag :type="getCategoryType(scope.row.category)" size="small">
              {{ scope.row.category }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          prop="priority"
          label="优先级"
          width="80"
          align="center"
          sortable
        >
          <template #default="scope">
            <el-tag :type="getPriorityType(scope.row.priority)" size="small">
              {{ scope.row.priority }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          prop="protocol"
          label="协议"
          width="80"
          align="center"
        />
        <el-table-column prop="enabled" label="状态" width="80" align="center">
          <template #default="scope">
            <el-switch
              v-model="scope.row.enabled"
              @change="toggleRule(scope.row)"
              size="small"
            />
          </template>
        </el-table-column>
        <el-table-column label="操作" width="150" align="center">
          <template #default="scope">
            <el-button type="primary" size="small" @click="editRule(scope.row)">
              编辑
            </el-button>
            <el-button
              type="danger"
              size="small"
              @click="deleteRule(scope.row)"
            >
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 分页 -->
      <div class="pagination-wrapper">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="totalRules"
          layout="total, sizes, prev, pager, next, jumper"
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
        />
      </div>
    </el-card>

    <!-- 创建/编辑规则对话框 -->
    <el-dialog
      v-model="showCreateDialog"
      :title="isEditing ? '编辑规则' : '创建规则'"
      width="800px"
      :close-on-click-modal="false"
    >
      <div
        style="
          margin-bottom: 20px;
          padding: 12px;
          background: #f0f9ff;
          border-radius: 4px;
          border-left: 4px solid #409eff;
        "
      >
        <p style="margin: 0; color: #666; font-size: 14px">
          <strong>匹配逻辑说明：</strong
          >系统会优先匹配端口一致的规则，同时也会测试所有未指定端口的规则（any规则），确保不遗漏潜在威胁。
          协议字段为可选，如不确定可留空。
        </p>
      </div>
      <el-form
        ref="ruleFormRef"
        :model="ruleForm"
        :rules="ruleRules"
        label-width="120px"
      >
        <el-row :gutter="20">
          <el-col :span="12">
            <el-form-item label="规则 ID" prop="rule_id">
              <el-input
                v-model="ruleForm.rule_id"
                :disabled="isEditing"
                placeholder="唯一标识符"
              />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="规则名称" prop="name">
              <el-input v-model="ruleForm.name" placeholder="规则描述" />
            </el-form-item>
          </el-col>
        </el-row>

        <el-row :gutter="20">
          <el-col :span="8">
            <el-form-item label="协议（可选）">
              <el-select
                v-model="ruleForm.protocol"
                clearable
                placeholder="选择协议或留空"
              >
                <el-option label="TCP" value="tcp" />
                <el-option label="UDP" value="udp" />
                <el-option label="ICMP" value="icmp" />
                <el-option label="IP" value="ip" />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="8">
            <el-form-item label="优先级" prop="priority">
              <el-select
                v-model.number="ruleForm.priority"
                placeholder="选择优先级"
              >
                <el-option label="高" :value="1" />
                <el-option label="中" :value="2" />
                <el-option label="低" :value="3" />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="8">
            <el-form-item label="类别" prop="category">
              <el-input v-model="ruleForm.category" placeholder="规则类别" />
            </el-form-item>
          </el-col>
        </el-row>

        <el-row :gutter="20">
          <el-col :span="12">
            <el-form-item label="源 IP" prop="src">
              <el-input v-model="ruleForm.src" placeholder="any 或 IP 地址" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="目标 IP" prop="dst">
              <el-input v-model="ruleForm.dst" placeholder="any 或 IP 地址" />
            </el-form-item>
          </el-col>
        </el-row>

        <el-row :gutter="20">
          <el-col :span="12">
            <el-form-item label="源端口">
              <el-input
                v-model="ruleForm.src_ports_str"
                placeholder="any 或端口号，如 80 或 80:443"
              />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="目标端口">
              <el-input
                v-model="ruleForm.dst_ports_str"
                placeholder="any 或端口号，如 80 或 80:443"
              />
            </el-form-item>
          </el-col>
        </el-row>

        <el-form-item label="匹配模式" prop="pattern">
          <el-select
            v-model="ruleForm.pattern_type"
            style="width: 120px; margin-bottom: 10px"
          >
            <el-option label="字符串" value="string" />
            <el-option label="正则表达式" value="pcre" />
          </el-select>
          <el-input
            v-model="ruleForm.pattern"
            type="textarea"
            :rows="3"
            placeholder="匹配内容或正则表达式"
          />
        </el-form-item>

        <el-form-item label="描述">
          <el-input
            v-model="ruleForm.description"
            type="textarea"
            :rows="2"
            placeholder="规则详细描述"
          />
        </el-form-item>

        <el-form-item label="标签">
          <el-input
            v-model="ruleForm.tags_str"
            placeholder="用逗号分隔的标签"
          />
        </el-form-item>

        <el-form-item label="启用">
          <el-switch v-model="ruleForm.enabled" />
        </el-form-item>
      </el-form>

      <template #footer>
        <span class="dialog-footer">
          <el-button @click="showCreateDialog = false">取消</el-button>
          <el-button type="primary" @click="submitRule" :loading="submitting">
            {{ isEditing ? "更新" : "创建" }}
          </el-button>
        </span>
      </template>
    </el-dialog>

    <!-- 导入规则对话框 -->
    <el-dialog
      v-model="showImportDialog"
      title="导入规则"
      width="600px"
      :close-on-click-modal="false"
    >
      <el-tabs v-model="importTab" @tab-click="handleImportTabClick">
        <el-tab-pane label="Snort 规则文件" name="snort">
          <div class="import-section">
            <p>上传 Snort 格式的规则文件 (.rules)</p>
            <el-upload
              ref="snortUploadRef"
              class="upload-demo"
              drag
              :action="`${apiBase}/rules/bulk-import`"
              :headers="uploadHeaders"
              :on-success="handleSnortImportSuccess"
              :on-error="handleImportError"
              :before-upload="beforeSnortUpload"
              accept=".rules"
              :show-file-list="false"
            >
              <el-icon class="el-icon--upload"><UploadFilled /></el-icon>
              <div class="el-upload__text">
                将文件拖到此处，或 <em>点击上传</em>
              </div>
              <template #tip>
                <div class="el-upload__tip">
                  只能上传 .rules 文件，且不超过 10MB
                </div>
              </template>
            </el-upload>
          </div>
        </el-tab-pane>

        <el-tab-pane label="JSON 规则" name="json">
          <div class="import-section">
            <p>粘贴 JSON 格式的规则列表</p>
            <el-input
              v-model="jsonRulesText"
              type="textarea"
              :rows="10"
              placeholder='[{"name": "规则名称", "patterns": ["匹配内容"], "severity": "high", "description": "描述"}]'
            />
            <el-button
              type="primary"
              @click="importJsonRules"
              :loading="importing"
              style="margin-top: 10px"
            >
              导入 JSON 规则
            </el-button>
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-dialog>
  </div>
</template>

<script>
import { ref, reactive, onMounted, computed } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";

export default {
  setup() {
    const rules = ref([]);
    const loading = ref(false);
    const submitting = ref(false);
    const importing = ref(false);

    const showCreateDialog = ref(false);
    const showImportDialog = ref(false);
    const isEditing = ref(false);
    const importTab = ref("snort");

    const currentPage = ref(1);
    const pageSize = ref(20);
    const totalRules = ref(0);

    const apiBase = ""; // 相对路径，由代理处理

    const ruleForm = reactive({
      rule_id: "",
      name: "",
      protocol: null,
      priority: 2,
      category: "custom",
      src: "any",
      dst: "any",
      src_ports_str: "any",
      dst_ports_str: "any",
      pattern: "",
      pattern_type: "string",
      description: "",
      tags_str: "",
      enabled: true,
    });

    const ruleFormRef = ref(null);
    const snortUploadRef = ref(null);
    const jsonRulesText = ref("");

    const ruleRules = {
      rule_id: [
        { required: true, message: "请输入规则 ID", trigger: "blur" },
        {
          pattern: /^[a-zA-Z0-9_-]+$/,
          message: "规则 ID 只能包含字母、数字、下划线和连字符",
          trigger: "blur",
        },
      ],
      name: [{ required: true, message: "请输入规则名称", trigger: "blur" }],
      priority: [
        { required: true, message: "请选择优先级", trigger: "change" },
      ],
      pattern: [{ required: true, message: "请输入匹配模式", trigger: "blur" }],
    };

    const tableHeight = computed(() => {
      const screenHeight = window.innerHeight;
      return Math.max(400, screenHeight - 300);
    });

    const uploadHeaders = computed(() => ({
      // 如果需要认证，可以在这里添加
    }));

    const getCategoryType = (category) => {
      const types = {
        web: "danger",
        admin: "warning",
        dos: "danger",
        recon: "info",
        policy: "success",
        custom: "",
      };
      return types[category] || "";
    };

    const getPriorityType = (priority) => {
      const types = {
        1: "danger",
        2: "warning",
        3: "info",
      };
      return types[priority] || "info";
    };

    const loadRules = async () => {
      loading.value = true;
      try {
        const response = await fetch(`${apiBase}/api/rules`);
        if (response.ok) {
          const data = await response.json();
          rules.value = data;
          totalRules.value = data.length;
        } else {
          ElMessage.error("加载规则失败");
        }
      } catch (error) {
        console.error("加载规则失败:", error);
        ElMessage.error("加载规则失败");
      } finally {
        loading.value = false;
      }
    };

    const toggleRule = async (rule) => {
      try {
        const response = await fetch(`${apiBase}/api/rules/${rule.rule_id}`, {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(rule),
        });

        if (!response.ok) {
          // 恢复开关状态
          rule.enabled = !rule.enabled;
          ElMessage.error("更新规则状态失败");
        } else {
          ElMessage.success("规则状态已更新");
        }
      } catch (error) {
        // 恢复开关状态
        rule.enabled = !rule.enabled;
        console.error("更新规则状态失败:", error);
        ElMessage.error("更新规则状态失败");
      }
    };

    const editRule = (rule) => {
      // 复制规则数据到表单
      Object.assign(ruleForm, {
        rule_id: rule.rule_id,
        name: rule.name,
        protocol: rule.protocol,
        priority: rule.priority,
        category: rule.category,
        src: rule.src,
        dst: rule.dst,
        src_ports_str: rule.src_ports ? rule.src_ports.join(",") : "any",
        dst_ports_str: rule.dst_ports ? rule.dst_ports.join(",") : "any",
        pattern: Array.isArray(rule.pattern)
          ? rule.pattern.join(" | ")
          : rule.pattern,
        pattern_type: rule.pattern_type,
        description: rule.description,
        tags_str: rule.tags ? rule.tags.join(",") : "",
        enabled: rule.enabled,
      });

      isEditing.value = true;
      showCreateDialog.value = true;
    };

    const deleteRule = async (rule) => {
      try {
        await ElMessageBox.confirm(
          `确定要删除规则 "${rule.name}" 吗？此操作不可恢复。`,
          "确认删除",
          {
            confirmButtonText: "确定",
            cancelButtonText: "取消",
            type: "warning",
          },
        );

        const response = await fetch(`${apiBase}/api/rules/${rule.rule_id}`, {
          method: "DELETE",
        });

        if (response.ok) {
          ElMessage.success("规则已删除");
          loadRules();
        } else {
          ElMessage.error("删除规则失败");
        }
      } catch (error) {
        if (error !== "cancel") {
          console.error("删除规则失败:", error);
          ElMessage.error("删除规则失败");
        }
      }
    };

    const submitRule = async () => {
      if (!ruleFormRef.value) return;

      await ruleFormRef.value.validate(async (valid) => {
        if (!valid) return;

        submitting.value = true;

        try {
          // 转换表单数据
          const ruleData = {
            rule_id: ruleForm.rule_id,
            name: ruleForm.name,
            action: "alert",
            protocol: ruleForm.protocol,
            priority: ruleForm.priority,
            category: ruleForm.category,
            src: ruleForm.src,
            dst: ruleForm.dst,
            src_ports:
              ruleForm.src_ports_str === "any"
                ? null
                : parsePorts(ruleForm.src_ports_str),
            dst_ports:
              ruleForm.dst_ports_str === "any"
                ? null
                : parsePorts(ruleForm.dst_ports_str),
            direction: "->",
            pattern: ruleForm.pattern,
            pattern_type: ruleForm.pattern_type,
            description: ruleForm.description,
            tags: ruleForm.tags_str
              ? ruleForm.tags_str.split(",").map((t) => t.trim())
              : [],
            metadata: {},
            enabled: ruleForm.enabled,
          };

          const url = isEditing.value
            ? `${apiBase}/api/rules/${ruleForm.rule_id}`
            : `${apiBase}/api/rules`;

          const method = isEditing.value ? "PUT" : "POST";

          const response = await fetch(url, {
            method,
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify(ruleData),
          });

          if (response.ok) {
            ElMessage.success(isEditing.value ? "规则已更新" : "规则已创建");
            showCreateDialog.value = false;
            loadRules();
            resetForm();
          } else {
            const error = await response.json();
            ElMessage.error(error.detail || "操作失败");
          }
        } catch (error) {
          console.error("提交规则失败:", error);
          ElMessage.error("操作失败");
        } finally {
          submitting.value = false;
        }
      });
    };

    const parsePorts = (portStr) => {
      if (!portStr || portStr === "any") return null;

      if (portStr.includes(":")) {
        const [start, end] = portStr.split(":").map((p) => parseInt(p.trim()));
        return Array.from({ length: end - start + 1 }, (_, i) => start + i);
      }

      return [parseInt(portStr.trim())];
    };

    const resetForm = () => {
      Object.assign(ruleForm, {
        rule_id: "",
        name: "",
        protocol: null,
        priority: 2,
        category: "custom",
        src: "any",
        dst: "any",
        src_ports_str: "any",
        dst_ports_str: "any",
        pattern: "",
        pattern_type: "string",
        description: "",
        tags_str: "",
        enabled: true,
      });
      isEditing.value = false;
      if (ruleFormRef.value) {
        ruleFormRef.value.clearValidate();
      }
    };

    const handleCreateRule = () => {
      resetForm();
      showCreateDialog.value = true;
    };

    const handleSnortImportSuccess = (response) => {
      if (response.message) {
        ElMessage.success(response.message);
        showImportDialog.value = false;
        loadRules();
      }
    };

    const handleImportError = (error) => {
      console.error("导入失败:", error);
      ElMessage.error("导入失败，请检查文件格式");
    };

    const beforeSnortUpload = (file) => {
      const isRules =
        file.type === "text/plain" || file.name.endsWith(".rules");
      const isLt10M = file.size / 1024 / 1024 < 10;

      if (!isRules) {
        ElMessage.error("只能上传 .rules 格式的文件!");
        return false;
      }
      if (!isLt10M) {
        ElMessage.error("上传文件大小不能超过 10MB!");
        return false;
      }
      return true;
    };

    const importJsonRules = async () => {
      if (!jsonRulesText.value.trim()) {
        ElMessage.warning("请输入 JSON 规则数据");
        return;
      }

      try {
        const rulesData = JSON.parse(jsonRulesText.value);
        if (!Array.isArray(rulesData)) {
          ElMessage.error("JSON 数据必须是数组格式");
          return;
        }

        importing.value = true;

        const response = await fetch(`${apiBase}/api/rules/bulk-import-json`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(rulesData),
        });

        if (response.ok) {
          const result = await response.json();
          ElMessage.success(result.message);
          showImportDialog.value = false;
          jsonRulesText.value = "";
          loadRules();
        } else {
          const error = await response.json();
          ElMessage.error(error.detail || "导入失败");
        }
      } catch (error) {
        console.error("JSON 解析或导入失败:", error);
        ElMessage.error("JSON 格式错误或导入失败");
      } finally {
        importing.value = false;
      }
    };

    const handleImportTabClick = (tab) => {
      // 切换标签时的处理
    };

    const handleSizeChange = (size) => {
      pageSize.value = size;
      // 这里可以实现分页逻辑
    };

    const handleCurrentChange = (page) => {
      currentPage.value = page;
      // 这里可以实现分页逻辑
    };

    onMounted(() => {
      loadRules();
    });

    return {
      rules,
      loading,
      submitting,
      importing,
      showCreateDialog,
      showImportDialog,
      isEditing,
      importTab,
      currentPage,
      pageSize,
      totalRules,
      ruleForm,
      ruleFormRef,
      snortUploadRef,
      jsonRulesText,
      ruleRules,
      tableHeight,
      uploadHeaders,
      getCategoryType,
      getPriorityType,
      loadRules,
      toggleRule,
      editRule,
      deleteRule,
      submitRule,
      resetForm,
      handleCreateRule,
      handleSnortImportSuccess,
      handleImportError,
      beforeSnortUpload,
      importJsonRules,
      handleImportTabClick,
      handleSizeChange,
      handleCurrentChange,
    };
  },
};
</script>

<style scoped>
.rules-container {
  padding: 20px;
  background-color: #f5f7fa;
  min-height: 100vh;
}

.rules-card {
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

.rules-table {
  border-radius: 8px;
  overflow: hidden;
}

.pagination-wrapper {
  display: flex;
  justify-content: center;
  margin-top: 20px;
}

.import-section {
  padding: 20px 0;
}

.upload-demo {
  width: 100%;
}

.dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}
</style>
