<template>
  <div class="users-container">
    <el-card class="users-card" shadow="never">
      <template #header>
        <div class="users-header">
          <div class="title">
            <span>用户管理</span>
            <small>仅 admin 可访问，用于创建、编辑和删除账号</small>
          </div>
          <el-button type="primary" @click="loadUsers" :loading="loading">
            刷新
          </el-button>
        </div>
      </template>

      <div v-if="!isAdmin" class="not-admin">
        <el-alert
          type="error"
          title="当前用户不是 admin"
          description="只有 admin 账号可以管理用户。请使用 admin 登录。"
          :closable="false"
          show-icon
        />
      </div>

      <div v-else>
        <el-row :gutter="20">
          <el-col :span="12">
            <el-card shadow="hover" class="create-card">
              <template #header>
                <span>创建新用户</span>
              </template>
              <el-form
                :model="form"
                :rules="rules"
                ref="formRef"
                label-width="80px"
              >
                <el-form-item label="用户名" prop="username">
                  <el-input
                    v-model="form.username"
                    autocomplete="off"
                    placeholder="例如：alice"
                  />
                </el-form-item>
                <el-form-item label="密码" prop="password">
                  <el-input
                    v-model="form.password"
                    type="password"
                    show-password
                    autocomplete="new-password"
                    placeholder="例如：alice123"
                  />
                </el-form-item>
                <el-form-item label="角色" prop="role">
                  <el-select v-model="form.role" placeholder="选择角色">
                    <el-option label="admin（管理员）" value="admin" />
                    <el-option label="readonly（只读）" value="readonly" />
                  </el-select>
                </el-form-item>
                <el-form-item label="启用">
                  <el-switch v-model="form.is_active" />
                </el-form-item>
                <el-form-item>
                  <el-button
                    type="primary"
                    :loading="creating"
                    @click="handleCreate"
                  >
                    创建用户
                  </el-button>
                  <el-button @click="resetForm">重置</el-button>
                </el-form-item>
              </el-form>
            </el-card>
          </el-col>

          <el-col :span="12">
            <el-card shadow="hover" class="list-card">
              <template #header>
                <span>现有用户</span>
              </template>
              <el-table
                :data="users"
                border
                size="small"
                v-loading="loading"
                style="width: 100%"
              >
                <el-table-column prop="username" label="用户名" />
                <el-table-column prop="role" label="角色" width="120">
                  <template #default="scope">
                    <el-tag
                      :type="scope.row.role === 'admin' ? 'danger' : 'info'"
                      size="small"
                    >
                      {{ scope.row.role }}
                    </el-tag>
                  </template>
                </el-table-column>
                <el-table-column
                  prop="is_active"
                  label="状态"
                  width="120"
                  align="center"
                >
                  <template #default="scope">
                    <el-tag
                      :type="scope.row.is_active ? 'success' : 'warning'"
                      size="small"
                    >
                      {{ scope.row.is_active ? "启用" : "禁用" }}
                    </el-tag>
                  </template>
                </el-table-column>
                <el-table-column label="操作" width="200" align="center">
                  <template #default="scope">
                    <el-button
                      type="primary"
                      size="small"
                      @click="openEditDialog(scope.row)"
                    >
                      编辑
                    </el-button>
                    <el-button
                      type="danger"
                      size="small"
                      @click="handleDelete(scope.row)"
                      :disabled="scope.row.username === 'admin'"
                    >
                      删除
                    </el-button>
                  </template>
                </el-table-column>
              </el-table>
            </el-card>
          </el-col>
        </el-row>

        <!-- 编辑用户弹窗 -->
        <el-dialog
          v-model="editDialogVisible"
          title="编辑用户"
          width="400px"
          :close-on-click-modal="false"
          @close="resetEditForm"
        >
          <el-form
            ref="editFormRef"
            :model="editForm"
            :rules="editRules"
            label-width="80px"
          >
            <el-form-item label="用户名">
              <el-input v-model="editForm.username" disabled />
            </el-form-item>
            <el-form-item label="新密码" prop="password">
              <el-input
                v-model="editForm.password"
                type="password"
                show-password
                placeholder="留空则不修改密码"
                autocomplete="new-password"
              />
            </el-form-item>
            <el-form-item label="角色" prop="role">
              <el-select v-model="editForm.role" placeholder="选择角色">
                <el-option label="admin（管理员）" value="admin" />
                <el-option label="readonly（只读）" value="readonly" />
              </el-select>
            </el-form-item>
            <el-form-item label="状态" prop="is_active">
              <el-switch v-model="editForm.is_active" active-text="启用" inactive-text="禁用" />
            </el-form-item>
          </el-form>
          <template #footer>
            <el-button @click="editDialogVisible = false">取消</el-button>
            <el-button type="primary" :loading="updating" @click="handleUpdate">保存</el-button>
          </template>
        </el-dialog>
      </div>
    </el-card>
  </div>
</template>

<script>
import { ref, computed, onMounted } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";

export default {
  setup() {
    const apiBase = "";
    const token = ref(localStorage.getItem("ids_token") || "");
    const currentUser = ref(null);
    const users = ref([]);
    const loading = ref(false);
    const creating = ref(false);
    const updating = ref(false);
    const formRef = ref(null);
    const editFormRef = ref(null);
    const editDialogVisible = ref(false);
    const form = ref({
      username: "",
      password: "",
      role: "readonly",
      is_active: true,
    });

    const editForm = ref({
      username: "",
      password: "",
      role: "readonly",
      is_active: true,
    });

    const isAdmin = computed(
      () => currentUser.value && currentUser.value.role === "admin",
    );

    const rules = {
      username: [{ required: true, message: "请输入用户名", trigger: "blur" }],
      password: [{ required: true, message: "请输入密码", trigger: "blur" }],
      role: [{ required: true, message: "请选择角色", trigger: "change" }],
    };

    const editRules = {
      role: [{ required: true, message: "请选择角色", trigger: "change" }],
    };

    const authHeaders = computed(() => {
      const headers = {};
      if (token.value) {
        headers.Authorization = `Bearer ${token.value}`;
      }
      return headers;
    });

    const fetchCurrentUser = async () => {
      if (!token.value) {
        currentUser.value = null;
        return;
      }
      try {
        const resp = await fetch(`${apiBase}/api/auth/me`, {
          headers: authHeaders.value,
        });
        if (resp.ok) {
          currentUser.value = await resp.json();
        } else {
          currentUser.value = null;
        }
      } catch (e) {
        console.error("获取当前用户失败:", e);
      }
    };

    const loadUsers = async () => {
      if (!token.value) return;
      loading.value = true;
      try {
        const resp = await fetch(`${apiBase}/api/auth/users`, {
          headers: {
            "Content-Type": "application/json",
            ...authHeaders.value,
          },
        });
        if (resp.ok) {
          users.value = await resp.json();
        } else {
          const err = await resp.json().catch(() => ({}));
          ElMessage.error(err.detail || "加载用户失败");
        }
      } catch (e) {
        console.error("加载用户失败:", e);
        ElMessage.error("加载用户失败");
      } finally {
        loading.value = false;
      }
    };

    const handleCreate = () => {
      if (!formRef.value) return;
      formRef.value.validate(async (valid) => {
        if (!valid) return;
        creating.value = true;
        try {
          const resp = await fetch(`${apiBase}/api/auth/users`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              ...authHeaders.value,
            },
            body: JSON.stringify(form.value),
          });
          if (resp.ok) {
            ElMessage.success("创建用户成功");
            resetForm();
            loadUsers();
          } else {
            const err = await resp.json().catch(() => ({}));
            ElMessage.error(err.detail || "创建用户失败");
          }
        } catch (e) {
          console.error("创建用户失败:", e);
          ElMessage.error("创建用户失败");
        } finally {
          creating.value = false;
        }
      });
    };

    const openEditDialog = (row) => {
      editForm.value = {
        username: row.username,
        password: "",
        role: row.role,
        is_active: row.is_active,
      };
      editDialogVisible.value = true;
    };

    const resetEditForm = () => {
      editForm.value = {
        username: "",
        password: "",
        role: "readonly",
        is_active: true,
      };
      editFormRef.value?.clearValidate();
    };

    const handleUpdate = async () => {
      if (!editFormRef.value) return;
      await editFormRef.value.validate(async (valid) => {
        if (!valid) return;
        const payload = {};
        if (editForm.value.password) payload.password = editForm.value.password;
        payload.role = editForm.value.role;
        payload.is_active = editForm.value.is_active;
        if (Object.keys(payload).length === 0) {
          ElMessage.warning("请至少修改一项");
          return;
        }
        updating.value = true;
        try {
          const resp = await fetch(
            `${apiBase}/api/auth/users/${encodeURIComponent(editForm.value.username)}`,
            {
              method: "PATCH",
              headers: {
                "Content-Type": "application/json",
                ...authHeaders.value,
              },
              body: JSON.stringify(payload),
            },
          );
          if (resp.ok) {
            ElMessage.success("修改成功");
            editDialogVisible.value = false;
            loadUsers();
          } else {
            const err = await resp.json().catch(() => ({}));
            ElMessage.error(err.detail || "修改失败");
          }
        } catch (e) {
          console.error("修改用户失败:", e);
          ElMessage.error("修改失败");
        } finally {
          updating.value = false;
        }
      });
    };

    const handleDelete = async (row) => {
      if (!row || !row.username) return;
      try {
        await ElMessageBox.confirm(
          `确定要删除用户 "${row.username}" 吗？`,
          "确认删除",
          {
            type: "warning",
            confirmButtonText: "删除",
            cancelButtonText: "取消",
          },
        );
      } catch {
        return;
      }
      try {
        const resp = await fetch(
          `${apiBase}/api/auth/users/${encodeURIComponent(row.username)}`,
          {
            method: "DELETE",
            headers: authHeaders.value,
          },
        );
        if (resp.ok) {
          ElMessage.success("用户已删除");
          loadUsers();
        } else {
          const err = await resp.json().catch(() => ({}));
          ElMessage.error(err.detail || "删除用户失败");
        }
      } catch (e) {
        console.error("删除用户失败:", e);
        ElMessage.error("删除用户失败");
      }
    };

    const resetForm = () => {
      form.value = {
        username: "",
        password: "",
        role: "readonly",
        is_active: true,
      };
      if (formRef.value) {
        formRef.value.clearValidate();
      }
    };

    onMounted(async () => {
      await fetchCurrentUser();
      if (isAdmin.value) {
        loadUsers();
      }
    });

    return {
      users,
      loading,
      creating,
      updating,
      form,
      formRef,
      editForm,
      editFormRef,
      editDialogVisible,
      editRules,
      rules,
      isAdmin,
      loadUsers,
      handleCreate,
      handleDelete,
      handleUpdate,
      openEditDialog,
      resetEditForm,
      resetForm,
    };
  },
};
</script>

<style scoped>
.users-container {
  padding: 8px 0;
}

.users-card {
  border-radius: 10px;
}

.users-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.users-header .title {
  display: flex;
  flex-direction: column;
}

.users-header .title span {
  font-size: 16px;
  font-weight: 600;
}

.users-header .title small {
  font-size: 12px;
  color: #909399;
}

.not-admin {
  margin-top: 12px;
}

.create-card,
.list-card {
  height: 100%;
}
</style>

