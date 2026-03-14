<template>
  <div class="login-container">
    <el-card class="login-card" shadow="hover">
      <div class="login-header">
        <h2>用户登录</h2>
        <p class="login-subtitle">
          使用 admin/readonly 账号登录，默认初始账号为 admin / admin
        </p>
      </div>

      <el-form
        :model="form"
        :rules="rules"
        ref="formRef"
        label-width="80px"
        class="login-form"
      >
        <el-form-item label="用户名" prop="username">
          <el-input
            v-model="form.username"
            autocomplete="username"
            placeholder="例如：admin"
          />
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input
            v-model="form.password"
            type="password"
            show-password
            autocomplete="current-password"
            placeholder="例如：admin"
          />
        </el-form-item>
        <el-form-item>
          <el-button
            type="primary"
            :loading="loading"
            class="login-btn"
            @click="handleLogin"
          >
            登录
          </el-button>
          <el-button class="reset-btn" @click="reset">
            重置
          </el-button>
        </el-form-item>
      </el-form>

      <div v-if="currentUser" class="current-user">
        <el-alert
          type="success"
          :closable="false"
          show-icon
          title="当前已登录用户"
        >
          <template #default>
            <div class="current-user-body">
              <span>用户名：{{ currentUser.username }}</span>
              <span>角色：{{ currentUser.role }}</span>
            </div>
          </template>
        </el-alert>
      </div>
    </el-card>
  </div>
</template>

<script>
import { ref } from "vue";
import { ElMessage } from "element-plus";

export default {
  setup() {
    const apiBase = "";
    const form = ref({
      username: "",
      password: "",
    });
    const formRef = ref(null);
    const loading = ref(false);
    const currentUser = ref(null);

    const rules = {
      username: [{ required: true, message: "请输入用户名", trigger: "blur" }],
      password: [{ required: true, message: "请输入密码", trigger: "blur" }],
    };

    const fetchCurrentUser = async () => {
      const token = localStorage.getItem("ids_token");
      if (!token) {
        currentUser.value = null;
        return;
      }
      try {
        const resp = await fetch(`${apiBase}/api/auth/me`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
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

    const handleLogin = () => {
      if (!formRef.value) return;
      formRef.value.validate(async (valid) => {
        if (!valid) return;
        loading.value = true;
        try {
          const body = new URLSearchParams();
          body.append("username", form.value.username);
          body.append("password", form.value.password);
          body.append("grant_type", "");
          body.append("scope", "");
          body.append("client_id", "");
          body.append("client_secret", "");

          const resp = await fetch(`${apiBase}/api/auth/login`, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body,
          });
          if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            ElMessage.error(err.detail || "登录失败");
            return;
          }
          const data = await resp.json();
          if (data.access_token) {
            localStorage.setItem("ids_token", data.access_token);
            ElMessage.success("登录成功");
            await fetchCurrentUser();
            // 登录成功后跳转到首页
            window.location.hash = "#/home";
            window.location.reload();
          } else {
            ElMessage.error("登录响应异常");
          }
        } catch (e) {
          console.error("登录失败:", e);
          ElMessage.error("登录失败");
        } finally {
          loading.value = false;
        }
      });
    };

    const reset = () => {
      form.value.username = "";
      form.value.password = "";
      if (formRef.value) {
        formRef.value.clearValidate();
      }
    };

    // 初次进入页面时尝试获取当前用户信息
    fetchCurrentUser();

    return {
      apiBase,
      form,
      formRef,
      rules,
      loading,
      handleLogin,
      reset,
      currentUser,
    };
  },
};
</script>

<style scoped>
.login-container {
  display: flex;
  justify-content: center;
  align-items: flex-start;
  padding-top: 40px;
}

.login-card {
  width: 420px;
}

.login-header {
  margin-bottom: 16px;
}

.login-header h2 {
  margin: 0 0 4px;
  font-size: 20px;
  font-weight: 600;
  color: #303133;
}

.login-subtitle {
  margin: 0;
  font-size: 13px;
  color: #909399;
}

.login-form {
  margin-top: 8px;
}

.login-btn {
  width: 120px;
}

.reset-btn {
  margin-left: 12px;
}

.current-user {
  margin-top: 16px;
}

.current-user-body {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 13px;
}
</style>

