import { createApp } from "vue";
import App from "./App.vue";
import ElementPlus from "element-plus";
import "element-plus/dist/index.css";

// 1. 引入图标库
import * as ElementPlusIconsVue from "@element-plus/icons-vue";

const app = createApp(App);

// 2. 循环注册所有图标
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
  app.component(key, component);
}

app.use(ElementPlus);

// 3. 全局错误处理：防止未捕获的错误导致页面崩溃或无法切换路由
app.config.errorHandler = (err, instance, info) => {
  console.error("Vue Error:", err);
  console.error("Error Info:", info);
  // 错误不会导致整个应用崩溃，组件会继续工作
};

// 4. 全局未处理的 Promise 拒绝处理
window.addEventListener("unhandledrejection", (event) => {
  console.error("Unhandled Promise Rejection:", event.reason);
  // 不阻止默认行为，但记录错误
});

app.mount("#app");
