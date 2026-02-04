import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 3000,
    proxy: {
      // Proxy API and backend endpoints to backend during development
      "/api": "http://localhost:8000",
      "/health": "http://localhost:8000",
      "/config": "http://localhost:8000",
      "/ws": {
        target: "ws://localhost:8000",
        ws: true,
      },
    },
  },
});
