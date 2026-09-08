import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins: [react()],
  base: "/dashboard/static/react/",
  server: {
    port: 5174,
    strictPort: true,
    host: "127.0.0.1",
    proxy: {
      "^/dashboard/(?!static/react)": {
        target: process.env.AGENTDECOMPILE_BACKEND || "http://127.0.0.1:8080",
        changeOrigin: true,
      },
      "/api": {
        target: process.env.AGENTDECOMPILE_BACKEND || "http://127.0.0.1:8080",
        changeOrigin: true,
      },
      "/atlas": {
        target: process.env.AGENTDECOMPILE_BACKEND || "http://127.0.0.1:8080",
        changeOrigin: true,
      },
    },
  },
  build: { outDir: "../static/react", emptyOutDir: true, sourcemap: false },
});
