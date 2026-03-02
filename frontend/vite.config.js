import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const apiTarget = process.env.VITE_API_URL || "http://localhost:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: "0.0.0.0",
    proxy: {
      "/auth":        { target: apiTarget, changeOrigin: true },
      "/scan":        { target: apiTarget, changeOrigin: true },
      "/credentials": { target: apiTarget, changeOrigin: true },
      "/datasets":    { target: apiTarget, changeOrigin: true },
      "/settings":    { target: apiTarget, changeOrigin: true },
      "/healthz":     { target: apiTarget, changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
