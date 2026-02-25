import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// API target for dev proxy — override with VITE_API_URL env var
const apiTarget =
  process.env.VITE_API_URL || "http://localhost:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: "0.0.0.0", // bind to all interfaces so LAN access works
    proxy: {
      // Proxy /auth, /scan, /credentials, /datasets, /healthz to backend
      // This avoids CORS in development entirely
      "/auth": { target: apiTarget, changeOrigin: true },
      "/scan": { target: apiTarget, changeOrigin: true },
      "/credentials": { target: apiTarget, changeOrigin: true },
      "/datasets": { target: apiTarget, changeOrigin: true },
      "/healthz": { target: apiTarget, changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
