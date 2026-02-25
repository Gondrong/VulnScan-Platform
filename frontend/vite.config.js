import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// VITE_API_URL is the target for Vite's *server-side* proxy.
// Inside Docker Compose this is set to http://backend:8080 (service name).
// Outside Docker (bare npm run dev) it falls back to http://localhost:8080.
const apiTarget = process.env.VITE_API_URL || "http://localhost:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: "0.0.0.0", // bind to all interfaces so LAN access works
    proxy: {
      // All API paths are proxied server-side — no CORS needed in dev.
      // The browser just hits the Vite dev server (port 5173) for everything.
      "/auth":        { target: apiTarget, changeOrigin: true },
      "/scan":        { target: apiTarget, changeOrigin: true },
      "/credentials": { target: apiTarget, changeOrigin: true },
      "/datasets":    { target: apiTarget, changeOrigin: true },
      "/healthz":     { target: apiTarget, changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
