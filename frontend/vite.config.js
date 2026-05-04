import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Where the dev-server proxy should forward backend calls.
// VITE_API_URL is empty in compose (used as a runtime hint for the browser to
// use same-origin URLs), so we use VITE_PROXY_TARGET for the dev proxy itself.
const apiTarget =
  process.env.VITE_PROXY_TARGET ||
  process.env.VITE_API_URL ||
  "http://backend:8888";  // works inside the docker network; falls back to localhost outside

const proxyOpts = { target: apiTarget, changeOrigin: true };

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: "0.0.0.0",
    allowedHosts: true,
    proxy: {
      "/auth":          proxyOpts,
      "/scan":          proxyOpts,
      "/credentials":   proxyOpts,
      "/datasets":      proxyOpts,
      "/settings":      proxyOpts,
      "/healthz":       proxyOpts,
      "/ai":            proxyOpts,
      "/graph":         proxyOpts,
      "/integrations":  proxyOpts,
      "/api-scanner":   proxyOpts,
      "/assets":        proxyOpts,
      "/reports":       proxyOpts,
      "/events":        proxyOpts,
      "/threat-intel":  proxyOpts,
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
