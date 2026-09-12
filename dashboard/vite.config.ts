import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dev server proxies to the control plane so the dashboard runs on :5173
// against a backend on :8080 without CORS games. In production the built
// assets are served by whatever fronts the control plane (see
// deploy/docker/Dockerfile.dashboard) and API calls are same-origin.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: process.env.KEEPER_API ?? "http://localhost:8080", changeOrigin: true },
      "/health": { target: process.env.KEEPER_API ?? "http://localhost:8080", changeOrigin: true },
    },
  },
  build: { outDir: "dist", sourcemap: true, target: "es2020" },
});
