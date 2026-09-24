import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In development the Vite dev server proxies /api to the FastAPI app, so the
// browser talks to one origin and no CORS configuration is needed. In
// production FastAPI serves the built `dist/` itself (see main.py).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: process.env.VITE_API_TARGET ?? "http://127.0.0.1:8000", changeOrigin: true },
    },
  },
});
