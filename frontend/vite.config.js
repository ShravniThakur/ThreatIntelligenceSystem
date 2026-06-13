import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev: Vite on :5173 talks to the FastAPI backend on :8001 (CORS is open there).
// Build: emits to frontend/dist, which the backend serves same-origin at :8001
// (see FRONTEND_DIR in backend/main.py). `base: "./"` keeps asset URLs relative
// so the SPA works under the static mount.
export default defineConfig({
  plugins: [react()],
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    open: true,
  },
});
