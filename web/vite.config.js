import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/health": "http://127.0.0.1:8000",
      "/import": "http://127.0.0.1:8000",
      "/forecast": "http://127.0.0.1:8000",
      "/graph": "http://127.0.0.1:8000",
      "/heatmap": "http://127.0.0.1:8000",
    },
  },
});
