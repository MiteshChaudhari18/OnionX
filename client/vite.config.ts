import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default defineConfig({
  plugins: [react()],
  base: "/", 
  resolve: {
    alias: {
      // CORRECTED: @ is relative to the current directory
      "@": path.resolve(__dirname, "src"), 
      // CORRECTED: .. is used to look up one level for external folders
      "@shared": path.resolve(__dirname, "..", "shared"),
      "@assets": path.resolve(__dirname, "..", "attached_assets"),
    },
  },
  // CRITICAL: Anchors the project root to the 'client' folder
  root: __dirname, 
  build: {
    // CRITICAL: Tells Vite to place the files one folder up
    outDir: path.resolve(__dirname, "..", "dist/public"), 
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    fs: {
      strict: true,
      deny: ["**/.*"],
    },
  },
});
