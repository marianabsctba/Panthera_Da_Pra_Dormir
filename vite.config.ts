import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Caminhos relativos: funciona em qualquer nome de repositório no GitHub Pages.
export default defineConfig({
  base: "./",
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false, target: "es2022" },
});
