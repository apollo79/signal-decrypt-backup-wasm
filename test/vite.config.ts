import { defineConfig } from "vite";
import solidPlugin from "vite-plugin-solid";
import wasm from "vite-plugin-wasm";

export default defineConfig({
  plugins: [solidPlugin(), wasm()],
  optimizeDeps: {
    exclude: ["signal-decrypt-backup-wasm", "@sqlite.org/sqlite-wasm"],
  },
  server: {
    port: 3000,
  },
  build: {
    target: "esnext",
  },
});
