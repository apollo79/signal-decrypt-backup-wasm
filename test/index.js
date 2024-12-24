const server = Bun.serve({
  static: {
    "/": new Response(await Bun.file("./dist/index.html").bytes(), {
      headers: {
        "Content-Type": "text/html",
      },
    }),
    "/index.js": new Response(await Bun.file("./dist/index.js").bytes(), {
      headers: {
        "Content-Type": "text/javascript",
      },
    }),
    "/pkg/signal_decrypt_backup_wasm.js": new Response(
      await Bun.file("../pkg/signal_decrypt_backup_wasm.js").bytes(),
      {
        headers: {
          "Content-Type": "text/javascript",
        },
      },
    ),
    "/pkg/signal_decrypt_backup_wasm_bg.wasm": new Response(
      await Bun.file("../pkg/signal_decrypt_backup_wasm_bg.wasm").bytes(),
      {
        headers: {
          "Content-Type": "application/wasm",
        },
      },
    ),
  },
  fetch(req) {
    console.log(req);
    return new Response("404!");
  },
});
