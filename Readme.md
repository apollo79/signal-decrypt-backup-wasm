# signal-decrypt-backup-rust
A port of [https://github.com/mossblaser/signal_for_android_decryption](signal_for_android_decryption) in Rust for wasm.

This port was done for speed improvements and easier integration with wasm. A big part was done using AI.

The cli version is available at [https://git.duskflower.dev/duskflower/signal-decrypt-backup-rust](duskflower/signal-decrypt-backup-wasm)

## Build
You need `wasm-pack` installed. If you don't have it installed, you can install it using `cargo install wasm-pack`

```
wasm-pack build --target web
```

This will generate the usable js and wasm file in ./pkg
