#!/bin/bash
wasm-pack build --scope duskflower --release --target bundler
jq '. |= . + {"publishConfig": {"registry": "https://git.duskflower.dev/api/packages/duskflower/npm/"}}' pkg/package.json  > pkg/package.json.tmp && mv pkg/package.json.tmp pkg/package.json
