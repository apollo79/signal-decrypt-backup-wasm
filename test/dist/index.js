import init, { BackupDecryptor } from "../pkg/signal_decrypt_backup_wasm.js";

let isInitialized = false;

async function initialize() {
  if (!isInitialized) {
    await init().catch((err) =>
      console.error("Failed to initialize WASM module: ", err),
    );
    isInitialized = true;
  }
}

export async function decryptBackup(file, passphrase, progressCallback) {
  await initialize();

  console.log("Starting decryption of file size:", file.size);
  const decryptor = new BackupDecryptor();
  const chunkSize = 1024 * 1024 * 40; // 40MB chunks
  let offset = 0;
  let percent;

  try {
    while (offset < file.size) {
      const newPercent = Math.round((100 / file.size) * offset);

      if (newPercent !== percent) {
        percent = newPercent;
        console.info(`${percent}% done`);
      }

      console.log(`Processing chunk at offset ${offset}`);
      const chunk = file.slice(offset, offset + chunkSize);
      const arrayBuffer = await chunk.arrayBuffer();
      const uint8Array = new Uint8Array(arrayBuffer);

      decryptor.feed_data(uint8Array);

      let done = false;
      while (!done) {
        try {
          done = await decryptor.process_chunk(passphrase, progressCallback);
        } catch (e) {
          console.error("Error processing chunk:", e);
          throw e;
        }
      }

      offset += chunkSize;
      console.log(`Completed chunk, new offset: ${offset}`);
      if (performance.memory) {
        const memoryInfo = performance.memory;
        console.log(`Total JS Heap Size: ${memoryInfo.totalJSHeapSize} bytes`);
        console.log(`Used JS Heap Size: ${memoryInfo.usedJSHeapSize} bytes`);
        console.log(`JS Heap Size Limit: ${memoryInfo.jsHeapSizeLimit} bytes`);
      } else {
        console.log("Memory information is not available in this environment.");
      }
    }

    console.log("All chunks processed, finishing up");
    console.log(window.performance.measureUserAgentSpecificMemory());
    return decryptor.finish();
  } catch (e) {
    console.error("Decryption failed:", e);
    throw e;
  }
}

async function decrypt(file, passphrase) {
  try {
    const result = await decryptBackup(file, passphrase);

    console.log("Database bytes length:", result.databaseBytes.length);
    console.log("Preferences:", result.preferences);
    console.log("Key values:", result.keyValues);

    // Example: Convert database bytes to SQL statements
    const sqlStatements = new TextDecoder().decode(result.databaseBytes);
    console.log("SQL statements:", sqlStatements);
  } catch (error) {
    console.error("Decryption failed:", error);
  }
}

/**
 * @type {HTMLInputElement}
 */
const passphraseInput = document.querySelector("#passphrase-input");
/**
 * @type {HTMLInputElement}
 */
const backupInput = document.querySelector("#backup-input");

backupInput.addEventListener("change", (event) => {
  const file = event.currentTarget.files[0];

  decrypt(file, passphraseInput.value);
});
