import { createEffect, createSignal, on, type Component } from "solid-js";

import { BackupDecryptor } from "@duskflower/signal-decrypt-backup-wasm";
import { db } from "./db";

export async function decryptBackup(
  file: File,
  passphrase: string,
  progressCallback: (progres: number) => void,
) {
  const fileSize = file.size;
  console.log("Starting decryption of file size:", fileSize);
  const decryptor = new BackupDecryptor();
  decryptor.set_progress_callback(fileSize, (percentage: number) =>
    console.info(`${percentage}% done`),
  );
  const chunkSize = 1024 * 1024 * 40; // 40MB chunks
  let offset = 0;

  try {
    while (offset < file.size) {
      // console.log(`Processing chunk at offset ${offset}`);
      const chunk = file.slice(offset, offset + chunkSize);
      const arrayBuffer = await chunk.arrayBuffer();
      const uint8Array = new Uint8Array(arrayBuffer);

      decryptor.feed_data(uint8Array);

      let done = false;
      while (!done) {
        try {
          done = decryptor.process_chunk(passphrase);
        } catch (e) {
          console.error("Error processing chunk:", e);
          throw e;
        }
      }

      offset += chunkSize;
      // console.log(`Completed chunk, new offset: ${offset}`);
      // if (performance.memory) {
      //   const memoryInfo = performance.memory;
      //   console.log(`Total JS Heap Size: ${memoryInfo.totalJSHeapSize} bytes`);
      //   console.log(`Used JS Heap Size: ${memoryInfo.usedJSHeapSize} bytes`);
      //   console.log(`JS Heap Size Limit: ${memoryInfo.jsHeapSizeLimit} bytes`);
      // } else {
      //   console.log("Memory information is not available in this environment.");
      // }
    }

    // console.log("All chunks processed, finishing up");
    const result = decryptor.finish();

    // decryptor.free();

    return result;
  } catch (e) {
    console.error("Decryption failed:", e);
    throw e;
  }
}

async function decrypt(file: File, passphrase: string) {
  try {
    const result = await decryptBackup(file, passphrase, console.info);

    // console.log(result, result.database_bytes);

    // console.log("Database bytes length:", result.databaseBytes.length);
    // console.log(
    //   "Database bytes as string (partly)",
    //   new TextDecoder().decode(result.database_bytes.slice(0, 1024 * 50)),
    // );

    // console.log(result.database_statements);

    return result;
    // console.log("Preferences:", result.preferences);
    // console.log("Key values:", result.keyValues);
  } catch (error) {
    console.error("Decryption failed:", error);
  }
}

const App: Component = () => {
  const [passphrase, setPassphrase] = createSignal("");
  const [backupFile, setBackupFile] = createSignal<File>();

  createEffect(
    on(
      backupFile,
      (currentBackupFile) => {
        if (currentBackupFile) {
          decrypt(currentBackupFile, passphrase()).then((result) => {
            if (result) {
              for (const statement of result.database_statements) {
                try {
                  console.log("executing");
                  db.exec(statement);
                } catch (e) {
                  throw new Error(`statement failed: ${statement}`, {
                    cause: e,
                  });
                }
              }

              console.log("All statements executed");

              console.log(
                db.exec("SELECT * from message", {
                  returnValue: "resultRows",
                }),
              );
            }
          });
        }
      },
      {
        defer: true,
      },
    ),
  );

  return (
    <form id="test-form">
      <input
        type="password"
        id="passphrase-input"
        onChange={(event) => {
          setPassphrase(event.currentTarget.value);
        }}
      />
      <input
        type="file"
        id="backup-input"
        onChange={(event) => {
          setBackupFile(event.currentTarget.files?.[0]);
        }}
      />
    </form>
  );
};

export default App;
