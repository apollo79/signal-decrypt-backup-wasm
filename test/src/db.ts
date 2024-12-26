import sqlite3InitModule, {
  type Database,
  type OpfsDatabase,
} from "@sqlite.org/sqlite-wasm";

export let db: OpfsDatabase | Database;

const sqlite3 = (await sqlite3InitModule()).oo1;
if (!sqlite3) {
  throw new Error("fail to load sqlite");
}
const path = "/signal.db";

if (sqlite3.OpfsDb) {
  console.log("support OPFS");
  db = new sqlite3.OpfsDb(path);
}

console.log("doesn't support OPFS");

db = new sqlite3.DB(path);
