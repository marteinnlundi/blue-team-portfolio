import { openDb } from "./db.js";
import { createApp } from "./app.js";

const PORT = Number(process.env["PORT"] ?? 3000);
// Caseboard has no authentication, so it only listens on loopback unless told otherwise.
const HOST = process.env["HOST"] ?? "127.0.0.1";
const DB_PATH = process.env["CASEBOARD_DB"] ?? "caseboard.db";

const db = openDb(DB_PATH);
const app = createApp(db);

const server = app.listen(PORT, HOST, () => {
  console.log(`caseboard listening on http://${HOST}:${PORT} (db: ${DB_PATH})`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    server.close(() => {
      db.close();
      process.exit(0);
    });
  });
}
