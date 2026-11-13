import Database from "better-sqlite3";
import type { Ioc } from "./types.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS iocs (
  id          TEXT NOT NULL,
  type        TEXT NOT NULL,
  value       TEXT NOT NULL,
  source      TEXT NOT NULL DEFAULT '',
  confidence  INTEGER NOT NULL DEFAULT 50,
  valid_from  TEXT NOT NULL,
  valid_until TEXT,
  labels      TEXT NOT NULL DEFAULT '[]',
  description TEXT NOT NULL DEFAULT '',
  ingested_at TEXT NOT NULL,
  PRIMARY KEY (type, value)
);
`;

export function openDb(path: string): Database.Database {
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.exec(SCHEMA);
  return db;
}

export function upsertIocs(db: Database.Database, iocs: Ioc[]): number {
  const stmt = db.prepare(`
    INSERT INTO iocs (id, type, value, source, confidence, valid_from, valid_until, labels, description, ingested_at)
    VALUES (@id, @type, @value, @source, @confidence, @validFrom, @validUntil, @labels, @description, @ingestedAt)
    ON CONFLICT(type, value) DO UPDATE SET
      source      = excluded.source,
      confidence  = excluded.confidence,
      valid_from  = excluded.valid_from,
      valid_until = excluded.valid_until,
      labels      = excluded.labels,
      description = excluded.description,
      ingested_at = excluded.ingested_at
  `);

  const insertMany = db.transaction((rows: Ioc[]) => {
    let count = 0;
    for (const row of rows) {
      stmt.run({ ...row, labels: JSON.stringify(row.labels) });
      count++;
    }
    return count;
  });

  return insertMany(iocs);
}

export function lookupIoc(
  db: Database.Database,
  type: string,
  value: string
): Ioc | null {
  const now = new Date().toISOString();
  const row = db
    .prepare(
      `SELECT * FROM iocs
       WHERE type = ? AND value = ?
       AND (valid_until IS NULL OR valid_until > ?)
       AND valid_from <= ?`
    )
    .get(type, value, now, now) as Record<string, unknown> | undefined;

  if (!row) return null;

  return {
    id: row.id as string,
    type: row.type as Ioc["type"],
    value: row.value as string,
    source: row.source as string,
    confidence: row.confidence as number,
    validFrom: row.valid_from as string,
    validUntil: row.valid_until as string | null,
    labels: JSON.parse(row.labels as string),
    description: row.description as string,
    ingestedAt: row.ingested_at as string,
  };
}

export function countIocs(db: Database.Database): number {
  const row = db.prepare("SELECT COUNT(*) as n FROM iocs").get() as { n: number };
  return row.n;
}

export function deleteExpired(db: Database.Database): number {
  const now = new Date().toISOString();
  const info = db
    .prepare("DELETE FROM iocs WHERE valid_until IS NOT NULL AND valid_until <= ?")
    .run(now);
  return info.changes;
}
