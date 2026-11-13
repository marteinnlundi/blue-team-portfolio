#!/usr/bin/env node
import { createInterface } from "readline";
import { openDb, upsertIocs, deleteExpired, countIocs } from "./db.js";
import { parseFeedFile } from "./stix.js";
import { matchEvent } from "./match.js";
import type { NormalizedEvent } from "./types.js";

const DB_PATH = process.env["IOC_DB"] ?? "ioc-feed.db";

const USAGE = `Usage:
  ioc-feed ingest <feed.stix.json>   load a STIX 2.1 bundle into the database
  ioc-feed match [--feed <file>]     read events (JSONL) from stdin, write an alert for every IOC match
  ioc-feed purge                     remove expired IOCs from the database

Environment:
  IOC_DB   path of the SQLite database (default: ioc-feed.db, use ":memory:" for none)`;

/** Wrong usage or unreadable input: exit code 2, as in docs/standards/logging_style.md. */
class UsageError extends Error {}

function loadFeed(feedPath: string) {
  try {
    return parseFeedFile(feedPath);
  } catch (err) {
    throw new UsageError(`cannot read feed ${feedPath}: ${(err as Error).message}`);
  }
}

function cmdIngest(feedPath: string): void {
  const iocs = loadFeed(feedPath);
  const db = openDb(DB_PATH);
  const n = upsertIocs(db, iocs);
  console.error(`ioc-feed: ingested ${n} IOC(s) from ${feedPath}; ${countIocs(db)} in ${DB_PATH}`);
}

async function cmdMatch(feedPath: string | null): Promise<void> {
  const iocs = feedPath ? loadFeed(feedPath) : [];
  const db = openDb(DB_PATH);
  if (feedPath) {
    upsertIocs(db, iocs);
    console.error(`ioc-feed: ingested ${iocs.length} IOC(s) from ${feedPath}`);
  }

  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let event: NormalizedEvent;
    try {
      event = JSON.parse(trimmed);
    } catch {
      continue;
    }
    if (typeof event !== "object" || event === null) continue;
    for (const alert of matchEvent(db, event)) {
      process.stdout.write(JSON.stringify(alert) + "\n");
    }
  }
}

function cmdPurge(): void {
  const db = openDb(DB_PATH);
  console.error(`ioc-feed: purged ${deleteExpired(db)} expired IOC(s)`);
}

async function main(): Promise<void> {
  const [, , cmd, ...rest] = process.argv;

  if (cmd === "ingest" && rest[0]) {
    cmdIngest(rest[0]);
  } else if (cmd === "match") {
    const feedIdx = rest.indexOf("--feed");
    if (feedIdx !== -1 && !rest[feedIdx + 1]) throw new UsageError("--feed needs a file");
    await cmdMatch(feedIdx !== -1 ? rest[feedIdx + 1] : null);
  } else if (cmd === "purge") {
    cmdPurge();
  } else if (cmd === "--help" || cmd === "-h") {
    console.log(USAGE);
  } else {
    throw new UsageError(USAGE);
  }
}

main().catch((err) => {
  if (err instanceof UsageError) {
    console.error(err.message.startsWith("Usage") ? err.message : `ioc-feed: ${err.message}`);
    process.exit(2);
  }
  console.error(err);
  process.exit(1);
});
