import type Database from "better-sqlite3";
import { lookupIoc } from "./db.js";
import { makeAlert } from "./alert.js";
import type { Alert, NormalizedEvent } from "./types.js";

function candidatesFromEvent(event: NormalizedEvent): Array<{ type: string; value: string }> {
  const candidates: Array<{ type: string; value: string }> = [];

  if (event.network?.src_ip) candidates.push({ type: "ip", value: event.network.src_ip.toLowerCase() });
  if (event.network?.dst_ip) candidates.push({ type: "ip", value: event.network.dst_ip.toLowerCase() });

  if (event.process?.command_line) {
    const domainRe = /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b/gi;
    for (const match of event.process.command_line.matchAll(domainRe)) {
      candidates.push({ type: "domain", value: match[1].toLowerCase() });
    }
  }

  return candidates;
}

export function matchEvent(db: Database.Database, event: NormalizedEvent): Alert[] {
  const alerts: Alert[] = [];
  const seen = new Set<string>();

  for (const { type, value } of candidatesFromEvent(event)) {
    const key = `${type}:${value}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const ioc = lookupIoc(db, type, value);
    if (ioc) alerts.push(makeAlert(event, ioc));
  }

  return alerts;
}
