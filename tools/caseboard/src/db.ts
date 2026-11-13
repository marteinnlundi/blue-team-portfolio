import Database from "better-sqlite3";
import type { Alert, Case, TimelineEntry } from "./types.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS alerts (
  id          TEXT PRIMARY KEY,
  time        TEXT NOT NULL,
  title       TEXT NOT NULL,
  severity    TEXT NOT NULL DEFAULT 'low',
  rule_id     TEXT NOT NULL DEFAULT '',
  raw         TEXT NOT NULL DEFAULT '{}',
  case_id     TEXT,
  ingested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
  id          TEXT PRIMARY KEY,
  title       TEXT NOT NULL,
  severity    TEXT NOT NULL DEFAULT 'low',
  status      TEXT NOT NULL DEFAULT 'open',
  tags        TEXT NOT NULL DEFAULT '[]',
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_case ON alerts(case_id);

CREATE TABLE IF NOT EXISTS timeline (
  id          TEXT PRIMARY KEY,
  case_id     TEXT NOT NULL,
  kind        TEXT NOT NULL,
  content     TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  created_by  TEXT NOT NULL DEFAULT 'system',
  FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE INDEX IF NOT EXISTS idx_timeline_case ON timeline(case_id);
`;

export function openDb(path: string): Database.Database {
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA);
  return db;
}

function rowToAlert(row: Record<string, unknown>): Alert {
  return {
    id: row.id as string,
    time: row.time as string,
    title: row.title as string,
    severity: row.severity as Alert["severity"],
    ruleId: row.rule_id as string,
    raw: row.raw as string,
    caseId: row.case_id as string | null,
    ingestedAt: row.ingested_at as string,
  };
}

function rowToCase(row: Record<string, unknown>): Case {
  return {
    id: row.id as string,
    title: row.title as string,
    severity: row.severity as Case["severity"],
    status: row.status as Case["status"],
    tags: JSON.parse(row.tags as string),
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
  };
}

function rowToTimeline(row: Record<string, unknown>): TimelineEntry {
  return {
    id: row.id as string,
    caseId: row.case_id as string,
    kind: row.kind as TimelineEntry["kind"],
    content: row.content as string,
    createdAt: row.created_at as string,
    createdBy: row.created_by as string,
  };
}

export function insertAlert(db: Database.Database, alert: Alert): void {
  db.prepare(`
    INSERT OR IGNORE INTO alerts (id, time, title, severity, rule_id, raw, case_id, ingested_at)
    VALUES (@id, @time, @title, @severity, @ruleId, @raw, @caseId, @ingestedAt)
  `).run(alert);
}

/** Most severe first, then newest first: the order an analyst works the inbox in. */
const ALERT_ORDER = `
  ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
           time DESC, ingested_at DESC`;

export function listAlerts(db: Database.Database, untriagedOnly = false): Alert[] {
  const where = untriagedOnly ? "WHERE case_id IS NULL" : "";
  return (db.prepare(`SELECT * FROM alerts ${where} ${ALERT_ORDER}`).all() as Record<string, unknown>[]).map(rowToAlert);
}

export function getAlert(db: Database.Database, id: string): Alert | null {
  const row = db.prepare("SELECT * FROM alerts WHERE id = ?").get(id) as Record<string, unknown> | undefined;
  return row ? rowToAlert(row) : null;
}

export function insertCase(db: Database.Database, c: Case): void {
  db.prepare(`
    INSERT INTO cases (id, title, severity, status, tags, created_at, updated_at)
    VALUES (@id, @title, @severity, @status, @tags, @createdAt, @updatedAt)
  `).run({ ...c, tags: JSON.stringify(c.tags) });
}

export function listCases(db: Database.Database): Case[] {
  return (db.prepare("SELECT * FROM cases ORDER BY created_at DESC").all() as Record<string, unknown>[]).map(rowToCase);
}

export function getCase(db: Database.Database, id: string): Case | null {
  const row = db.prepare("SELECT * FROM cases WHERE id = ?").get(id) as Record<string, unknown> | undefined;
  return row ? rowToCase(row) : null;
}

export function updateCase(db: Database.Database, id: string, patch: Partial<Pick<Case, "title" | "severity" | "status" | "tags">>): Case | null {
  const existing = getCase(db, id);
  if (!existing) return null;
  const updated: Case = {
    ...existing,
    ...patch,
    updatedAt: new Date().toISOString(),
  };
  db.prepare(`
    UPDATE cases SET title = @title, severity = @severity, status = @status,
      tags = @tags, updated_at = @updatedAt WHERE id = @id
  `).run({ ...updated, tags: JSON.stringify(updated.tags) });
  return updated;
}

export function assignAlertToCase(db: Database.Database, alertId: string, caseId: string): void {
  db.prepare("UPDATE alerts SET case_id = ? WHERE id = ?").run(caseId, alertId);
}

export function getAlertsForCase(db: Database.Database, caseId: string): Alert[] {
  return (db.prepare(`SELECT * FROM alerts WHERE case_id = ? ${ALERT_ORDER}`).all(caseId) as Record<string, unknown>[]).map(rowToAlert);
}

export function insertTimeline(db: Database.Database, entry: TimelineEntry): void {
  db.prepare(`
    INSERT INTO timeline (id, case_id, kind, content, created_at, created_by)
    VALUES (@id, @caseId, @kind, @content, @createdAt, @createdBy)
  `).run(entry);
}

export function getTimeline(db: Database.Database, caseId: string): TimelineEntry[] {
  return (db.prepare("SELECT * FROM timeline WHERE case_id = ? ORDER BY created_at ASC, rowid ASC").all(caseId) as Record<string, unknown>[]).map(rowToTimeline);
}
