import { Router } from "express";
import { randomUUID } from "crypto";
import type Database from "better-sqlite3";
import {
  insertAlert, listAlerts, getAlert,
  insertCase, listCases, getCase, updateCase,
  assignAlertToCase, getAlertsForCase,
  insertTimeline, getTimeline,
} from "./db.js";
import { CASE_STATUSES, SEVERITIES } from "./types.js";
import type { Alert, Case, CaseExport, CaseStatus, Severity, TimelineEntry } from "./types.js";

const MAX_TEXT = 10_000;

function isText(value: unknown, max = MAX_TEXT): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.length <= max;
}

function isSeverity(value: unknown): value is Severity {
  return SEVERITIES.includes(value as Severity);
}

function isStatus(value: unknown): value is CaseStatus {
  return CASE_STATUSES.includes(value as CaseStatus);
}

function isTagList(value: unknown): value is string[] {
  return Array.isArray(value) && value.length <= 50 && value.every((tag) => isText(tag, 100));
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

export function makeRouter(db: Database.Database): Router {
  const router = Router();

  router.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  router.post("/alerts/ingest", (req, res) => {
    const body = asRecord(req.body);
    const alertDoc = asRecord(body.alert);
    const ruleDoc = asRecord(body.rule);

    if (!isText(alertDoc.title, 500)) {
      res.status(400).json({ error: "alert.title is required" });
      return;
    }
    if (typeof alertDoc.time !== "string" || Number.isNaN(Date.parse(alertDoc.time))) {
      res.status(400).json({ error: "alert.time is required and must be a timestamp" });
      return;
    }
    if (alertDoc.severity !== undefined && !isSeverity(alertDoc.severity)) {
      res.status(400).json({ error: `alert.severity must be one of ${SEVERITIES.join(", ")}` });
      return;
    }

    const alert: Alert = {
      id: `alert-${randomUUID()}`,
      time: new Date(alertDoc.time).toISOString(),
      title: alertDoc.title,
      severity: alertDoc.severity ?? "low",
      ruleId: isText(ruleDoc.id, 200) ? ruleDoc.id : "",
      raw: JSON.stringify(body),
      caseId: null,
      ingestedAt: new Date().toISOString(),
    };

    insertAlert(db, alert);
    res.status(201).json(alert);
  });

  router.get("/alerts", (req, res) => {
    const untriaged = req.query["untriaged"] === "true";
    res.json(listAlerts(db, untriaged));
  });

  router.get("/alerts/:id", (req, res) => {
    const alert = getAlert(db, req.params.id);
    if (!alert) { res.status(404).json({ error: "not found" }); return; }
    res.json(alert);
  });

  router.post("/cases", (req, res) => {
    const body = asRecord(req.body);
    if (!isText(body.title, 500)) {
      res.status(400).json({ error: "title is required" });
      return;
    }
    if (body.severity !== undefined && !isSeverity(body.severity)) {
      res.status(400).json({ error: `severity must be one of ${SEVERITIES.join(", ")}` });
      return;
    }
    if (body.tags !== undefined && !isTagList(body.tags)) {
      res.status(400).json({ error: "tags must be a list of strings" });
      return;
    }
    const alertIds = body.alertIds ?? [];
    if (!Array.isArray(alertIds) || !alertIds.every((id) => typeof id === "string")) {
      res.status(400).json({ error: "alertIds must be a list of alert ids" });
      return;
    }
    const unknown = (alertIds as string[]).filter((id) => !getAlert(db, id));
    if (unknown.length > 0) {
      res.status(404).json({ error: `unknown alert id(s): ${unknown.join(", ")}` });
      return;
    }

    const now = new Date().toISOString();
    const c: Case = {
      id: `case-${randomUUID()}`,
      title: body.title.trim(),
      severity: body.severity ?? "low",
      status: "open",
      tags: body.tags ?? [],
      createdAt: now,
      updatedAt: now,
    };

    db.transaction(() => {
      insertCase(db, c);
      for (const aid of alertIds as string[]) {
        assignAlertToCase(db, aid, c.id);
        insertTimeline(db, {
          id: `tl-${randomUUID()}`,
          caseId: c.id,
          kind: "alert",
          content: `Alert ${aid} added to case`,
          createdAt: now,
          createdBy: "system",
        });
      }
    })();

    res.status(201).json(c);
  });

  router.get("/cases", (_req, res) => {
    res.json(listCases(db));
  });

  router.get("/cases/:id", (req, res) => {
    const c = getCase(db, req.params.id);
    if (!c) { res.status(404).json({ error: "not found" }); return; }
    res.json({ ...c, alerts: getAlertsForCase(db, c.id), timeline: getTimeline(db, c.id) });
  });

  router.patch("/cases/:id", (req, res) => {
    const body = asRecord(req.body);
    const patch: Partial<Pick<Case, "title" | "severity" | "status" | "tags">> = {};

    if (body.title !== undefined) {
      if (!isText(body.title, 500)) { res.status(400).json({ error: "title must be a non-empty string" }); return; }
      patch.title = body.title.trim();
    }
    if (body.severity !== undefined) {
      if (!isSeverity(body.severity)) { res.status(400).json({ error: `severity must be one of ${SEVERITIES.join(", ")}` }); return; }
      patch.severity = body.severity;
    }
    if (body.status !== undefined) {
      if (!isStatus(body.status)) { res.status(400).json({ error: `status must be one of ${CASE_STATUSES.join(", ")}` }); return; }
      patch.status = body.status;
    }
    if (body.tags !== undefined) {
      if (!isTagList(body.tags)) { res.status(400).json({ error: "tags must be a list of strings" }); return; }
      patch.tags = body.tags;
    }

    const before = getCase(db, req.params.id);
    if (!before) { res.status(404).json({ error: "not found" }); return; }
    const updated = updateCase(db, req.params.id, patch);
    if (!updated) { res.status(404).json({ error: "not found" }); return; }

    if (patch.status && patch.status !== before.status) {
      insertTimeline(db, {
        id: `tl-${randomUUID()}`,
        caseId: req.params.id,
        kind: "status_change",
        content: `Status changed from ${before.status} to ${patch.status}`,
        createdAt: new Date().toISOString(),
        createdBy: "analyst",
      });
    }

    res.json(updated);
  });

  router.post("/cases/:id/alerts", (req, res) => {
    const body = asRecord(req.body);
    if (typeof body.alertId !== "string") { res.status(400).json({ error: "alertId is required" }); return; }
    if (!getCase(db, req.params.id)) { res.status(404).json({ error: "case not found" }); return; }
    if (!getAlert(db, body.alertId)) { res.status(404).json({ error: "alert not found" }); return; }

    assignAlertToCase(db, body.alertId, req.params.id);
    insertTimeline(db, {
      id: `tl-${randomUUID()}`,
      caseId: req.params.id,
      kind: "alert",
      content: `Alert ${body.alertId} linked to case`,
      createdAt: new Date().toISOString(),
      createdBy: "system",
    });

    res.json({ ok: true });
  });

  router.post("/cases/:id/notes", (req, res) => {
    const body = asRecord(req.body);
    if (!isText(body.content)) { res.status(400).json({ error: "content is required" }); return; }
    if (!getCase(db, req.params.id)) { res.status(404).json({ error: "not found" }); return; }

    const entry: TimelineEntry = {
      id: `tl-${randomUUID()}`,
      caseId: req.params.id,
      kind: "note",
      content: body.content,
      createdAt: new Date().toISOString(),
      createdBy: isText(body.author, 100) ? body.author.trim() : "analyst",
    };
    insertTimeline(db, entry);
    res.status(201).json(entry);
  });

  router.post("/cases/:id/evidence", (req, res) => {
    const body = asRecord(req.body);
    if (!isText(body.ref, 2000)) { res.status(400).json({ error: "ref is required" }); return; }
    if (!getCase(db, req.params.id)) { res.status(404).json({ error: "not found" }); return; }

    const entry: TimelineEntry = {
      id: `tl-${randomUUID()}`,
      caseId: req.params.id,
      kind: "evidence",
      content: JSON.stringify({ ref: body.ref, description: isText(body.description) ? body.description : "" }),
      createdAt: new Date().toISOString(),
      createdBy: "analyst",
    };
    insertTimeline(db, entry);
    res.status(201).json(entry);
  });

  router.get("/cases/:id/export", (req, res) => {
    const c = getCase(db, req.params.id);
    if (!c) { res.status(404).json({ error: "not found" }); return; }

    const exportData: CaseExport = {
      case: c,
      alerts: getAlertsForCase(db, c.id),
      timeline: getTimeline(db, c.id),
      exportedAt: new Date().toISOString(),
    };
    res.json(exportData);
  });

  return router;
}
