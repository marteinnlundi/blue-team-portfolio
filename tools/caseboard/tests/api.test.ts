import { describe, expect, it } from "vitest";
import request from "supertest";
import { openDb } from "../src/db.js";
import { createApp } from "../src/app.js";

function makeApp() {
  const db = openDb(":memory:");
  return { app: createApp(db), db };
}

const SAMPLE_ALERT = {
  alert: {
    time: "2025-05-01T10:00:00Z",
    title: "SSH Brute Force",
    severity: "high",
  },
  rule: { id: "auth-anom-brute-force" },
  host: { name: "prod-server" },
  user: { name: "root" },
};

describe("POST /api/alerts/ingest", () => {
  it("ingests a valid alert and returns 201", async () => {
    const { app } = makeApp();
    const res = await request(app).post("/api/alerts/ingest").send(SAMPLE_ALERT);
    expect(res.status).toBe(201);
    expect(res.body.title).toBe("SSH Brute Force");
    expect(res.body.severity).toBe("high");
    expect(res.body.ruleId).toBe("auth-anom-brute-force");
    expect(res.body.caseId).toBeNull();
  });

  it("returns 400 when alert.title is missing", async () => {
    const { app } = makeApp();
    const res = await request(app).post("/api/alerts/ingest").send({ alert: { time: "2025-01-01T00:00:00Z" } });
    expect(res.status).toBe(400);
  });
});

describe("GET /api/alerts", () => {
  it("returns all ingested alerts", async () => {
    const { app } = makeApp();
    await request(app).post("/api/alerts/ingest").send(SAMPLE_ALERT);
    await request(app).post("/api/alerts/ingest").send({ ...SAMPLE_ALERT, alert: { ...SAMPLE_ALERT.alert, title: "Alert 2" } });
    const res = await request(app).get("/api/alerts");
    expect(res.status).toBe(200);
    expect(res.body.length).toBe(2);
  });

  it("filters to untriaged when ?untriaged=true", async () => {
    const { app } = makeApp();
    const a1 = (await request(app).post("/api/alerts/ingest").send(SAMPLE_ALERT)).body;
    await request(app).post("/api/alerts/ingest").send({ ...SAMPLE_ALERT, alert: { ...SAMPLE_ALERT.alert, title: "Alert 2" } });

    await request(app).post("/api/cases").send({ title: "Test Case", alertIds: [a1.id] });

    const res = await request(app).get("/api/alerts?untriaged=true");
    expect(res.body.length).toBe(1);
    expect(res.body[0].title).toBe("Alert 2");
  });
});

describe("POST /api/cases", () => {
  it("creates a case with linked alerts", async () => {
    const { app } = makeApp();
    const alert = (await request(app).post("/api/alerts/ingest").send(SAMPLE_ALERT)).body;

    const res = await request(app).post("/api/cases").send({
      title: "Incident: Brute Force on prod-server",
      severity: "high",
      alertIds: [alert.id],
    });

    expect(res.status).toBe(201);
    expect(res.body.title).toBe("Incident: Brute Force on prod-server");
    expect(res.body.status).toBe("open");
  });

  it("returns 400 when title is missing", async () => {
    const { app } = makeApp();
    const res = await request(app).post("/api/cases").send({ severity: "high" });
    expect(res.status).toBe(400);
  });
});

describe("GET /api/cases/:id", () => {
  it("returns case with linked alerts and timeline", async () => {
    const { app } = makeApp();
    const alert = (await request(app).post("/api/alerts/ingest").send(SAMPLE_ALERT)).body;
    const c = (await request(app).post("/api/cases").send({ title: "Case", alertIds: [alert.id] })).body;

    const res = await request(app).get(`/api/cases/${c.id}`);
    expect(res.status).toBe(200);
    expect(res.body.alerts).toHaveLength(1);
    expect(res.body.timeline.length).toBeGreaterThanOrEqual(1);
  });

  it("returns 404 for unknown case", async () => {
    const { app } = makeApp();
    const res = await request(app).get("/api/cases/case-does-not-exist");
    expect(res.status).toBe(404);
  });
});

describe("PATCH /api/cases/:id", () => {
  it("updates status and logs a timeline entry", async () => {
    const { app } = makeApp();
    const c = (await request(app).post("/api/cases").send({ title: "My Case" })).body;

    const res = await request(app).patch(`/api/cases/${c.id}`).send({ status: "investigating" });
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("investigating");

    const detail = await request(app).get(`/api/cases/${c.id}`);
    const statusEntry = detail.body.timeline.find((e: { kind: string }) => e.kind === "status_change");
    expect(statusEntry).toBeDefined();
  });
});

describe("POST /api/cases/:id/notes", () => {
  it("adds a note to the timeline", async () => {
    const { app } = makeApp();
    const c = (await request(app).post("/api/cases").send({ title: "My Case" })).body;

    const res = await request(app)
      .post(`/api/cases/${c.id}/notes`)
      .send({ content: "Checked firewall logs, no lateral movement observed." });
    expect(res.status).toBe(201);
    expect(res.body.kind).toBe("note");
    expect(res.body.content).toContain("firewall");
  });
});

describe("POST /api/cases/:id/evidence", () => {
  it("attaches an evidence reference to the timeline", async () => {
    const { app } = makeApp();
    const c = (await request(app).post("/api/cases").send({ title: "My Case" })).body;

    const res = await request(app)
      .post(`/api/cases/${c.id}/evidence`)
      .send({ ref: "/cases/2025-05-01/pcap.tar.gz", description: "Full packet capture" });
    expect(res.status).toBe(201);
    expect(res.body.kind).toBe("evidence");
    const parsed = JSON.parse(res.body.content);
    expect(parsed.ref).toBe("/cases/2025-05-01/pcap.tar.gz");
  });
});

describe("GET /api/cases/:id/export", () => {
  it("exports a full case summary as JSON", async () => {
    const { app } = makeApp();
    const alert = (await request(app).post("/api/alerts/ingest").send(SAMPLE_ALERT)).body;
    const c = (await request(app).post("/api/cases").send({ title: "Export Test", alertIds: [alert.id] })).body;
    await request(app).post(`/api/cases/${c.id}/notes`).send({ content: "Investigation note" });

    const res = await request(app).get(`/api/cases/${c.id}/export`);
    expect(res.status).toBe(200);
    expect(res.body.case.id).toBe(c.id);
    expect(res.body.alerts).toHaveLength(1);
    expect(res.body.timeline.length).toBeGreaterThan(0);
    expect(res.body.exportedAt).toBeDefined();
  });
});

describe("input validation", () => {
  it("rejects an alert with an unknown severity", async () => {
    const { app } = makeApp();
    const res = await request(app)
      .post("/api/alerts/ingest")
      .send({ alert: { time: "2025-01-01T00:00:00Z", title: "x", severity: "<img src=x onerror=alert(1)>" } });
    expect(res.status).toBe(400);
  });

  it("rejects an alert with an invalid timestamp", async () => {
    const { app } = makeApp();
    const res = await request(app).post("/api/alerts/ingest").send({ alert: { time: "yesterday-ish", title: "x" } });
    expect(res.status).toBe(400);
  });

  it("defaults severity to low and stores the raw alert", async () => {
    const { app } = makeApp();
    const res = await request(app)
      .post("/api/alerts/ingest")
      .send({ alert: { time: "2025-01-01T00:00:00Z", title: "x" }, host: { name: "h" } });
    expect(res.status).toBe(201);
    expect(res.body.severity).toBe("low");
    expect(JSON.parse(res.body.raw).host.name).toBe("h");
  });

  it("rejects a case with an invalid severity", async () => {
    const { app } = makeApp();
    const res = await request(app).post("/api/cases").send({ title: "x", severity: "urgent" });
    expect(res.status).toBe(400);
  });

  it("rejects a case that references an unknown alert", async () => {
    const { app } = makeApp();
    const res = await request(app).post("/api/cases").send({ title: "x", alertIds: ["alert-does-not-exist"] });
    expect(res.status).toBe(404);
    expect((await request(app).get("/api/cases")).body).toHaveLength(0);
  });

  it("rejects an invalid status change", async () => {
    const { app } = makeApp();
    const c = await request(app).post("/api/cases").send({ title: "x" });
    const res = await request(app).patch(`/api/cases/${c.body.id}`).send({ status: "deleted" });
    expect(res.status).toBe(400);
  });

  it("records the old and new status in the timeline", async () => {
    const { app } = makeApp();
    const c = await request(app).post("/api/cases").send({ title: "x" });
    await request(app).patch(`/api/cases/${c.body.id}`).send({ status: "investigating" });
    const detail = await request(app).get(`/api/cases/${c.body.id}`);
    expect(detail.body.timeline.at(-1).content).toBe("Status changed from open to investigating");
  });

  it("returns JSON 400 for a malformed body", async () => {
    const { app } = makeApp();
    const res = await request(app).post("/api/cases").set("Content-Type", "application/json").send("{not json");
    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  it("returns JSON 404 for unknown API routes", async () => {
    const { app } = makeApp();
    const res = await request(app).get("/api/nope");
    expect(res.status).toBe(404);
    expect(res.body.error).toBe("not found");
  });
});

describe("hardening", () => {
  it("sets security headers and hides the framework", async () => {
    const { app } = makeApp();
    const res = await request(app).get("/api/health");
    expect(res.status).toBe(200);
    expect(res.headers["content-security-policy"]).toContain("script-src 'self'");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["x-frame-options"]).toBe("DENY");
    expect(res.headers["x-powered-by"]).toBeUndefined();
  });

  it("serves a UI with no inline scripts or styles (required by the CSP)", async () => {
    const { app } = makeApp();
    const page = await request(app).get("/");
    expect(page.status).toBe(200);
    expect(page.text).not.toMatch(/<script(?![^>]*\bsrc=)/i);
    expect(page.text).not.toMatch(/\son[a-z]+\s*=/i);
    expect(page.text).not.toMatch(/\sstyle\s*=/i);

    const js = await request(app).get("/app.js");
    expect(js.status).toBe(200);
    expect(js.text).not.toMatch(/\.innerHTML\s*=/);
    expect(js.text).not.toMatch(/insertAdjacentHTML|document\.write/);
  });
});

describe("alert ordering", () => {
  it("lists the most severe alerts first", async () => {
    const { app } = makeApp();
    for (const severity of ["low", "critical", "medium", "high"]) {
      await request(app).post("/api/alerts/ingest").send({ alert: { time: "2025-05-01T10:00:00Z", title: severity, severity } });
    }
    const res = await request(app).get("/api/alerts");
    expect(res.body.map((a: { severity: string }) => a.severity)).toEqual(["critical", "high", "medium", "low"]);
  });
});
