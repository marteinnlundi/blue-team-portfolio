import { describe, expect, it } from "vitest";
import { openDb, upsertIocs } from "../src/db.js";
import { matchEvent } from "../src/match.js";
import type { Ioc, NormalizedEvent } from "../src/types.js";

function makeIoc(overrides: Partial<Ioc> = {}): Ioc {
  return {
    id: "indicator--test",
    type: "ip",
    value: "198.51.100.42",
    source: "test-feed",
    confidence: 90,
    validFrom: "2020-01-01T00:00:00Z",
    validUntil: null,
    labels: ["malicious"],
    description: "Known bad",
    ingestedAt: new Date().toISOString(),
    ...overrides,
  };
}

function seedDb(...iocs: Partial<Ioc>[]) {
  const db = openDb(":memory:");
  upsertIocs(db, iocs.map((o, i) => makeIoc({ id: `indicator--${i}`, ...o })));
  return db;
}

describe("matchEvent — IP matching", () => {
  it("matches on network.src_ip", () => {
    const db = seedDb({ type: "ip", value: "198.51.100.42" });
    const event: NormalizedEvent = {
      network: { src_ip: "198.51.100.42" },
      host: { name: "prod-server" },
    };
    const alerts = matchEvent(db, event);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].rule.id).toBe("ioc-feed-match");
    expect(alerts[0].ioc.value).toBe("198.51.100.42");
    expect(alerts[0].ioc.type).toBe("ip");
    expect(alerts[0].host?.name).toBe("prod-server");
  });

  it("matches on network.dst_ip", () => {
    const db = seedDb({ type: "ip", value: "198.51.100.42" });
    const event: NormalizedEvent = { network: { dst_ip: "198.51.100.42" } };
    expect(matchEvent(db, event)).toHaveLength(1);
  });

  it("returns empty array for unknown IP", () => {
    const db = seedDb({ type: "ip", value: "198.51.100.42" });
    const event: NormalizedEvent = { network: { src_ip: "10.0.0.1" } };
    expect(matchEvent(db, event)).toHaveLength(0);
  });

  it("does not duplicate alerts for same IOC hit on src and dst", () => {
    const db = seedDb({ type: "ip", value: "198.51.100.42" });
    const event: NormalizedEvent = {
      network: { src_ip: "198.51.100.42", dst_ip: "198.51.100.42" },
    };
    expect(matchEvent(db, event)).toHaveLength(1);
  });
});

describe("matchEvent — domain matching", () => {
  it("extracts domain from process.command_line", () => {
    const db = seedDb({ type: "domain", value: "evil-login.example.net" });
    const event: NormalizedEvent = {
      process: { command_line: "curl https://evil-login.example.net/creds" },
    };
    expect(matchEvent(db, event)).toHaveLength(1);
  });

  it("returns empty for benign domain", () => {
    const db = seedDb({ type: "domain", value: "evil-login.example.net" });
    const event: NormalizedEvent = {
      process: { command_line: "curl https://safe.example.com/" },
    };
    expect(matchEvent(db, event)).toHaveLength(0);
  });
});

describe("matchEvent — alert fields", () => {
  it("sets severity high for confidence >= 80", () => {
    const db = seedDb({ confidence: 90 });
    const alerts = matchEvent(db, { network: { src_ip: "198.51.100.42" } });
    expect(alerts[0].alert.severity).toBe("high");
  });

  it("sets severity medium for confidence 50-79", () => {
    const db = seedDb({ confidence: 65 });
    const alerts = matchEvent(db, { network: { src_ip: "198.51.100.42" } });
    expect(alerts[0].alert.severity).toBe("medium");
  });

  it("sets severity low for confidence < 50", () => {
    const db = seedDb({ confidence: 30 });
    const alerts = matchEvent(db, { network: { src_ip: "198.51.100.42" } });
    expect(alerts[0].alert.severity).toBe("low");
  });
});

describe("alert shape", () => {
  it("always carries host.name and the IOC labels as tags", () => {
    const db = openDb(":memory:");
    upsertIocs(db, [makeIoc({ type: "ip", value: "198.51.100.42", labels: ["c2"] })]);
    const [alert] = matchEvent(db, { network: { dst_ip: "198.51.100.42", dst_port: 4444 } });
    expect(alert.host.name).toBe("unknown");
    expect(alert.tags).toEqual(["c2"]);
    expect(alert.network?.dst_port).toBe(4444);
    expect(alert.alert.id).toMatch(/^alert-/);
  });
});
