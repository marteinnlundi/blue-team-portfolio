import { describe, expect, it } from "vitest";
import { openDb, upsertIocs, lookupIoc, countIocs, deleteExpired } from "../src/db.js";
import type { Ioc } from "../src/types.js";

function tmpDb() {
  return openDb(":memory:");
}

function makeIoc(overrides: Partial<Ioc> = {}): Ioc {
  return {
    id: "indicator--test-1",
    type: "ip",
    value: "1.2.3.4",
    source: "test-feed",
    confidence: 80,
    validFrom: "2020-01-01T00:00:00Z",
    validUntil: null,
    labels: ["test"],
    description: "test IOC",
    ingestedAt: new Date().toISOString(),
    ...overrides,
  };
}

describe("upsertIocs", () => {
  it("inserts new IOCs", () => {
    const db = tmpDb();
    const n = upsertIocs(db, [makeIoc()]);
    expect(n).toBe(1);
    expect(countIocs(db)).toBe(1);
  });

  it("deduplicates by type+value", () => {
    const db = tmpDb();
    upsertIocs(db, [makeIoc({ confidence: 50 })]);
    upsertIocs(db, [makeIoc({ confidence: 90 })]);
    expect(countIocs(db)).toBe(1);
    const ioc = lookupIoc(db, "ip", "1.2.3.4");
    expect(ioc!.confidence).toBe(90);
  });
});

describe("lookupIoc", () => {
  it("returns matching IOC", () => {
    const db = tmpDb();
    upsertIocs(db, [makeIoc()]);
    const found = lookupIoc(db, "ip", "1.2.3.4");
    expect(found).not.toBeNull();
    expect(found!.value).toBe("1.2.3.4");
  });

  it("returns null for unknown value", () => {
    const db = tmpDb();
    upsertIocs(db, [makeIoc()]);
    expect(lookupIoc(db, "ip", "9.9.9.9")).toBeNull();
  });

  it("does not return expired IOCs", () => {
    const db = tmpDb();
    upsertIocs(db, [
      makeIoc({ validUntil: "2000-01-01T00:00:00Z" }),
    ]);
    expect(lookupIoc(db, "ip", "1.2.3.4")).toBeNull();
  });

  it("does not return IOC before valid_from", () => {
    const db = tmpDb();
    upsertIocs(db, [makeIoc({ validFrom: "2099-01-01T00:00:00Z" })]);
    expect(lookupIoc(db, "ip", "1.2.3.4")).toBeNull();
  });
});

describe("deleteExpired", () => {
  it("removes only expired IOCs", () => {
    const db = tmpDb();
    upsertIocs(db, [
      makeIoc({ value: "1.1.1.1", validUntil: "2000-01-01T00:00:00Z" }),
      makeIoc({ value: "2.2.2.2", validUntil: null }),
    ]);
    const removed = deleteExpired(db);
    expect(removed).toBe(1);
    expect(countIocs(db)).toBe(1);
    expect(lookupIoc(db, "ip", "2.2.2.2")).not.toBeNull();
  });
});
