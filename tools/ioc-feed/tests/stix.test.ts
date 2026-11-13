import { beforeAll, describe, expect, it } from "vitest";
import { parseFeedFile } from "../src/stix.js";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SAMPLE = path.join(__dirname, "../samples/feed.stix.json");

describe("parseFeedFile", () => {
  let iocs: ReturnType<typeof parseFeedFile>;

  beforeAll(() => {
    iocs = parseFeedFile(SAMPLE);
  });

  it("parses all valid indicators (excludes non-indicator objects)", () => {
    expect(iocs.length).toBe(5);
  });

  it("parses ipv4-addr pattern correctly", () => {
    const ip = iocs.find((i) => i.type === "ip" && i.value === "198.51.100.42");
    expect(ip).toBeDefined();
    expect(ip!.confidence).toBe(90);
    expect(ip!.labels).toContain("c2");
    expect(ip!.description).toBe("Confirmed C2 server used in APT campaign");
  });

  it("parses domain-name pattern correctly", () => {
    const domain = iocs.find((i) => i.type === "domain");
    expect(domain).toBeDefined();
    expect(domain!.value).toBe("evil-login.example.net");
    expect(domain!.confidence).toBe(85);
  });

  it("parses sha256 hash pattern correctly", () => {
    const hash = iocs.find((i) => i.type === "sha256");
    expect(hash).toBeDefined();
    expect(hash!.value).toMatch(/^[a-f0-9]{64}$/);
  });

  it("preserves valid_until when present", () => {
    const scanner = iocs.find((i) => i.value === "203.0.113.99");
    expect(scanner!.validUntil).toBe("2099-01-01T00:00:00Z");
  });

  it("sets validUntil to null when not present", () => {
    const c2 = iocs.find((i) => i.value === "198.51.100.42");
    expect(c2!.validUntil).toBeNull();
  });

  it("throws on non-bundle input", () => {
    expect(() =>
      parseFeedFile(path.join(__dirname, "../package.json"))
    ).toThrow();
  });
});
