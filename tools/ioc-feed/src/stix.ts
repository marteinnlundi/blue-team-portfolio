import { readFileSync } from "fs";
import path from "path";
import type { Ioc, IocType, StixBundle, StixIndicator } from "./types.js";

const PATTERNS: Array<{ type: IocType; re: RegExp }> = [
  { type: "ip",     re: /\[ipv4-addr:value\s*=\s*'([^']+)'\]/i },
  { type: "domain", re: /\[domain-name:value\s*=\s*'([^']+)'\]/i },
  { type: "sha256", re: /\[file:hashes\.SHA-256\s*=\s*'([^']+)'\]/i },
];

function parsePattern(pattern: string): { type: IocType; value: string } | null {
  for (const { type, re } of PATTERNS) {
    const m = pattern.match(re);
    // IP addresses, domains and hashes are all case-insensitive: store one form.
    if (m) return { type, value: m[1].trim().toLowerCase() };
  }
  return null;
}

function isIndicator(obj: { type: string }): obj is StixIndicator {
  return obj.type === "indicator";
}

export function parseFeedFile(filePath: string): Ioc[] {
  const raw = readFileSync(filePath, "utf-8");
  const bundle: StixBundle = JSON.parse(raw);

  if (bundle?.type !== "bundle" || !Array.isArray(bundle.objects)) {
    throw new Error(`${filePath} is not a STIX 2.1 bundle (expected type "bundle" with an "objects" list)`);
  }

  const now = new Date().toISOString();
  const iocs: Ioc[] = [];

  for (const obj of bundle.objects) {
    if (!isIndicator(obj)) continue;
    if (typeof obj.pattern !== "string" || typeof obj.valid_from !== "string") continue;

    const parsed = parsePattern(obj.pattern);
    if (!parsed) continue;

    iocs.push({
      id: obj.id,
      type: parsed.type,
      value: parsed.value,
      source: path.basename(filePath),
      confidence: obj.confidence ?? 50,
      validFrom: obj.valid_from,
      validUntil: obj.valid_until ?? null,
      labels: obj.labels ?? [],
      description: obj.description ?? obj.name ?? "",
      ingestedAt: now,
    });
  }

  return iocs;
}
