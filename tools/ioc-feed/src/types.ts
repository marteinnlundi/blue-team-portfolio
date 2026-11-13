export type IocType = "ip" | "domain" | "sha256";

export interface Ioc {
  id: string;
  type: IocType;
  value: string;
  source: string;
  confidence: number;
  validFrom: string;
  validUntil: string | null;
  labels: string[];
  description: string;
  ingestedAt: string;
}

export interface StixBundle {
  type: "bundle";
  id: string;
  objects: StixObject[];
}

export interface StixIndicator {
  type: "indicator";
  id: string;
  name?: string;
  description?: string;
  pattern: string;
  pattern_type: string;
  valid_from: string;
  valid_until?: string;
  confidence?: number;
  labels?: string[];
}

export type StixObject = StixIndicator | { type: string };

export interface NormalizedEvent {
  event?: { time?: string; source?: string; kind?: string };
  host?: { name?: string };
  user?: { name?: string };
  network?: { src_ip?: string; dst_ip?: string; dst_port?: number; protocol?: string };
  process?: { name?: string; pid?: number; command_line?: string };
  tags?: string[];
}

export interface Alert {
  alert: {
    id: string;
    time: string;
    title: string;
    severity: string;
  };
  rule: { id: string };
  host: { name: string };
  user?: { name: string };
  network?: { src_ip?: string; dst_ip?: string; dst_port?: number };
  tags?: string[];
  ioc: {
    type: IocType;
    value: string;
    source: string;
    confidence: number;
  };
  summary: string;
}
