export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export const CASE_STATUSES = ["open", "investigating", "resolved", "closed"] as const;

export type Severity = (typeof SEVERITIES)[number];
export type CaseStatus = (typeof CASE_STATUSES)[number];
export type TimelineEntryKind = "alert" | "note" | "evidence" | "status_change";

export interface Alert {
  id: string;
  time: string;
  title: string;
  severity: Severity;
  ruleId: string;
  /** The alert document exactly as it was received, as a JSON string. */
  raw: string;
  caseId: string | null;
  ingestedAt: string;
}

export interface Case {
  id: string;
  title: string;
  severity: Severity;
  status: CaseStatus;
  tags: string[];
  createdAt: string;
  updatedAt: string;
}

export interface TimelineEntry {
  id: string;
  caseId: string;
  kind: TimelineEntryKind;
  content: string;
  createdAt: string;
  createdBy: string;
}

export interface CaseExport {
  case: Case;
  alerts: Alert[];
  timeline: TimelineEntry[];
  exportedAt: string;
}
