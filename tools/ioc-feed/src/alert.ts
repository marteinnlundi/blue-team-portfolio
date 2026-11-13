import { randomUUID } from "crypto";
import type { Alert, Ioc, NormalizedEvent } from "./types.js";

export function makeAlert(event: NormalizedEvent, ioc: Ioc): Alert {
  const severityFromConfidence = (c: number) => {
    if (c >= 80) return "high";
    if (c >= 50) return "medium";
    return "low";
  };

  const alert: Alert = {
    alert: {
      id: `alert-${randomUUID()}`,
      time: new Date().toISOString(),
      title: `IOC Match: ${ioc.type} ${ioc.value}`,
      severity: severityFromConfidence(ioc.confidence),
    },
    rule: { id: "ioc-feed-match" },
    host: { name: event.host?.name || "unknown" },
    ioc: {
      type: ioc.type,
      value: ioc.value,
      source: ioc.source,
      confidence: ioc.confidence,
    },
    summary: `Event matched IOC ${ioc.type}:${ioc.value} from feed "${ioc.source}". ${ioc.description}`.trim(),
  };

  if (ioc.labels.length > 0) alert.tags = ioc.labels;
  if (event.user?.name) alert.user = { name: event.user.name };
  if (event.network) {
    alert.network = {
      src_ip: event.network.src_ip,
      dst_ip: event.network.dst_ip,
      dst_port: event.network.dst_port,
    };
  }

  return alert;
}
