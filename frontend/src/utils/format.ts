import type { AlertSeverity, AttackType } from "../types/api";

export const SEVERITY_COLORS: Record<AlertSeverity, string> = {
  low: "#5B9BD5",
  medium: "#E8B94A",
  high: "#E8734A",
  critical: "#E24B4B",
};

export const SEVERITY_LABELS: Record<AlertSeverity, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

export const ATTACK_TYPE_LABELS: Record<AttackType, string> = {
  normal: "Normal",
  brute_force: "Brute Force",
  ddos: "DDoS",
  botnet: "Botnet",
  port_scan: "Port Scan",
  sql_injection: "SQL Injection",
  web_attack: "Web Attack",
  other: "Other",
};

export function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatRelativeTime(iso: string): string {
  const date = new Date(iso);
  const diffMs = Date.now() - date.getTime();
  const diffMin = Math.floor(diffMs / 60000);

  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}d ago`;
}
