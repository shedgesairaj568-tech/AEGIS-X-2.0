import type { AlertSeverity } from "../types/api";
import { SEVERITY_COLORS, SEVERITY_LABELS } from "../utils/format";

export function SeverityBadge({ severity }: { severity: AlertSeverity }) {
  const color = SEVERITY_COLORS[severity];
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs font-medium font-mono uppercase tracking-wide"
      style={{ color, backgroundColor: `${color}1A`, border: `1px solid ${color}40` }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
      {SEVERITY_LABELS[severity]}
    </span>
  );
}
