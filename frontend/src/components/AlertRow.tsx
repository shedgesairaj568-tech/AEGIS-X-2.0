import type { Alert } from "../types/api";
import { SeverityBadge } from "./SeverityBadge";
import { RiskMeter } from "./RiskMeter";
import { ATTACK_TYPE_LABELS, SEVERITY_COLORS, formatRelativeTime } from "../utils/format";

interface Props {
  alert: Alert;
  onClick: () => void;
}

export function AlertRow({ alert, onClick }: Props) {
  const color = SEVERITY_COLORS[alert.severity];

  return (
    <button
      onClick={onClick}
      className="flex w-full items-center gap-4 border-b border-border bg-surface px-4 py-3 text-left transition-colors last:border-b-0 hover:bg-surface-raised"
      style={{ borderLeft: `3px solid ${color}` }}
    >
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-sm font-medium">{alert.title}</span>
          <SeverityBadge severity={alert.severity} />
        </div>
        <div className="mt-1 flex items-center gap-3 text-xs text-text-muted font-mono">
          <span>{ATTACK_TYPE_LABELS[alert.attack_type]}</span>
          {alert.source_ip && <span>{alert.source_ip}</span>}
          {alert.mitre_technique_id && <span>{alert.mitre_technique_id}</span>}
          <span>{formatRelativeTime(alert.detected_at)}</span>
        </div>
      </div>

      {alert.risk_score !== null && <RiskMeter score={alert.risk_score} severity={alert.severity} size="sm" />}

      <span className="shrink-0 rounded border border-border px-2 py-0.5 text-[10px] font-mono uppercase text-text-secondary">
        {alert.status.replace("_", " ")}
      </span>
    </button>
  );
}
