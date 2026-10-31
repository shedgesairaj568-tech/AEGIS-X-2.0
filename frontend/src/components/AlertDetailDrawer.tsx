import { useEffect, useState } from "react";
import type { Alert, AlertStatus, Report, ThreatHistoryEntry } from "../types/api";
import { alertsService } from "../services/alertsService";
import { SeverityBadge } from "./SeverityBadge";
import { RiskMeter } from "./RiskMeter";
import { ATTACK_TYPE_LABELS, formatTimestamp } from "../utils/format";

interface Props {
  alert: Alert;
  onClose: () => void;
  onUpdated: (updated: Alert) => void;
}

const STATUS_OPTIONS: AlertStatus[] = ["open", "investigating", "resolved", "false_positive"];

export function AlertDetailDrawer({ alert, onClose, onUpdated }: Props) {
  const [history, setHistory] = useState<ThreatHistoryEntry[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isUpdating, setIsUpdating] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    Promise.all([alertsService.getHistory(alert.id), alertsService.getReports(alert.id)])
      .then(([h, r]) => {
        if (!cancelled) {
          setHistory(h);
          setReports(r);
        }
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [alert.id]);

  const handleStatusChange = async (status: AlertStatus) => {
    setIsUpdating(true);
    try {
      const updated = await alertsService.update(alert.id, { status });
      onUpdated(updated);
      const newHistory = await alertsService.getHistory(alert.id);
      setHistory(newHistory);
    } finally {
      setIsUpdating(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="relative flex h-full w-full max-w-lg flex-col overflow-y-auto border-l border-border bg-base shadow-2xl">
        <div className="flex items-start justify-between border-b border-border px-5 py-4">
          <div>
            <h2 className="text-base font-semibold">{alert.title}</h2>
            <div className="mt-1.5 flex items-center gap-2">
              <SeverityBadge severity={alert.severity} />
              <span className="text-xs font-mono text-text-muted">{ATTACK_TYPE_LABELS[alert.attack_type]}</span>
            </div>
          </div>
          <button onClick={onClose} className="rounded p-1 text-text-muted hover:bg-surface-raised" aria-label="Close">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <div className="space-y-5 px-5 py-4">
          {alert.risk_score !== null && (
            <div>
              <div className="mb-1.5 text-xs font-medium uppercase tracking-wide text-text-muted">Risk Score</div>
              <RiskMeter score={alert.risk_score} severity={alert.severity} size="lg" />
            </div>
          )}

          <div className="grid grid-cols-2 gap-3 text-sm">
            {alert.source_ip && <Field label="Source IP" value={alert.source_ip} mono />}
            {alert.destination_ip && <Field label="Destination IP" value={alert.destination_ip} mono />}
            {alert.mitre_technique_id && (
              <Field label="MITRE Technique" value={`${alert.mitre_technique_id} — ${alert.mitre_technique_name}`} />
            )}
            {alert.confidence !== null && (
              <Field label="Confidence" value={`${Math.round(alert.confidence * 100)}%`} mono />
            )}
          </div>

          {alert.description && (
            <div>
              <div className="mb-1 text-xs font-medium uppercase tracking-wide text-text-muted">Explanation</div>
              <p className="text-sm text-text-secondary">{alert.description}</p>
            </div>
          )}

          <div>
            <div className="mb-1.5 text-xs font-medium uppercase tracking-wide text-text-muted">Status</div>
            <div className="flex flex-wrap gap-1.5">
              {STATUS_OPTIONS.map((status) => (
                <button
                  key={status}
                  disabled={isUpdating}
                  onClick={() => handleStatusChange(status)}
                  className={`rounded px-2.5 py-1 text-xs font-medium capitalize transition-colors disabled:opacity-50 ${
                    alert.status === status
                      ? "bg-accent text-base"
                      : "border border-border text-text-secondary hover:bg-surface-raised"
                  }`}
                >
                  {status.replace("_", " ")}
                </button>
              ))}
            </div>
          </div>

          {reports.length > 0 && (
            <div>
              <div className="mb-2 text-xs font-medium uppercase tracking-wide text-text-muted">Incident Report</div>
              {reports.map((report) => (
                <div key={report.id} className="space-y-2 rounded-md border border-border bg-surface p-3">
                  <ReportSection label="Summary" text={report.summary} />
                  {report.root_cause && <ReportSection label="Root Cause" text={report.root_cause} />}
                  {report.mitigation && <ReportSection label="Mitigation" text={report.mitigation} />}
                  <div className="pt-1 text-[10px] font-mono uppercase text-text-muted">
                    Generated by: {report.generated_by}
                  </div>
                </div>
              ))}
            </div>
          )}

          <div>
            <div className="mb-2 text-xs font-medium uppercase tracking-wide text-text-muted">Timeline</div>
            {isLoading ? (
              <div className="text-xs text-text-muted">Loading...</div>
            ) : (
              <ol className="space-y-3">
                {history.map((entry) => (
                  <li key={entry.id} className="flex gap-3">
                    <div className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-accent" />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-baseline justify-between gap-2">
                        <span className="text-xs font-medium capitalize">{entry.event_type.replace("_", " ")}</span>
                        <span className="shrink-0 font-mono text-[10px] text-text-muted">
                          {formatTimestamp(entry.created_at)}
                        </span>
                      </div>
                      <p className="mt-0.5 text-xs text-text-secondary">{entry.description}</p>
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-[10px] font-medium uppercase tracking-wide text-text-muted">{label}</div>
      <div className={`mt-0.5 ${mono ? "font-mono" : ""}`}>{value}</div>
    </div>
  );
}

function ReportSection({ label, text }: { label: string; text: string }) {
  return (
    <div>
      <div className="text-[10px] font-medium uppercase tracking-wide text-text-muted">{label}</div>
      <p className="mt-0.5 text-xs text-text-secondary">{text}</p>
    </div>
  );
}
