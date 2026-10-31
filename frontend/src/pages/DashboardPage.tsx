import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { StatCard } from "../components/StatCard";
import { AttackDistributionChart } from "../components/AttackDistributionChart";
import { AlertRow } from "../components/AlertRow";
import { AlertDetailDrawer } from "../components/AlertDetailDrawer";
import { useAllAlertsForStats } from "../hooks/useAlerts";
import type { Alert } from "../types/api";

export function DashboardPage() {
  const { alerts, isLoading } = useAllAlertsForStats();
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const navigate = useNavigate();

  const openCount = alerts.filter((a) => a.status === "open").length;
  const criticalCount = alerts.filter((a) => a.severity === "critical").length;
  const highCount = alerts.filter((a) => a.severity === "high").length;
  const attackCount = alerts.filter((a) => a.attack_type !== "normal").length;

  const recentAlerts = [...alerts]
    .sort((a, b) => new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime())
    .slice(0, 6);

  return (
    <div className="p-6">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Dashboard</h1>
          <p className="text-sm text-text-muted">Real-time threat overview</p>
        </div>
      </div>

      {isLoading ? (
        <div className="text-sm text-text-muted">Loading...</div>
      ) : (
        <>
          <div className="mb-6 grid grid-cols-4 gap-4">
            <StatCard label="Open Alerts" value={openCount} icon={<DotIcon />} />
            <StatCard label="Critical" value={criticalCount} accentColor="#E24B4B" icon={<DotIcon />} />
            <StatCard label="High Severity" value={highCount} accentColor="#E8734A" icon={<DotIcon />} />
            <StatCard label="Attacks Detected" value={attackCount} icon={<DotIcon />} />
          </div>

          <div className="mb-6 grid grid-cols-3 gap-4">
            <div className="col-span-2 rounded-lg border border-border bg-surface p-4">
              <h2 className="mb-3 text-sm font-semibold">Attack Distribution</h2>
              <AttackDistributionChart alerts={alerts} />
            </div>

            <div className="rounded-lg border border-border bg-surface p-4">
              <h2 className="mb-3 text-sm font-semibold">Severity Breakdown</h2>
              <SeverityBreakdown alerts={alerts} />
            </div>
          </div>

          <div className="rounded-lg border border-border bg-surface">
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <h2 className="text-sm font-semibold">Recent Alerts</h2>
              <button onClick={() => navigate("/alerts")} className="text-xs text-accent hover:underline">
                View all →
              </button>
            </div>
            {recentAlerts.length === 0 ? (
              <div className="px-4 py-8 text-center text-sm text-text-muted">No alerts yet.</div>
            ) : (
              recentAlerts.map((alert) => (
                <AlertRow key={alert.id} alert={alert} onClick={() => setSelectedAlert(alert)} />
              ))
            )}
          </div>
        </>
      )}

      {selectedAlert && (
        <AlertDetailDrawer
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onUpdated={(updated) => setSelectedAlert(updated)}
        />
      )}
    </div>
  );
}

function SeverityBreakdown({ alerts }: { alerts: Alert[] }) {
  const severities = ["critical", "high", "medium", "low"] as const;
  const colors = { critical: "#E24B4B", high: "#E8734A", medium: "#E8B94A", low: "#5B9BD5" };
  const total = alerts.length || 1;

  return (
    <div className="space-y-3">
      {severities.map((sev) => {
        const count = alerts.filter((a) => a.severity === sev).length;
        const pct = (count / total) * 100;
        return (
          <div key={sev}>
            <div className="mb-1 flex items-center justify-between text-xs">
              <span className="capitalize text-text-secondary">{sev}</span>
              <span className="font-mono text-text-muted">{count}</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-raised">
              <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: colors[sev] }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function DotIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
      <circle cx="12" cy="12" r="6" />
    </svg>
  );
}
