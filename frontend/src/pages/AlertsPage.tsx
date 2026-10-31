import { useState } from "react";
import type { Alert, AlertFilters, AlertSeverity, AlertStatus, AttackType } from "../types/api";
import { useAlerts } from "../hooks/useAlerts";
import { AlertRow } from "../components/AlertRow";
import { AlertDetailDrawer } from "../components/AlertDetailDrawer";

const STATUS_OPTIONS: AlertStatus[] = ["open", "investigating", "resolved", "false_positive"];
const SEVERITY_OPTIONS: AlertSeverity[] = ["critical", "high", "medium", "low"];
const ATTACK_TYPE_OPTIONS: AttackType[] = [
  "ddos",
  "brute_force",
  "port_scan",
  "botnet",
  "sql_injection",
  "web_attack",
  "other",
  "normal",
];

export function AlertsPage() {
  const [filters, setFilters] = useState<AlertFilters>({ page: 1, page_size: 25 });
  const { data, isLoading, error, refetch } = useAlerts(filters);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  const updateFilter = (key: keyof AlertFilters, value: string | undefined) => {
    setFilters((prev) => ({ ...prev, [key]: value || undefined, page: 1 }));
  };

  const totalPages = data ? Math.ceil(data.total / data.page_size) : 1;

  return (
    <div className="p-6">
      <div className="mb-4">
        <h1 className="text-lg font-semibold">Alerts</h1>
        <p className="text-sm text-text-muted">{data?.total ?? 0} total alerts</p>
      </div>

      <div className="mb-4 flex flex-wrap gap-2">
        <FilterSelect
          label="Status"
          value={filters.status}
          options={STATUS_OPTIONS}
          onChange={(v) => updateFilter("status", v)}
        />
        <FilterSelect
          label="Severity"
          value={filters.severity}
          options={SEVERITY_OPTIONS}
          onChange={(v) => updateFilter("severity", v)}
        />
        <FilterSelect
          label="Attack Type"
          value={filters.attack_type}
          options={ATTACK_TYPE_OPTIONS}
          onChange={(v) => updateFilter("attack_type", v)}
        />
        {(filters.status || filters.severity || filters.attack_type) && (
          <button
            onClick={() => setFilters({ page: 1, page_size: 25 })}
            className="rounded-md border border-border px-3 py-1.5 text-xs text-text-secondary hover:bg-surface-raised"
          >
            Clear filters
          </button>
        )}
      </div>

      {error && (
        <div className="mb-4 rounded-md border border-severity-critical/40 bg-severity-critical/10 px-3 py-2 text-sm text-severity-critical">
          {error}{" "}
          <button onClick={refetch} className="underline">
            Retry
          </button>
        </div>
      )}

      <div className="rounded-lg border border-border bg-surface">
        {isLoading ? (
          <div className="px-4 py-8 text-center text-sm text-text-muted">Loading...</div>
        ) : data && data.items.length > 0 ? (
          data.items.map((alert) => (
            <AlertRow key={alert.id} alert={alert} onClick={() => setSelectedAlert(alert)} />
          ))
        ) : (
          <div className="px-4 py-8 text-center text-sm text-text-muted">No alerts match these filters.</div>
        )}
      </div>

      {data && totalPages > 1 && (
        <div className="mt-4 flex items-center justify-center gap-2">
          <button
            disabled={filters.page === 1}
            onClick={() => setFilters((p) => ({ ...p, page: (p.page ?? 1) - 1 }))}
            className="rounded-md border border-border px-3 py-1.5 text-xs text-text-secondary hover:bg-surface-raised disabled:opacity-40"
          >
            Previous
          </button>
          <span className="text-xs font-mono text-text-muted">
            Page {data.page} of {totalPages}
          </span>
          <button
            disabled={(filters.page ?? 1) >= totalPages}
            onClick={() => setFilters((p) => ({ ...p, page: (p.page ?? 1) + 1 }))}
            className="rounded-md border border-border px-3 py-1.5 text-xs text-text-secondary hover:bg-surface-raised disabled:opacity-40"
          >
            Next
          </button>
        </div>
      )}

      {selectedAlert && (
        <AlertDetailDrawer
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onUpdated={(updated) => {
            setSelectedAlert(updated);
            refetch();
          }}
        />
      )}
    </div>
  );
}

function FilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string | undefined;
  options: string[];
  onChange: (v: string | undefined) => void;
}) {
  return (
    <select
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value || undefined)}
      className="rounded-md border border-border bg-surface px-3 py-1.5 text-xs text-text-primary focus:border-accent"
    >
      <option value="">{label}: All</option>
      {options.map((opt) => (
        <option key={opt} value={opt}>
          {opt.replace("_", " ")}
        </option>
      ))}
    </select>
  );
}
