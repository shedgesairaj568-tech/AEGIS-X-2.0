interface StatCardProps {
  label: string;
  value: string | number;
  accentColor?: string;
  icon?: React.ReactNode;
}

export function StatCard({ label, value, accentColor = "#FFB454", icon }: StatCardProps) {
  return (
    <div className="rounded-lg border border-border bg-surface p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wide text-text-muted">{label}</span>
        {icon && (
          <span className="opacity-70" style={{ color: accentColor }}>
            {icon}
          </span>
        )}
      </div>
      <div className="mt-2 font-mono text-2xl font-semibold font-mono-data">{value}</div>
    </div>
  );
}
