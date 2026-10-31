import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Alert } from "../types/api";
import { ATTACK_TYPE_LABELS } from "../utils/format";

interface Props {
  alerts: Alert[];
}

export function AttackDistributionChart({ alerts }: Props) {
  const counts: Record<string, number> = {};
  for (const alert of alerts) {
    counts[alert.attack_type] = (counts[alert.attack_type] || 0) + 1;
  }

  const data = Object.entries(counts)
    .map(([type, count]) => ({
      name: ATTACK_TYPE_LABELS[type as keyof typeof ATTACK_TYPE_LABELS] ?? type,
      count,
    }))
    .sort((a, b) => b.count - a.count);

  if (data.length === 0) {
    return <div className="flex h-56 items-center justify-center text-sm text-text-muted">No alert data yet.</div>;
  }

  return (
    <ResponsiveContainer width="100%" height={224}>
      <BarChart data={data} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#253248" vertical={false} />
        <XAxis
          dataKey="name"
          tick={{ fill: "#8B97AC", fontSize: 11 }}
          axisLine={{ stroke: "#253248" }}
          tickLine={false}
        />
        <YAxis tick={{ fill: "#8B97AC", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
        <Tooltip
          cursor={{ fill: "#1A2438" }}
          contentStyle={{
            backgroundColor: "#131B2E",
            border: "1px solid #253248",
            borderRadius: 6,
            fontSize: 12,
            fontFamily: "IBM Plex Mono, monospace",
          }}
          labelStyle={{ color: "#E7ECF5" }}
        />
        <Bar dataKey="count" fill="#FFB454" radius={[3, 3, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
