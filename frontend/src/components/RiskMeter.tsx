import type { AlertSeverity } from "../types/api";
import { SEVERITY_COLORS } from "../utils/format";

interface RiskMeterProps {
  score: number; // 0-100
  severity: AlertSeverity;
  size?: "sm" | "md" | "lg";
}

/**
 * Renders risk_score as a segmented signal-strength readout — like a VU
 * meter or radar signal indicator — rather than a circular gauge. Ties
 * to the product's actual job: reading a signal out of noisy traffic.
 * Segments fill left-to-right; color is driven by severity, not score
 * directly, so the meter and the severity badge always agree.
 */
export function RiskMeter({ score, severity, size = "md" }: RiskMeterProps) {
  const segmentCount = 10;
  const filledSegments = Math.round((score / 100) * segmentCount);
  const color = SEVERITY_COLORS[severity];

  const dims = {
    sm: { barW: "w-1", barGap: "gap-0.5", h: "h-3", text: "text-xs" },
    md: { barW: "w-1.5", barGap: "gap-0.5", h: "h-5", text: "text-sm" },
    lg: { barW: "w-2", barGap: "gap-1", h: "h-8", text: "text-base" },
  }[size];

  return (
    <div className="flex items-center gap-2">
      <div className={`flex items-end ${dims.barGap} ${dims.h}`} role="img" aria-label={`Risk score ${score} out of 100`}>
        {Array.from({ length: segmentCount }).map((_, i) => {
          const isFilled = i < filledSegments;
          const heightPct = 35 + (i / segmentCount) * 65; // ramps up like a real signal meter
          return (
            <div
              key={i}
              className={`${dims.barW} rounded-sm transition-colors`}
              style={{
                height: `${heightPct}%`,
                backgroundColor: isFilled ? color : "#253248",
              }}
            />
          );
        })}
      </div>
      <span className={`font-mono font-mono-data ${dims.text} text-text-secondary`}>{Math.round(score)}</span>
    </div>
  );
}
