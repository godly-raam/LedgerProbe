import { severityClasses, severityDotClasses } from "@/lib/ui";
import type { Severity } from "@/lib/types";

export function SeverityBadge({ severity, compact = false }: { severity: Severity; compact?: boolean }) {
  return (
    <span
      className={`pill ${severityClasses[severity]} ${compact ? "px-2 py-0.5 text-[10px]" : ""}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${severityDotClasses[severity]}`} />
      {severity}
    </span>
  );
}
