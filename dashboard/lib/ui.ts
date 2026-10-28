import type { Severity } from "./types";

export const severityClasses: Record<Severity, string> = {
  critical: "border-rose-400/30 bg-rose-400/10 text-rose-200",
  high: "border-orange-400/30 bg-orange-400/10 text-orange-200",
  medium: "border-amber-300/30 bg-amber-300/10 text-amber-200",
  low: "border-sky-300/30 bg-sky-300/10 text-sky-200",
};

export const severityDotClasses: Record<Severity, string> = {
  critical: "bg-rose-400",
  high: "bg-orange-400",
  medium: "bg-amber-300",
  low: "bg-sky-300",
};

export const severityBarClasses: Record<Severity, string> = {
  critical: "bg-rose-400",
  high: "bg-orange-400",
  medium: "bg-amber-300",
  low: "bg-sky-300",
};

export const suiteLabels: Record<string, string> = {
  bola: "BOLA / IDOR",
  mcc: "MCC policy",
  race: "Race condition",
};

export function scoreHex(score: number): string {
  if (score >= 80) return "#2dd4bf";
  if (score >= 60) return "#38bdf8";
  if (score >= 40) return "#fbbf24";
  return "#fb7185";
}

export function scoreVerdict(score: number): string {
  if (score >= 80) return "Hardened baseline";
  if (score >= 60) return "Needs attention";
  if (score >= 40) return "Weak controls";
  return "Critical exposure";
}
