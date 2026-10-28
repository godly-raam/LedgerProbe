import type { ComponentType } from "react";

type Tone = "teal" | "rose" | "amber" | "slate";

const toneClasses: Record<Tone, string> = {
  teal: "border-teal-300/20 bg-teal-300/[0.07] text-teal-300",
  rose: "border-rose-400/20 bg-rose-400/[0.07] text-rose-300",
  amber: "border-amber-300/20 bg-amber-300/[0.07] text-amber-300",
  slate: "border-white/10 bg-white/[0.04] text-slate-300",
};

export function StatCard({
  label,
  value,
  hint,
  tone = "slate",
  icon: Icon,
}: {
  label: string;
  value: string | number;
  hint: string;
  tone?: Tone;
  icon: ComponentType<{ className?: string }>;
}) {
  return (
    <div className="panel p-4">
      <div className="flex items-start justify-between gap-3">
        <p className="eyebrow">{label}</p>
        <span className={`flex h-7 w-7 items-center justify-center rounded-lg border ${toneClasses[tone]}`}>
          <Icon className="h-3.5 w-3.5" />
        </span>
      </div>
      <p className="mt-3 font-mono text-2xl font-semibold tracking-tight text-white">{value}</p>
      <p className="mt-1 text-[11px] leading-4 text-slate-500">{hint}</p>
    </div>
  );
}
