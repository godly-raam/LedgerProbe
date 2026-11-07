import Link from "next/link";
import { ArrowLeft, BarChart3, CircleAlert, CircleCheck, CircleHelp } from "lucide-react";

import benchmark from "@/data/benchmark.json";

const countLabels = ["TP", "FP", "TN", "FN", "INC_vuln", "INC_safe"];

function Counts({ values }: { values: number[] }) {
  return (
    <span className="font-mono text-[10px] leading-5 text-slate-300">
      {values.map((value, index) => (
        <span key={countLabels[index]} title={countLabels[index]}>
          {value}
          {index < values.length - 1 ? "/" : ""}
        </span>
      ))}
    </span>
  );
}

export default function BenchmarkPage() {
  return (
    <div className="space-y-5">
      <Link
        href="/"
        className="inline-flex items-center gap-1.5 text-xs text-slate-400 transition hover:text-slate-200"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> Back to overview
      </Link>

      <section className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="eyebrow">Frozen benchmark</p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight text-white sm:text-3xl">
            Differential results, with counts
          </h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
            {benchmark.sample.cases} cases across {benchmark.sample.endpoints} distinct endpoints.
            {" "}{benchmark.sample.note}
          </p>
        </div>
        <div className="flex items-center gap-2 rounded-xl border border-teal-300/20 bg-teal-300/[0.05] px-4 py-3 text-xs text-teal-100">
          <BarChart3 className="h-4 w-4" /> Source: docs/BENCHMARK.md
        </div>
      </section>

      <section className="panel overflow-x-auto p-5">
        <table className="w-full min-w-[760px] border-collapse text-left text-xs">
          <thead>
            <tr className="border-b border-white/10 text-[10px] uppercase tracking-[0.12em] text-slate-500">
              <th className="py-2 pr-3">Target</th>
              <th className="py-2 pr-3">Mode</th>
              <th className="py-2 pr-3">v1</th>
              <th className="py-2 pr-3">v2</th>
              <th className="py-2 pr-3">v3</th>
            </tr>
          </thead>
          <tbody>
            {benchmark.rows.map((row) => (
              <tr key={`${row.target}-${row.mode}`} className="border-b border-white/[0.06]">
                <td className="py-3 pr-3 text-slate-200">{row.target}</td>
                <td className="py-3 pr-3 font-mono text-[10px] text-slate-400">{row.mode}</td>
                <td className="py-3 pr-3"><Counts values={row.v1} /></td>
                <td className="py-3 pr-3"><Counts values={row.v2} /></td>
                <td className="py-3 pr-3"><Counts values={row.v3} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-3 font-mono text-[10px] text-slate-500">
          TP / FP / TN / FN / INC_vuln / INC_safe
        </p>
        <ul className="mt-4 space-y-1.5 text-[11px] leading-5 text-slate-500">
          {benchmark.notes.map((note) => <li key={note}>• {note}</li>)}
        </ul>
      </section>

      <section className="panel p-5">
        <div className="flex items-center gap-2">
          <CircleHelp className="h-4 w-4 text-slate-500" />
          <h2 className="text-sm font-semibold text-white">Verdict legend</h2>
        </div>
        <div className="mt-3 grid gap-2 md:grid-cols-3">
          <div className="rounded-lg border border-rose-400/20 bg-rose-400/[0.04] p-3">
            <p className="flex items-center gap-2 text-xs font-semibold text-rose-200"><CircleAlert className="h-3.5 w-3.5" /> FAIL</p>
            <p className="mt-1 text-[11px] leading-5 text-slate-400">Owner-specific evidence or a verified state change crossed the tested boundary.</p>
          </div>
          <div className="rounded-lg border border-teal-300/20 bg-teal-300/[0.04] p-3">
            <p className="flex items-center gap-2 text-xs font-semibold text-teal-200"><CircleCheck className="h-3.5 w-3.5" /> PASS</p>
            <p className="mt-1 text-[11px] leading-5 text-slate-400">The tested controls and confirmation produced no reproducible violation. It is not proof of safety.</p>
          </div>
          <div className="rounded-lg border border-amber-300/20 bg-amber-300/[0.04] p-3">
            <p className="flex items-center gap-2 text-xs font-semibold text-amber-200"><CircleHelp className="h-3.5 w-3.5" /> INCONCLUSIVE</p>
            <p className="mt-1 text-[11px] leading-5 text-slate-400">The evidence was ambiguous, weak, rate-limited, timed out, or lacked a usable control.</p>
          </div>
        </div>
      </section>
    </div>
  );
}
