import Link from "next/link";
import { notFound } from "next/navigation";
import {
  ArrowLeft,
  ArrowUpRight,
  Bug,
  CircleAlert,
  Clock3,
  GitCompareArrows,
  ShieldCheck,
  Waypoints,
} from "lucide-react";

import { SeverityBadge } from "@/components/SeverityBadge";
import { findFinding, formatCents, formatDate, getReports } from "@/lib/reports";
import { suiteLabels } from "@/lib/ui";

export const dynamic = "force-dynamic";

function pretty(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2);
}

export default async function FindingPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ run?: string }>;
}) {
  const { id } = await params;
  const { run: runId } = await searchParams;
  const { reports } = getReports();
  const match = findFinding(reports, decodeURIComponent(id), runId);

  if (!match) notFound();

  const { report, finding } = match;
  const { evidence } = finding;
  const responseOk = evidence.response.status < 400;

  return (
    <div className="space-y-5">
      <Link
        href={`/?run=${report.run.id}`}
        className="inline-flex items-center gap-1.5 text-xs text-slate-400 transition hover:text-slate-200"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        Back to overview
      </Link>

      <section className="grid gap-4 lg:grid-cols-12">
        <div className="panel p-6 lg:col-span-8">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <span className="mono-label">{finding.id}</span>
            <span className="h-3 w-px bg-white/10" />
            <span className="text-[11px] text-slate-400">{suiteLabels[finding.suite] ?? finding.suite}</span>
            <span className="h-3 w-px bg-white/10" />
            <span className="text-[11px] text-slate-500">{finding.owasp.id}</span>
          </div>

          <h1 className="mt-4 text-2xl font-semibold leading-tight tracking-tight text-white">
            {finding.title}
          </h1>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">{finding.description}</p>

          <div className="mt-5 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-white/[0.06] pt-4 text-[11px] text-slate-500">
            <code className="font-mono text-slate-300">{finding.endpoint}</code>
            <span className="inline-flex items-center gap-1.5">
              <CircleAlert className="h-3.5 w-3.5" />
              {finding.owasp.name}
            </span>
            <span className="font-mono">{finding.cwe}</span>
            <span className="inline-flex items-center gap-1.5">
              <Clock3 className="h-3.5 w-3.5" />
              {formatDate(report.run.finished_at)}
            </span>
          </div>
        </div>

        <div className="panel p-6 lg:col-span-4">
          <p className="eyebrow">CVSS 3.1 base</p>
          <div className="mt-2 flex items-end justify-between gap-4">
            <span className="font-mono text-4xl font-semibold tracking-tight text-white">
              {finding.cvss.score.toFixed(1)}
            </span>
            <SeverityBadge severity={finding.severity} />
          </div>
          <p className="mt-3 break-all rounded-lg border border-white/[0.06] bg-black/30 p-3 font-mono text-[10px] leading-5 text-slate-400">
            {finding.cvss.vector}
          </p>
          <div className="mt-4 grid grid-cols-2 gap-3 text-[11px]">
            <div>
              <p className="text-slate-500">OWASP</p>
              <p className="mt-1 text-slate-200">{finding.owasp.id}</p>
            </div>
            <div>
              <p className="text-slate-500">Weakness</p>
              <p className="mt-1 font-mono text-slate-200">{finding.cwe}</p>
            </div>
          </div>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-12">
        <div className="panel p-5 lg:col-span-7">
          <h2 className="text-sm font-semibold text-white">Impact</h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">{finding.impact}</p>
          {evidence.notes && (
            <p className="mt-4 rounded-lg border border-amber-300/15 bg-amber-300/[0.04] p-3 text-[11px] leading-5 text-amber-100/80">
              <span className="mr-1.5 font-semibold uppercase tracking-wider text-amber-300/80">Observed</span>
              {evidence.notes}
            </p>
          )}
        </div>

        {evidence.burst ? (
          <div className="panel p-5 lg:col-span-5">
            <h2 className="text-sm font-semibold text-white">Concurrency evidence</h2>
            <div className="mt-3 grid grid-cols-2 gap-2">
              {[
                { label: "Burst size", value: evidence.burst.attempts },
                { label: "Approved", value: `${evidence.burst.approved} (max ${evidence.burst.safe_max_approved})` },
                { label: "Wallet delta", value: formatCents(evidence.burst.ledger_delta_cents) },
                { label: "Approved volume", value: formatCents(evidence.burst.approved_total_cents) },
              ].map((stat) => (
                <div key={stat.label} className="rounded-lg border border-white/[0.06] bg-black/25 p-3">
                  <p className="text-[10px] uppercase tracking-[0.12em] text-slate-500">{stat.label}</p>
                  <p className="mt-1 font-mono text-sm text-slate-200">{stat.value}</p>
                </div>
              ))}
            </div>
            <p className="mt-3 text-[10px] leading-4 text-slate-500">
              {evidence.burst.transactions_recorded} ledger rows recorded · starting balance{" "}
              {formatCents(evidence.burst.starting_balance_cents)} · ending balance{" "}
              {formatCents(evidence.burst.ending_balance_cents)}
            </p>
          </div>
        ) : (
          <div className="panel p-5 lg:col-span-5">
            <h2 className="text-sm font-semibold text-white">Evidence summary</h2>
            <div className="mt-3 space-y-2 text-[11px]">
              <div className="flex justify-between gap-3 border-b border-white/[0.06] pb-2">
                <span className="text-slate-500">HTTP status</span>
                <span className="font-mono text-slate-200">{evidence.response.status}</span>
              </div>
              <div className="flex justify-between gap-3 border-b border-white/[0.06] pb-2">
                <span className="text-slate-500">Round trip</span>
                <span className="font-mono text-slate-200">{evidence.duration_ms ?? "—"} ms</span>
              </div>
              <div className="flex justify-between gap-3">
                <span className="text-slate-500">Check</span>
                <span className="font-mono text-slate-200">{finding.check_id}</span>
              </div>
            </div>
          </div>
        )}
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <div className="panel overflow-hidden">
          <div className="flex items-center justify-between border-b border-white/[0.06] px-5 py-3">
            <h2 className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-400">Request</h2>
            <span className="pill border-white/10 bg-white/[0.03] font-mono text-[10px] text-slate-300">
              {evidence.request.method}
            </span>
          </div>
          <div className="p-5">
            <code className="block break-all font-mono text-[11px] text-teal-200/80">
              {evidence.request.path}
            </code>
            <div className="mt-3 space-y-1">
              {Object.entries(evidence.request.headers).map(([header, value]) => (
                <p key={header} className="font-mono text-[10px] text-slate-500">
                  <span className="text-slate-400">{header}</span>: {value}
                </p>
              ))}
            </div>
            <pre className="code-block mt-3 max-h-72">{pretty(evidence.request.body)}</pre>
          </div>
        </div>

        <div className="panel overflow-hidden">
          <div className="flex items-center justify-between border-b border-white/[0.06] px-5 py-3">
            <h2 className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-400">Response</h2>
            <span
              className={`pill font-mono text-[10px] ${
                responseOk
                  ? "border-rose-400/25 bg-rose-400/10 text-rose-200"
                  : "border-teal-300/25 bg-teal-300/10 text-teal-200"
              }`}
            >
              HTTP {evidence.response.status}
            </span>
          </div>
          <div className="p-5">
            <pre className="code-block max-h-[22rem]">{pretty(evidence.response.body)}</pre>
          </div>
        </div>
      </section>

      <section className="panel overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-3">
          <div className="flex items-center gap-2">
            <GitCompareArrows className="h-4 w-4 text-slate-500" />
            <h2 className="text-sm font-semibold text-white">Remediation</h2>
          </div>
          <span className="text-[11px] text-slate-500">{finding.remediation.language}</span>
        </div>

        <div className="p-5">
          <p className="max-w-3xl text-sm leading-6 text-slate-300">{finding.remediation.summary}</p>

          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <div className="overflow-hidden rounded-xl border border-rose-400/20">
              <div className="flex items-center gap-2 border-b border-rose-400/15 bg-rose-400/[0.06] px-4 py-2.5">
                <Bug className="h-3.5 w-3.5 text-rose-300" />
                <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-rose-200">
                  Vulnerable
                </span>
              </div>
              <pre className="overflow-x-auto whitespace-pre bg-black/35 p-4 font-mono text-[11px] leading-5 text-rose-100/70">
                {finding.remediation.vulnerable}
              </pre>
            </div>

            <div className="overflow-hidden rounded-xl border border-teal-300/20">
              <div className="flex items-center gap-2 border-b border-teal-300/15 bg-teal-300/[0.06] px-4 py-2.5">
                <ShieldCheck className="h-3.5 w-3.5 text-teal-300" />
                <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-teal-200">
                  Secure
                </span>
              </div>
              <pre className="overflow-x-auto whitespace-pre bg-black/35 p-4 font-mono text-[11px] leading-5 text-teal-100/70">
                {finding.remediation.secure}
              </pre>
            </div>
          </div>
        </div>
      </section>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <Link
          href={`/graph?run=${report.run.id}`}
          className="inline-flex items-center gap-1.5 text-xs font-medium text-teal-300 hover:text-teal-200"
        >
          <Waypoints className="h-3.5 w-3.5" />
          See this path in the permission graph
          <ArrowUpRight className="h-3 w-3" />
        </Link>
        <Link
          href={`/?run=${report.run.id}`}
          className="text-xs text-slate-500 transition hover:text-slate-300"
        >
          Run {report.run.id}
        </Link>
      </div>
    </div>
  );
}
