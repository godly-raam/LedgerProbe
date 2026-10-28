import Link from "next/link";
import {
  ArrowUpRight,
  CircleAlert,
  History,
  ListChecks,
  ServerCrash,
  ShieldCheck,
  XCircle,
} from "lucide-react";

import { FindingsList } from "@/components/FindingsList";
import { OwaspChart } from "@/components/OwaspChart";
import { ScoreRing } from "@/components/ScoreRing";
import { SeverityBadge } from "@/components/SeverityBadge";
import { StatCard } from "@/components/StatCard";
import { formatDate, getReports, pickReport } from "@/lib/reports";
import { scoreHex, scoreVerdict, severityBarClasses, severityDotClasses, suiteLabels } from "@/lib/ui";
import type { Severity } from "@/lib/types";

export const dynamic = "force-dynamic";

const severityOrder: Severity[] = ["critical", "high", "medium", "low"];

export default async function OverviewPage({
  searchParams,
}: {
  searchParams: Promise<{ run?: string }>;
}) {
  const params = await searchParams;
  const { reports, live } = getReports();
  const report = pickReport(reports, params.run);
  const { run, summary } = report;
  const totalFindings = summary.findings;
  const highRiskEndpoints = summary.endpoints.filter(
    (endpoint) => endpoint.worst_severity === "high" || endpoint.worst_severity === "critical",
  ).length;
  const failedChecks = report.checks.filter((check) => !check.passed);

  return (
    <div className="space-y-5">
      <section className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="eyebrow">Audit overview</p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight text-white sm:text-3xl">
            Neobank attack surface
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
            Stateful object-authorization, merchant-category, and concurrency probes against the
            FinShield mock bank. Findings are reproducible, scored with CVSS 3.1, and mapped to the
            OWASP API Security Top 10.
          </p>
        </div>

        <div className="flex flex-col gap-2 lg:items-end">
          <span
            className={`pill ${
              live
                ? "border-teal-300/25 bg-teal-300/[0.07] text-teal-200"
                : "border-sky-300/25 bg-sky-300/[0.07] text-sky-200"
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${live ? "bg-teal-300" : "bg-sky-300"}`} />
            {live ? "Live report directory" : "Bundled sample report"}
          </span>
          <div className="text-xs leading-5 text-slate-500 lg:text-right">
            <p className="font-mono text-slate-300">{run.id}</p>
            <p>
              {formatDate(run.finished_at)} · {(run.duration_ms / 1000).toFixed(1)}s
            </p>
            <p className="font-mono">{run.target}</p>
          </div>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-12">
        <div className="panel relative overflow-hidden p-6 lg:col-span-4">
          <div
            className="pointer-events-none absolute -right-16 -top-20 h-52 w-52 rounded-full opacity-20 blur-3xl"
            style={{ backgroundColor: scoreHex(run.score) }}
          />
          <div className="relative">
            <div className="flex items-center justify-between">
              <p className="eyebrow">Security score</p>
              <span className="pill border-white/10 bg-white/[0.04] text-slate-400">
                {scoreVerdict(run.score)}
              </span>
            </div>

            <div className="mt-5 flex items-center gap-5">
              <ScoreRing score={run.score} grade={run.grade} />
              <div className="min-w-0">
                <p className="text-sm font-medium text-slate-200">
                  {totalFindings === 0 ? "No open findings" : `${totalFindings} open findings`}
                </p>
                <p className="mt-1 text-xs leading-5 text-slate-500">
                  {run.checks_passed} of {run.checks_total} controls held under adversarial input.
                </p>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {severityOrder.map((severity) =>
                    summary.by_severity[severity] > 0 ? (
                      <span
                        key={severity}
                        className="inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 text-[10px] text-slate-400"
                      >
                        <span className={`h-1.5 w-1.5 rounded-full ${severityDotClasses[severity]}`} />
                        {summary.by_severity[severity]} {severity}
                      </span>
                    ) : null,
                  )}
                </div>
              </div>
            </div>

            <dl className="mt-6 grid grid-cols-2 gap-3 border-t border-white/[0.06] pt-4 text-xs">
              <div>
                <dt className="text-slate-500">Checks failed</dt>
                <dd className="mt-1 font-mono text-lg text-white">{run.checks_failed}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Scan duration</dt>
                <dd className="mt-1 font-mono text-lg text-white">{(run.duration_ms / 1000).toFixed(1)}s</dd>
              </div>
            </dl>

            <Link
              href={`/graph?run=${run.id}`}
              className="mt-5 inline-flex items-center gap-1.5 text-xs font-medium text-teal-300 transition hover:text-teal-200"
            >
              Inspect permission graph
              <ArrowUpRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        </div>

        <div className="space-y-4 lg:col-span-8">
          <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
            <StatCard
              label="Findings"
              value={totalFindings}
              hint="Reproducible issues in this run"
              tone="rose"
              icon={CircleAlert}
            />
            <StatCard
              label="High-risk endpoints"
              value={highRiskEndpoints}
              hint="Worst case high or critical"
              tone="amber"
              icon={ServerCrash}
            />
            <StatCard
              label="Checks passed"
              value={`${run.checks_passed}/${run.checks_total}`}
              hint="Positive and negative controls"
              tone="teal"
              icon={ShieldCheck}
            />
            <StatCard
              label="Scans in view"
              value={reports.length}
              hint={live ? "Read from the reports directory" : "Sample fallback only"}
              icon={History}
            />
          </div>

          <div className="panel p-5">
            <div className="flex items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-white">Severity mix</h2>
                <p className="mt-0.5 text-[11px] text-slate-500">
                  CVSS 3.1 base scores · {totalFindings} mapped finding{totalFindings === 1 ? "" : "s"}
                </p>
              </div>
              <span className="mono-label">run {run.id.slice(-6)}</span>
            </div>

            <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
              {severityOrder.map((severity) => {
                const count = summary.by_severity[severity];
                const percent = totalFindings > 0 ? Math.round((count / totalFindings) * 100) : 0;
                return (
                  <div key={severity} className="rounded-xl border border-white/[0.06] bg-black/20 p-3">
                    <div className="flex items-center justify-between gap-2">
                      <SeverityBadge severity={severity} compact />
                      <span className="font-mono text-lg leading-none text-white">{count}</span>
                    </div>
                    <div className="mt-3 h-1 overflow-hidden rounded-full bg-white/5">
                      <div
                        className={`h-full rounded-full ${severityBarClasses[severity]}`}
                        style={{ width: `${percent}%` }}
                      />
                    </div>
                    <p className="mt-1.5 text-[10px] text-slate-500">{percent}% of findings</p>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-12">
        <div className="panel p-5 lg:col-span-5">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-white">OWASP API Top 10</h2>
              <p className="mt-0.5 text-[11px] text-slate-500">Findings grouped by mapped category</p>
            </div>
            <span className="pill border-white/10 bg-white/[0.03] text-slate-400">
              {summary.by_owasp.length} categor{summary.by_owasp.length === 1 ? "y" : "ies"}
            </span>
          </div>
          <OwaspChart report={report} />
          <div className="mt-1 space-y-1.5 border-t border-white/[0.06] pt-3">
            {summary.by_owasp.map((category) => (
              <div key={category.id} className="flex items-center justify-between gap-3 text-[11px]">
                <span className="truncate text-slate-400">
                  <span className="mr-2 font-mono text-slate-500">{category.id}</span>
                  {category.name}
                </span>
                <span className="font-mono text-slate-300">{category.count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="panel p-5 lg:col-span-7">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-white">Endpoint risk</h2>
              <p className="mt-0.5 text-[11px] text-slate-500">
                Highest CVSS finding per attacked route
              </p>
            </div>
            <Link
              href={`/graph?run=${run.id}`}
              className="inline-flex items-center gap-1 text-[11px] font-medium text-teal-300 hover:text-teal-200"
            >
              Graph
              <ArrowUpRight className="h-3 w-3" />
            </Link>
          </div>

          <div className="mt-3 divide-y divide-white/[0.06]">
            {summary.endpoints.map((endpoint) => {
              const primaryFinding = report.findings.find((finding) => finding.endpoint === endpoint.endpoint);
              const content = (
                <div className="flex items-center gap-3 py-3">
                  <div className="min-w-0 flex-1">
                    <code className="block truncate font-mono text-[11px] text-slate-200">
                      {endpoint.endpoint}
                    </code>
                    <p className="mt-1 text-[10px] text-slate-500">
                      {endpoint.owasp.join(" · ")} · {endpoint.findings} finding
                      {endpoint.findings === 1 ? "" : "s"}
                    </p>
                  </div>
                  <SeverityBadge severity={endpoint.worst_severity} compact />
                  <div className="hidden w-16 text-right sm:block">
                    <p className="font-mono text-xs text-slate-200">{endpoint.max_cvss.toFixed(1)}</p>
                    <p className="text-[9px] uppercase tracking-[0.12em] text-slate-500">CVSS</p>
                  </div>
                </div>
              );

              return primaryFinding ? (
                <Link
                  key={endpoint.endpoint}
                  href={`/findings/${primaryFinding.id}?run=${run.id}`}
                  className="-mx-2 block rounded-lg px-2 transition hover:bg-white/[0.03]"
                >
                  {content}
                </Link>
              ) : (
                <div key={endpoint.endpoint}>{content}</div>
              );
            })}
            {summary.endpoints.length === 0 && (
              <p className="py-8 text-center text-xs text-slate-500">No endpoint findings in this run.</p>
            )}
          </div>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-12">
        <div className="panel p-5 lg:col-span-8">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-white">Findings</h2>
              <p className="mt-0.5 text-[11px] text-slate-500">
                Each finding includes captured traffic and a vulnerable/secure patch pair
              </p>
            </div>
            <span className="pill border-white/10 bg-white/[0.03] text-slate-400">
              {report.findings.length} total
            </span>
          </div>
          <FindingsList report={report} />
        </div>

        <div className="space-y-4 lg:col-span-4">
          <div className="panel p-5">
            <div className="flex items-center gap-2">
              <History className="h-4 w-4 text-slate-500" />
              <h2 className="text-sm font-semibold text-white">Run history</h2>
            </div>
            <p className="mt-0.5 text-[11px] text-slate-500">Newest report first</p>

            <div className="mt-3 space-y-1.5">
              {reports.map((entry) => {
                const active = entry.run.id === run.id;
                return (
                  <Link
                    key={entry.run.id}
                    href={`/?run=${entry.run.id}`}
                    className={`flex items-center gap-3 rounded-lg border px-3 py-2.5 transition ${
                      active
                        ? "border-teal-300/25 bg-teal-300/[0.06]"
                        : "border-transparent hover:border-white/10 hover:bg-white/[0.03]"
                    }`}
                  >
                    <span
                      className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border font-mono text-[11px]"
                      style={{
                        color: scoreHex(entry.run.score),
                        borderColor: `${scoreHex(entry.run.score)}40`,
                        backgroundColor: `${scoreHex(entry.run.score)}12`,
                      }}
                    >
                      {entry.run.score}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-[11px] text-slate-300">
                        {entry.run.id}
                      </span>
                      <span className="block text-[10px] text-slate-500">
                        {formatDate(entry.run.finished_at)} · {entry.summary.findings} findings
                      </span>
                    </span>
                    {active && <span className="h-1.5 w-1.5 rounded-full bg-teal-300" />}
                  </Link>
                );
              })}
            </div>
            {!live && (
              <p className="mt-3 border-t border-white/[0.06] pt-3 text-[10px] leading-4 text-slate-500">
                Live reports are read from <code className="text-slate-400">logic-fuzzer/reports</code>.
                Run the fuzzer to replace this sample.
              </p>
            )}
          </div>

          <div className="panel p-5">
            <div className="flex items-center gap-2">
              <ListChecks className="h-4 w-4 text-slate-500" />
              <h2 className="text-sm font-semibold text-white">Control coverage</h2>
            </div>
            <p className="mt-0.5 text-[11px] text-slate-500">
              {run.checks_passed}/{run.checks_total} checks held
            </p>

            <div className="mt-3 space-y-2">
              {failedChecks.slice(0, 5).map((check) => (
                <div key={check.name} className="flex gap-2.5 rounded-lg border border-white/[0.05] bg-black/20 p-2.5">
                  <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-300" />
                  <div className="min-w-0">
                    <p className="truncate font-mono text-[10px] text-slate-300">{check.name}</p>
                    <p className="mt-0.5 text-[10px] leading-4 text-slate-500">{check.detail}</p>
                  </div>
                </div>
              ))}
              {failedChecks.length === 0 && (
                <div className="flex items-center gap-2 rounded-lg border border-teal-300/20 bg-teal-300/[0.05] p-3 text-xs text-teal-200">
                  <ShieldCheck className="h-4 w-4" />
                  All checks passed
                </div>
              )}
              {failedChecks.length > 5 && (
                <p className="pl-1 text-[10px] text-slate-500">
                  +{failedChecks.length - 5} more failed checks
                </p>
              )}
            </div>

            <div className="mt-3 border-t border-white/[0.06] pt-3">
              <p className="mono-label mb-2">Suites</p>
              <div className="flex flex-wrap gap-1.5">
                {Object.keys(suiteLabels).map((suite) => (
                  <span
                    key={suite}
                    className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 text-[10px] text-slate-400"
                  >
                    {suiteLabels[suite]}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
