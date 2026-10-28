import Link from "next/link";
import { ArrowLeft, ShieldAlert } from "lucide-react";

import { PermissionGraph } from "@/components/PermissionGraph";
import { formatDate, getReports, pickReport } from "@/lib/reports";

export const dynamic = "force-dynamic";

export default async function GraphPage({
  searchParams,
}: {
  searchParams: Promise<{ run?: string }>;
}) {
  const params = await searchParams;
  const { reports } = getReports();
  const report = pickReport(reports, params.run);
  const exploited = report.graph.edges.filter((edge) => edge.finding_id).length;

  return (
    <div className="space-y-5">
      <Link
        href={`/?run=${report.run.id}`}
        className="inline-flex items-center gap-1.5 text-xs text-slate-400 transition hover:text-slate-200"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        Back to overview
      </Link>

      <section className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="eyebrow">Permission graph</p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight text-white sm:text-3xl">
            Parent-child authorization paths
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
            Each edge is a request the fuzzer made during this run. Red edges succeeded across a
            family boundary; select one to see the mapped finding.
          </p>
        </div>
        <div className="flex items-center gap-4 text-xs text-slate-500 lg:text-right">
          <div>
            <p className="font-mono text-slate-300">{report.run.id}</p>
            <p>
              {formatDate(report.run.finished_at)} · {report.run.target}
            </p>
          </div>
          <span className="pill border-rose-400/25 bg-rose-400/[0.07] text-rose-200">
            <ShieldAlert className="h-3 w-3" />
            {exploited} exploited path{exploited === 1 ? "" : "s"}
          </span>
        </div>
      </section>

      <PermissionGraph report={report} />
    </div>
  );
}
