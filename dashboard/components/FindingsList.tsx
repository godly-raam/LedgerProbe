import Link from "next/link";
import { ChevronRight } from "lucide-react";

import { SeverityBadge } from "@/components/SeverityBadge";
import { suiteLabels } from "@/lib/ui";
import type { AuditReport } from "@/lib/types";

export function FindingsList({ report }: { report: AuditReport }) {
  if (report.findings.length === 0) {
    return (
      <div className="mt-5 flex flex-col items-center justify-center rounded-xl border border-dashed border-teal-300/20 bg-teal-300/[0.03] px-6 py-10 text-center">
        <p className="text-sm font-medium text-teal-200">No findings in this run</p>
        <p className="mt-1 max-w-sm text-xs text-slate-500">
          Every authorization, MCC, and concurrency check was blocked by the target.
        </p>
      </div>
    );
  }

  return (
    <ol className="mt-3 divide-y divide-white/[0.06]">
      {report.findings.map((finding) => (
        <li key={finding.id}>
          <Link
            href={`/findings/${finding.id}?run=${report.run.id}`}
            className="group -mx-2 flex items-center gap-4 rounded-xl px-2 py-4 transition hover:bg-white/[0.03]"
          >
            <div className="hidden w-16 shrink-0 sm:block">
              <span className="font-mono text-[11px] text-slate-500">{finding.id}</span>
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} compact />
                <span className="text-[10px] uppercase tracking-[0.12em] text-slate-500">
                  {suiteLabels[finding.suite] ?? finding.suite}
                </span>
              </div>
              <h3 className="mt-1.5 truncate text-sm font-medium text-slate-100 group-hover:text-white">
                {finding.title}
              </h3>
              <p className="mt-1 truncate font-mono text-[11px] text-slate-500">
                {finding.endpoint} · {finding.owasp.id} · {finding.cwe}
              </p>
            </div>
            <div className="hidden shrink-0 text-right md:block">
              <p className="font-mono text-sm text-slate-200">{finding.cvss.score.toFixed(1)}</p>
              <p className="text-[9px] uppercase tracking-[0.14em] text-slate-500">CVSS 3.1</p>
            </div>
            <ChevronRight className="h-4 w-4 shrink-0 text-slate-600 transition group-hover:translate-x-0.5 group-hover:text-teal-300" />
          </Link>
        </li>
      ))}
    </ol>
  );
}
