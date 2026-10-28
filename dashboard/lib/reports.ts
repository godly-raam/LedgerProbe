import fs from "node:fs";
import path from "node:path";

import sampleJson from "@/data/sample-report.json";

import type { AuditReport, Finding } from "./types";

const sample = sampleJson as unknown as AuditReport;

export function reportsDirectory(): string {
  return process.env.REPORTS_DIR ?? path.resolve(process.cwd(), "..", "logic-fuzzer", "reports");
}

function isAuditReport(value: unknown): value is AuditReport {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<AuditReport>;
  return Boolean(
    candidate.schema_version &&
      candidate.run?.id &&
      candidate.summary &&
      Array.isArray(candidate.findings) &&
      candidate.graph?.nodes,
  );
}

export function getReports(): { reports: AuditReport[]; live: boolean } {
  const directory = reportsDirectory();
  let files: string[] = [];
  try {
    files = fs
      .readdirSync(/*turbopackIgnore: true*/ directory)
      .filter((file) => /^report-.*\.json$/.test(file));
  } catch {
    files = [];
  }

  const reports: AuditReport[] = [];
  for (const file of files) {
    try {
      const parsed: unknown = JSON.parse(
        fs.readFileSync(/*turbopackIgnore: true*/ path.join(directory, file), "utf8"),
      );
      if (isAuditReport(parsed)) reports.push(parsed);
    } catch {
      // A corrupt or partially written report must not break the console.
    }
  }

  reports.sort((a, b) => Date.parse(b.run.finished_at) - Date.parse(a.run.finished_at));

  if (reports.length === 0) {
    return { reports: [sample], live: false };
  }
  return { reports, live: true };
}

export function pickReport(reports: AuditReport[], runId?: string): AuditReport {
  if (runId) {
    const match = reports.find((report) => report.run.id === runId);
    if (match) return match;
  }
  return reports[0];
}

export function findFinding(
  reports: AuditReport[],
  findingId: string,
  runId?: string,
): { report: AuditReport; finding: Finding } | null {
  const ordered = runId
    ? [pickReport(reports, runId), ...reports.filter((report) => report.run.id !== runId)]
    : reports;
  for (const report of ordered) {
    const finding = report.findings.find((item) => item.id === findingId);
    if (finding) return { report, finding };
  }
  return null;
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString("en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  });
}

export function formatCents(cents: number): string {
  return (cents / 100).toLocaleString("en-US", { style: "currency", currency: "USD" });
}
