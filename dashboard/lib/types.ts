export type Severity = "critical" | "high" | "medium" | "low";

export interface Cvss {
  score: number;
  vector: string;
}

export interface Owasp {
  id: string;
  name: string;
}

export interface Remediation {
  summary: string;
  language: string;
  vulnerable: string;
  secure: string;
}

export interface BurstEvidence {
  attempts: number;
  amount_cents: number;
  daily_limit_cents: number;
  status_counts: Record<string, number>;
  approved: number;
  safe_max_approved: number;
  approved_total_cents: number;
  starting_balance_cents: number;
  ending_balance_cents: number;
  ledger_delta_cents: number;
  balance_consistent: boolean;
  transactions_recorded: number;
}

export interface Evidence {
  request: {
    method: string;
    path: string;
    headers: Record<string, string>;
    body: unknown;
  };
  response: {
    status: number;
    body: unknown;
  };
  duration_ms?: number;
  notes?: string | null;
  burst?: BurstEvidence;
}

export interface Finding {
  id: string;
  check_id: string;
  title: string;
  suite: string;
  severity: Severity;
  cvss: Cvss;
  owasp: Owasp;
  cwe: string;
  endpoint: string;
  description: string;
  impact: string;
  evidence: Evidence;
  remediation: Remediation;
}

export interface GraphNode {
  id: string;
  label: string;
  kind: "principal" | "teen" | "resource" | string;
}

export interface GraphEdge {
  id: string;
  from: string;
  to: string;
  action: string;
  allowed: boolean;
  check_id: string | null;
  finding_id: string | null;
}

export interface CheckResult {
  name: string;
  suite: string;
  passed: boolean;
  detail: string;
}

export interface EndpointRisk {
  endpoint: string;
  findings: number;
  max_cvss: number;
  worst_severity: Severity;
  owasp: string[];
}

export interface AuditReport {
  schema_version: string;
  run: {
    id: string;
    target: string;
    started_at: string;
    finished_at: string;
    duration_ms: number;
    score: number;
    grade: string;
    checks_total: number;
    checks_passed: number;
    checks_failed: number;
  };
  summary: {
    findings: number;
    by_severity: Record<Severity, number>;
    by_owasp: { id: string; name: string; count: number }[];
    endpoints: EndpointRisk[];
  };
  findings: Finding[];
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  checks: CheckResult[];
}
