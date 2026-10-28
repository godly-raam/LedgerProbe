"use client";

import Link from "next/link";
import { useState } from "react";
import { ArrowRight, Crosshair, Lock, ShieldAlert, ShieldCheck } from "lucide-react";

import { SeverityBadge } from "@/components/SeverityBadge";
import type { AuditReport, GraphEdge, GraphNode } from "@/lib/types";

const WIDTH = 1120;
const HEIGHT = 620;
const NODE_W = 196;
const NODE_H = 64;
const TOP = 82;

const COLUMN_X: Record<string, number> = { principal: 48, teen: 462, resource: 876 };
const COLUMN_TITLE: Record<string, string> = {
  principal: "Principals",
  teen: "Teens",
  resource: "Protected resources",
};

type Position = { x: number; y: number };

function layout(nodes: GraphNode[]): Record<string, Position> {
  const groups: Record<string, GraphNode[]> = { principal: [], teen: [], resource: [] };
  for (const node of nodes) {
    (groups[node.kind] ??= []).push(node);
  }

  const positions: Record<string, Position> = {};
  for (const [kind, group] of Object.entries(groups)) {
    const x = COLUMN_X[kind] ?? 462;
    const usable = HEIGHT - TOP * 2 - NODE_H;
    group.forEach((node, index) => {
      const y = group.length === 1 ? HEIGHT / 2 : TOP + NODE_H / 2 + (usable * index) / (group.length - 1);
      positions[node.id] = { x, y };
    });
  }
  return positions;
}

function edgePath(from: Position, to: Position): string {
  const x1 = from.x + NODE_W;
  const y1 = from.y;
  const x2 = to.x;
  const y2 = to.y;
  const bend = (x1 + x2) / 2;
  return `M ${x1} ${y1} C ${bend} ${y1}, ${bend} ${y2}, ${x2} ${y2}`;
}

export function PermissionGraph({ report }: { report: AuditReport }) {
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const { nodes, edges } = report.graph;
  const positions = layout(nodes);
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const selectedEdge = edges.find((edge) => edge.id === selectedEdgeId) ?? null;
  const selectedFinding = selectedEdge?.finding_id
    ? report.findings.find((finding) => finding.id === selectedEdge.finding_id)
    : undefined;

  const exploited = edges.filter((edge) => edge.finding_id);
  const blocked = edges.filter((edge) => !edge.allowed);
  const legitimate = edges.filter((edge) => edge.allowed && !edge.finding_id);
  const compromisedNodes = new Set(
    exploited.flatMap((edge) => [edge.from, edge.to]),
  );

  if (nodes.length === 0) {
    return (
      <div className="panel p-10 text-center text-sm text-slate-500">
        This report has no permission graph data.
      </div>
    );
  }

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
      <div className="panel overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-3">
          <div className="flex items-center gap-4 text-[11px] text-slate-400">
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-rose-400" />
              Exploited {exploited.length}
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-teal-300" />
              Allowed control {legitimate.length}
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-slate-500" />
              Blocked {blocked.length}
            </span>
          </div>
          <span className="mono-label">Click an edge</span>
        </div>

        <div className="p-2 sm:p-4">
          <svg
            viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
            className="h-auto w-full"
            role="img"
            aria-label="Parent-child permission graph with exploited edges highlighted"
          >
            <defs>
              <marker id="arrow-exploited" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto">
                <path d="M0,0 L9,4.5 L0,9 z" fill="#fb7185" />
              </marker>
              <marker id="arrow-allowed" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto">
                <path d="M0,0 L9,4.5 L0,9 z" fill="#2dd4bf" />
              </marker>
              <marker id="arrow-blocked" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto">
                <path d="M0,0 L9,4.5 L0,9 z" fill="#64748b" />
              </marker>
            </defs>

            {Object.entries(COLUMN_TITLE).map(([kind, title]) => (
              <text
                key={kind}
                x={(COLUMN_X[kind] ?? 462) + NODE_W / 2}
                y={40}
                textAnchor="middle"
                fill="#64748b"
                fontSize="10"
                letterSpacing="1.6"
              >
                {title.toUpperCase()}
              </text>
            ))}

            {edges.map((edge) => {
              const from = positions[edge.from];
              const to = positions[edge.to];
              if (!from || !to) return null;
              const exploitedEdge = Boolean(edge.finding_id);
              const color = exploitedEdge ? "#fb7185" : edge.allowed ? "#2dd4bf" : "#64748b";
              const active = selectedEdgeId === edge.id;
              const dimmed = selectedEdgeId !== null && !active;
              return (
                <g key={edge.id} opacity={dimmed ? 0.25 : 1}>
                  <path
                    d={edgePath(from, to)}
                    fill="none"
                    stroke={color}
                    strokeWidth={active ? 3 : exploitedEdge ? 2.2 : 1.4}
                    strokeDasharray={!edge.allowed && !exploitedEdge ? "6 5" : undefined}
                    markerEnd={`url(#arrow-${exploitedEdge ? "exploited" : edge.allowed ? "allowed" : "blocked"})`}
                  />
                  <path
                    d={edgePath(from, to)}
                    fill="none"
                    stroke="transparent"
                    strokeWidth="18"
                    className="cursor-pointer"
                    onClick={() => setSelectedEdgeId(active ? null : edge.id)}
                    role="button"
                    tabIndex={0}
                    aria-label={`${edge.action} edge from ${nodeById.get(edge.from)?.label ?? edge.from} to ${
                      nodeById.get(edge.to)?.label ?? edge.to
                    }`}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setSelectedEdgeId(active ? null : edge.id);
                      }
                    }}
                  >
                    <title>{`${edge.action} · ${edge.allowed ? "allowed" : "blocked"}${exploitedEdge ? " · exploited" : ""}`}</title>
                  </path>
                  {exploitedEdge && (
                    <text
                      x={(from.x + NODE_W + to.x) / 2}
                      y={(from.y + to.y) / 2 - 7}
                      textAnchor="middle"
                      fill="#fda4af"
                      fontSize="9"
                      fontFamily="ui-monospace, monospace"
                      letterSpacing="0.8"
                      opacity={dimmed ? 0.3 : 0.9}
                    >
                      {edge.action.toUpperCase()}
                    </text>
                  )}
                </g>
              );
            })}

            {nodes.map((node) => {
              const position = positions[node.id];
              if (!position) return null;
              const isCompromised = compromisedNodes.has(node.id);
              const isResource = node.kind === "resource";
              return (
                <g key={node.id}>
                  <rect
                    x={position.x}
                    y={position.y - NODE_H / 2}
                    width={NODE_W}
                    height={NODE_H}
                    rx="10"
                    fill={isCompromised ? "#1a1119" : "#0b111a"}
                    stroke={isCompromised ? "#fb718580" : isResource ? "#1f3a3a" : "#263348"}
                    strokeWidth="1.2"
                  />
                  {isCompromised && (
                    <rect
                      x={position.x}
                      y={position.y - NODE_H / 2}
                      width="4"
                      height={NODE_H}
                      rx="2"
                      fill="#fb7185"
                    />
                  )}
                  <circle
                    cx={position.x + 20}
                    cy={position.y}
                    r="5"
                    fill={isCompromised ? "#fb7185" : isResource ? "#2dd4bf" : "#64748b"}
                  />
                  <text
                    x={position.x + 34}
                    y={position.y - 4}
                    fill="#e2e8f0"
                    fontSize="12"
                    fontWeight="600"
                  >
                    {node.label.length > 25 ? `${node.label.slice(0, 24)}…` : node.label}
                  </text>
                  <text
                    x={position.x + 34}
                    y={position.y + 14}
                    fill="#64748b"
                    fontSize="9"
                    letterSpacing="1"
                  >
                    {node.kind.toUpperCase()}
                  </text>
                  <title>{node.label}</title>
                </g>
              );
            })}
          </svg>
        </div>
      </div>

      <div className="space-y-4">
        <div className="panel p-5">
          {selectedEdge ? (
            <>
              <div className="flex items-center justify-between gap-2">
                <p className="eyebrow">Selected path</p>
                <button
                  type="button"
                  onClick={() => setSelectedEdgeId(null)}
                  className="text-[10px] text-slate-500 transition hover:text-slate-300"
                >
                  Clear
                </button>
              </div>

              <div className="mt-3 flex items-center gap-2 text-[11px]">
                <span className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 text-slate-300">
                  {nodeById.get(selectedEdge.from)?.label ?? selectedEdge.from}
                </span>
                <ArrowRight className="h-3.5 w-3.5 shrink-0 text-slate-500" />
                <span className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 text-slate-300">
                  {nodeById.get(selectedEdge.to)?.label ?? selectedEdge.to}
                </span>
              </div>

              <div className="mt-4 space-y-2 border-t border-white/[0.06] pt-3 text-[11px]">
                <div className="flex items-center justify-between">
                  <span className="text-slate-500">Action</span>
                  <span className="font-mono uppercase text-slate-300">{selectedEdge.action}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-500">Authorization</span>
                  <span className={selectedEdge.allowed ? "text-rose-300" : "text-teal-300"}>
                    {selectedEdge.allowed ? "Allowed" : "Blocked"}
                  </span>
                </div>
              </div>

              {selectedFinding ? (
                <div className="mt-4 rounded-xl border border-rose-400/20 bg-rose-400/[0.05] p-3">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-rose-300" />
                    <span className="font-mono text-[10px] text-rose-200">{selectedFinding.id}</span>
                    <SeverityBadge severity={selectedFinding.severity} compact />
                  </div>
                  <p className="mt-2 text-xs leading-5 text-slate-300">{selectedFinding.title}</p>
                  <Link
                    href={`/findings/${selectedFinding.id}?run=${report.run.id}`}
                    className="mt-3 inline-flex items-center gap-1 text-[11px] font-medium text-rose-200 hover:text-rose-100"
                  >
                    Open finding
                    <ArrowRight className="h-3 w-3" />
                  </Link>
                </div>
              ) : (
                <div className="mt-4 flex items-center gap-2 rounded-xl border border-teal-300/15 bg-teal-300/[0.04] p-3 text-[11px] text-teal-200">
                  <ShieldCheck className="h-4 w-4" />
                  Control path held
                </div>
              )}
            </>
          ) : (
            <>
              <div className="flex items-center gap-2">
                <Crosshair className="h-4 w-4 text-slate-500" />
                <p className="eyebrow">Escalation paths</p>
              </div>
              <p className="mt-2 text-[11px] leading-5 text-slate-500">
                Parent identities should only reach their own teen&apos;s resources. Solid red edges
                cross a family boundary and are linked to a finding.
              </p>
              <div className="mt-3 space-y-1.5">
                {exploited.map((edge) => (
                  <button
                    key={edge.id}
                    type="button"
                    onClick={() => setSelectedEdgeId(edge.id)}
                    className="flex w-full items-center gap-2 rounded-lg border border-white/[0.06] bg-black/25 px-3 py-2 text-left transition hover:border-rose-400/25 hover:bg-rose-400/[0.04]"
                  >
                    <Lock className="h-3.5 w-3.5 shrink-0 text-rose-300" />
                    <span className="min-w-0 flex-1 truncate text-[11px] text-slate-300">
                      {nodeById.get(edge.from)?.label} → {nodeById.get(edge.to)?.label}
                    </span>
                    <span className="font-mono text-[10px] uppercase text-slate-500">{edge.action}</span>
                  </button>
                ))}
                {exploited.length === 0 && (
                  <p className="rounded-lg border border-teal-300/15 bg-teal-300/[0.04] p-3 text-[11px] text-teal-200">
                    No cross-boundary access was observed.
                  </p>
                )}
              </div>
            </>
          )}
        </div>

        <div className="panel p-5">
          <p className="eyebrow">Graph legend</p>
          <dl className="mt-3 space-y-2.5 text-[11px]">
            <div className="flex items-start gap-2.5">
              <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-rose-400" />
              <div>
                <dt className="text-slate-300">Exploited edge</dt>
                <dd className="text-slate-500">Request succeeded across tenants</dd>
              </div>
            </div>
            <div className="flex items-start gap-2.5">
              <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-teal-300" />
              <div>
                <dt className="text-slate-300">Allowed control</dt>
                <dd className="text-slate-500">Legitimate owner access still works</dd>
              </div>
            </div>
            <div className="flex items-start gap-2.5">
              <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-slate-500" />
              <div>
                <dt className="text-slate-300">Blocked edge</dt>
                <dd className="text-slate-500">Target rejected the mutation</dd>
              </div>
            </div>
          </dl>
          <p className="mt-4 border-t border-white/[0.06] pt-3 font-mono text-[10px] leading-4 text-slate-600">
            {report.run.id}
          </p>
        </div>
      </div>
    </div>
  );
}
