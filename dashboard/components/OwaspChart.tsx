"use client";

import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import type { AuditReport } from "@/lib/types";

export function OwaspChart({ report }: { report: AuditReport }) {
  const data = report.summary.by_owasp.map((item) => ({
    name: item.id.replace(":2023", ""),
    label: item.name,
    count: item.count,
  }));

  if (data.length === 0) {
    return (
      <div className="mt-4 flex h-[210px] items-center justify-center rounded-xl border border-dashed border-white/10 text-xs text-slate-500">
        No mapped findings in this run.
      </div>
    );
  }

  return (
    <div className="mt-4 h-[210px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
          <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis
            allowDecimals={false}
            stroke="#64748b"
            tick={{ fontSize: 11 }}
            axisLine={false}
            tickLine={false}
            width={40}
          />
          <Tooltip
            cursor={{ fill: "rgba(148,163,184,0.06)" }}
            contentStyle={{
              background: "#0b111a",
              border: "1px solid #1c2634",
              borderRadius: 12,
              fontSize: 12,
            }}
            labelStyle={{ color: "#e2e8f0" }}
            formatter={(value) => [`${value} finding${value === 1 ? "" : "s"}`, "Count"]}
          />
          <Bar dataKey="count" fill="#2dd4bf" radius={[6, 6, 0, 0]} maxBarSize={48} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
