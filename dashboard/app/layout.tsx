import type { Metadata } from "next";
import Link from "next/link";
import { Activity, ShieldAlert, Waypoints } from "lucide-react";

import "./globals.css";

export const metadata: Metadata = {
  title: "FinShield Core — Security Console",
  description:
    "Authorization logic, race-condition, and SIM-binding findings for the FinShield mock neobank.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-ink font-sans text-slate-200 antialiased">
        <div className="grid-backdrop pointer-events-none fixed inset-0 -z-10" />
        <header className="sticky top-0 z-20 border-b border-white/10 bg-ink/80 backdrop-blur-md">
          <div className="mx-auto flex w-full max-w-7xl flex-wrap items-center gap-x-8 gap-y-3 px-4 py-4 sm:px-6 lg:px-8">
            <Link href="/" className="group flex items-center gap-3">
              <span className="relative flex h-9 w-9 items-center justify-center rounded-xl border border-teal-300/30 bg-teal-300/10">
                <ShieldAlert className="h-5 w-5 text-teal-300" aria-hidden />
              </span>
              <span className="text-sm font-semibold tracking-tight text-white">
                FinShield<span className="text-teal-300">Core</span>
                <span className="ml-2 hidden text-[10px] font-normal uppercase tracking-[0.2em] text-slate-500 sm:inline">
                  Security Console
                </span>
              </span>
            </Link>

            <nav className="flex items-center gap-1 text-sm">
              <Link
                href="/"
                className="inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-slate-300 transition hover:bg-white/5 hover:text-white"
              >
                <Activity className="h-4 w-4" aria-hidden />
                Overview
              </Link>
              <Link
                href="/graph"
                className="inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-slate-300 transition hover:bg-white/5 hover:text-white"
              >
                <Waypoints className="h-4 w-4" aria-hidden />
                Permission graph
              </Link>
            </nav>

            <span className="ml-auto inline-flex items-center gap-2 rounded-full border border-amber-300/25 bg-amber-300/[0.07] px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-amber-200/90">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-amber-300" />
              Lab · authorized targets
            </span>
          </div>
        </header>

        <main className="mx-auto w-full max-w-7xl px-4 pb-20 pt-8 sm:px-6 lg:px-8">{children}</main>

        <footer className="border-t border-white/[0.06] py-6">
          <div className="mx-auto flex w-full max-w-7xl flex-col gap-2 px-4 text-[11px] text-slate-600 sm:flex-row sm:items-center sm:justify-between sm:px-6 lg:px-8">
            <span>FinShield-Core · self-contained neobank security harness</span>
            <span className="font-mono">Synthetic accounts · no live funds · never expose this lab</span>
          </div>
        </footer>
      </body>
    </html>
  );
}
