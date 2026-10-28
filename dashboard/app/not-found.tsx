import Link from "next/link";
import { ShieldQuestion } from "lucide-react";

export default function NotFound() {
  return (
    <div className="panel mx-auto mt-16 max-w-lg p-10 text-center">
      <ShieldQuestion className="mx-auto h-8 w-8 text-slate-500" />
      <h1 className="mt-4 text-lg font-semibold text-white">Not found in this audit</h1>
      <p className="mt-2 text-sm leading-6 text-slate-500">
        The finding or run may have been replaced by a newer scan.
      </p>
      <Link
        href="/"
        className="mt-5 inline-flex rounded-lg border border-teal-300/25 bg-teal-300/[0.08] px-4 py-2 text-xs font-medium text-teal-200 transition hover:bg-teal-300/[0.12]"
      >
        Back to overview
      </Link>
    </div>
  );
}
