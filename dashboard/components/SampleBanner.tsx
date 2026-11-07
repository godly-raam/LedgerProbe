export function SampleBanner({ live }: { live: boolean }) {
  if (live) return null;
  return (
    <div className="rounded-xl border border-amber-300/20 bg-amber-300/[0.06] px-4 py-3 text-xs leading-5 text-amber-100/90">
      <strong className="font-semibold">Sample data from the local lab.</strong>{" "}
      This is the bundled sample report from the local mock-bank fixture, not a live scan or a benchmark result.
    </div>
  );
}
