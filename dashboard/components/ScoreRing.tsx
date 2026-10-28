import { scoreHex } from "@/lib/ui";

export function ScoreRing({ score, grade }: { score: number; grade: string }) {
  const radius = 56;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;
  const color = scoreHex(score);

  return (
    <div className="relative h-[148px] w-[148px] shrink-0">
      <svg viewBox="0 0 148 148" className="h-full w-full -rotate-90" role="img" aria-label={`Security score ${score} of 100`}>
        <circle cx="74" cy="74" r={radius} fill="none" stroke="#1c2634" strokeWidth="9" />
        <circle
          cx="74"
          cy="74"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-4xl font-semibold tracking-tight text-white">{score}</span>
        <span className="mono-label mt-0.5">/ 100 · {grade}</span>
      </div>
    </div>
  );
}
