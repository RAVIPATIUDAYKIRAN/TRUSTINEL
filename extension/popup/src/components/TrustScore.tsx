import type { TrustReport } from "../../../lib/api";

interface TrustScoreProps {
  report: TrustReport;
}

const riskConfig = {
  LOW: {
    label: "Low Risk",
    badgeClasses: "bg-emerald-500/15 border-emerald-500/40 text-emerald-400",
    scoreColor: "text-emerald-400",
    ringColor: "stroke-emerald-500",
  },
  MEDIUM: {
    label: "Medium Risk",
    badgeClasses: "bg-amber-500/15 border-amber-500/40 text-amber-400",
    scoreColor: "text-amber-400",
    ringColor: "stroke-amber-500",
  },
  HIGH: {
    label: "High Risk",
    badgeClasses: "bg-red-500/15 border-red-500/40 text-red-400",
    scoreColor: "text-red-400",
    ringColor: "stroke-red-500",
  },
} as const;

export default function TrustScore({ report }: TrustScoreProps) {
  const config = riskConfig[report.risk_level];
  const percentage = report.trust_score / 100;
  // SVG circle math: radius=40, circumference=2*PI*40 ≈ 251.33
  const circumference = 2 * Math.PI * 40;
  const strokeDashoffset = circumference * (1 - percentage);

  return (
    <div className="flex flex-col items-center gap-3">
      {/* Circular Score Ring */}
      <div className="relative w-28 h-28">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
          <circle
            cx="50" cy="50" r="40"
            fill="none" stroke="currentColor"
            strokeWidth="6"
            className="text-slate-800/60"
          />
          <circle
            cx="50" cy="50" r="40"
            fill="none"
            strokeWidth="6"
            strokeLinecap="round"
            className={config.ringColor}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            style={{ transition: "stroke-dashoffset 0.8s ease-out" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-3xl font-black ${config.scoreColor}`}>
            {report.trust_score}
          </span>
          <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
            / 100
          </span>
        </div>
      </div>

      {/* Risk Level Badge */}
      <span
        className={`px-3 py-1 rounded-full border text-[11px] font-bold uppercase tracking-widest ${config.badgeClasses}`}
      >
        {config.label}
      </span>
    </div>
  );
}
