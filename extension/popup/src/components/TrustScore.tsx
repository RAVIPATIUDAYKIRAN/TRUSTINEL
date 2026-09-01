import type { TrustReport } from "../../../lib/api";

interface TrustScoreProps {
  report: TrustReport;
}

const riskConfig = {
  LOW: {
    label: "Overall Risk: LOW",
    badgeClasses: "bg-emerald-500/15 border-emerald-500/40 text-emerald-400",
    scoreColor: "text-emerald-400",
    ringColor: "stroke-emerald-500",
  },
  MEDIUM: {
    label: "Overall Risk: MEDIUM",
    badgeClasses: "bg-amber-500/15 border-amber-500/40 text-amber-400",
    scoreColor: "text-amber-400",
    ringColor: "stroke-amber-500",
  },
  HIGH: {
    label: "Overall Risk: HIGH SCAM RISK",
    badgeClasses: "bg-red-500/15 border-red-500/40 text-red-400 animate-pulse",
    scoreColor: "text-red-400",
    ringColor: "stroke-red-500",
  },
} as const;

export default function TrustScore({ report }: TrustScoreProps) {
  const overallRiskLevel = report.overall_risk_level || report.risk_level;
  const config = riskConfig[overallRiskLevel] || riskConfig.LOW;

  const displayOverallScore = report.overall_risk_score !== undefined && report.overall_risk_score !== null
    ? report.overall_risk_score
    : (report.risk_level === "HIGH" ? 85 : report.risk_level === "MEDIUM" ? 55 : 15);

  const percentage = displayOverallScore / 100;
  const circumference = 2 * Math.PI * 40;
  const strokeDashoffset = circumference * (1 - percentage);

  const techScore = report.technical_trust_score ?? report.trust_score;
  const contentRisk = report.content_risk_score ?? 0;
  const behavioralRisk = report.behavioral_risk_score ?? 0;
  const repRisk = report.reputation_risk_score ?? 0;

  return (
    <div className="w-full flex flex-col items-center gap-4">
      {/* Primary Overall Scam Risk Ring */}
      <div className="flex flex-col items-center gap-2">
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
              {displayOverallScore}
            </span>
            <span className="text-[9px] font-semibold text-slate-500 uppercase tracking-wider">
              Scam Risk
            </span>
          </div>
        </div>

        {/* Overall Scam Risk Badge */}
        <span
          className={`px-3 py-1 rounded-full border text-[11px] font-bold uppercase tracking-widest ${config.badgeClasses}`}
        >
          {config.label}
        </span>
      </div>

      {/* Multi-Dimensional Risk Grid */}
      <div className="w-full grid grid-cols-2 gap-2 text-center">
        {/* Technical Security Score */}
        <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/80 flex flex-col items-center">
          <span className="text-[9px] font-bold text-slate-500 uppercase tracking-wider">Technical Security</span>
          <span className={`text-base font-black mt-0.5 ${techScore >= 80 ? "text-emerald-400" : techScore >= 50 ? "text-amber-400" : "text-red-400"}`}>
            {techScore} <span className="text-[10px] text-slate-500 font-normal">/ 100</span>
          </span>
          <span className="text-[9px] text-slate-400 font-medium">SSL / WHOIS / Headers</span>
        </div>

        {/* Content Scam Risk */}
        <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/80 flex flex-col items-center">
          <span className="text-[9px] font-bold text-slate-500 uppercase tracking-wider">Content Scam Risk</span>
          <span className={`text-base font-black mt-0.5 ${contentRisk >= 60 ? "text-red-400" : contentRisk >= 30 ? "text-amber-400" : "text-emerald-400"}`}>
            {contentRisk} <span className="text-[10px] text-slate-500 font-normal">/ 100</span>
          </span>
          <span className="text-[9px] text-slate-400 font-medium">Urgency / Discounts</span>
        </div>

        {/* Behavioral Risk */}
        <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/80 flex flex-col items-center">
          <span className="text-[9px] font-bold text-slate-500 uppercase tracking-wider">Behavioral Risk</span>
          <span className={`text-base font-black mt-0.5 ${behavioralRisk >= 60 ? "text-red-400" : behavioralRisk >= 30 ? "text-amber-400" : "text-emerald-400"}`}>
            {behavioralRisk} <span className="text-[10px] text-slate-500 font-normal">/ 100</span>
          </span>
          <span className="text-[9px] text-slate-400 font-medium">Domain Age / Anomalies</span>
        </div>

        {/* Reputation Threat */}
        <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/80 flex flex-col items-center">
          <span className="text-[9px] font-bold text-slate-500 uppercase tracking-wider">Reputation Threat</span>
          <span className={`text-base font-black mt-0.5 ${repRisk >= 60 ? "text-red-400" : repRisk >= 30 ? "text-amber-400" : "text-emerald-400"}`}>
            {repRisk} <span className="text-[10px] text-slate-500 font-normal">/ 100</span>
          </span>
          <span className="text-[9px] text-slate-400 font-medium">Threat Blacklists</span>
        </div>
      </div>
    </div>
  );
}
