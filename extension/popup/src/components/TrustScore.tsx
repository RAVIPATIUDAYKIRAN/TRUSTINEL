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

  // D7 fix: Do NOT fabricate a numeric score when overall_risk_score is unavailable.
  // Preserve the distinction between legitimate low risk (score=0) and unavailable analysis (no score).
  const hasValidScore = report.overall_risk_score !== undefined
    && report.overall_risk_score !== null
    && typeof report.overall_risk_score === "number"
    && isFinite(report.overall_risk_score);
  const displayOverallScore = hasValidScore ? report.overall_risk_score! : null;

  const percentage = displayOverallScore !== null ? displayOverallScore / 100 : 0;
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
            {displayOverallScore !== null && (
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
            )}
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            {displayOverallScore !== null ? (
              <>
                <span className={`text-3xl font-black ${config.scoreColor}`}>
                  {displayOverallScore}
                </span>
                <span className="text-[9px] font-semibold text-slate-500 uppercase tracking-wider">
                  Scam Risk
                </span>
              </>
            ) : (
              <>
                <span className="text-xl font-black text-slate-500">
                  N/A
                </span>
                <span className="text-[8px] font-semibold text-slate-600 uppercase tracking-wider text-center leading-tight">
                  Analysis<br />Unavailable
                </span>
              </>
            )}
          </div>
        </div>

        {/* User-Facing Verdict Banner */}
        {report.user_facing_verdict && (
          <div className="flex flex-col items-center gap-1 mt-1 text-center max-w-[280px]">
            <span
              className={`px-3 py-1 rounded-full border text-[11px] font-black uppercase tracking-wider ${
                report.user_facing_verdict === "HIGH_CONFIDENCE_SCAM"
                  ? "bg-red-950/80 border-red-500/80 text-red-400 animate-pulse shadow-lg shadow-red-500/20"
                  : report.user_facing_verdict === "LIKELY_SCAM"
                  ? "bg-red-500/15 border-red-500/40 text-red-400"
                  : report.user_facing_verdict === "SUSPICIOUS"
                  ? "bg-amber-500/15 border-amber-500/40 text-amber-400"
                  : report.user_facing_verdict === "PROBABLY_LEGITIMATE"
                  ? "bg-emerald-500/15 border-emerald-500/30 text-emerald-300"
                  : report.user_facing_verdict === "LEGITIMATE"
                  ? "bg-emerald-500/20 border-emerald-500/50 text-emerald-400 font-extrabold"
                  : "bg-slate-800/60 border-slate-700 text-slate-400"
              }`}
            >
              VERDICT: {report.user_facing_verdict.replace(/_/g, " ")}
            </span>
            {report.recommended_user_action && (
              <p className="text-[11px] font-medium text-slate-300 leading-snug">
                {report.recommended_user_action}
              </p>
            )}
          </div>
        )}

        {/* Overall Scam Risk Badge */}
        {displayOverallScore !== null ? (
          <span
            className={`px-2.5 py-0.5 rounded-full border text-[10px] font-bold uppercase tracking-widest ${config.badgeClasses}`}
          >
            {config.label}
          </span>
        ) : (
          <span
            className="px-2.5 py-0.5 rounded-full border text-[10px] font-bold uppercase tracking-widest bg-slate-800/60 border-slate-700 text-slate-400"
          >
            ANALYSIS UNAVAILABLE
          </span>
        )}
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
