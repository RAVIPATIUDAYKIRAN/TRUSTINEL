import { useState } from "react";
import type { TrustReport } from "../../../lib/api";

interface RiskWarningProps {
  report: TrustReport;
  isStale?: boolean;
}

export default function RiskWarning({ report, isStale }: RiskWarningProps) {
  const [dismissed, setDismissed] = useState(false);

  const topRisks = (report.key_risks || []).slice(0, 4);

  // ---------------------------------------------------------------------------
  // HIGH RISK UI
  // ---------------------------------------------------------------------------
  if (report.risk_level === "HIGH") {
    if (dismissed) {
      return (
        <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-bold text-red-400">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              className="h-4 w-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
              />
            </svg>
            <span>High Risk Warning Dismissed</span>
          </div>
          <button
            onClick={() => setDismissed(false)}
            className="text-[10px] font-bold text-red-400 underline hover:text-red-300 transition-colors"
          >
            Show Warning
          </button>
        </div>
      );
    }

    return (
      <div className="p-4 rounded-xl bg-gradient-to-br from-red-950/80 via-red-900/40 to-slate-950 border-2 border-red-500/70 shadow-xl shadow-red-500/10 flex flex-col gap-3 text-slate-100">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-red-500/30 pb-2.5">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-red-500/20 border border-red-500/40 flex items-center justify-center shrink-0">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                className="h-4 w-4 text-red-400"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2.5}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                />
              </svg>
            </div>
            <div>
              <span className="text-xs font-black uppercase tracking-widest text-red-400">
                HIGH RISK WARNING
              </span>
              <p className="text-[10px] font-medium text-slate-400">
                Score: {report.trust_score} / 100
              </p>
            </div>
          </div>
          {isStale && (
            <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-amber-500/20 border border-amber-500/40 text-amber-300">
              Outdated
            </span>
          )}
        </div>

        {/* Message */}
        <p className="text-xs text-slate-200 leading-relaxed font-medium">
          {report.summary ||
            "This website shows elevated risk indicators based on the available security analysis."}
        </p>

        {/* Top Key Risks */}
        {topRisks.length > 0 && (
          <div className="p-2.5 rounded-lg bg-red-950/50 border border-red-500/20 flex flex-col gap-1.5">
            <span className="text-[10px] font-bold text-red-300 uppercase tracking-widest">
              Primary Concerns ({topRisks.length})
            </span>
            <ul className="flex flex-col gap-1">
              {topRisks.map((risk, i) => (
                <li key={i} className="flex items-start gap-1.5 text-[11px] text-slate-300 leading-tight">
                  <span className="text-red-400 shrink-0 mt-0.5">⚠</span>
                  <span className="break-words">{risk}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Stale warning note */}
        {isStale && (
          <p className="text-[10px] text-amber-300/90 italic bg-amber-500/10 p-1.5 rounded border border-amber-500/20">
            ⚠️ Note: This result was generated &gt;10 minutes ago and may be outdated.
          </p>
        )}

        {/* Actions */}
        <div className="flex items-center gap-2 pt-1">
          <button
            onClick={() => setDismissed(true)}
            className="flex-1 py-2 rounded-lg bg-slate-800/90 hover:bg-slate-800 border border-slate-700/80 text-slate-300 text-[11px] font-bold uppercase tracking-wider transition-all duration-150 active:scale-[0.98]"
          >
            Continue Anyway
          </button>
        </div>
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // MEDIUM RISK UI
  // ---------------------------------------------------------------------------
  if (report.risk_level === "MEDIUM") {
    return (
      <div className="p-3.5 rounded-xl bg-gradient-to-br from-amber-950/60 via-amber-900/20 to-slate-950 border border-amber-500/50 shadow-md flex flex-col gap-2.5 text-slate-100">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-lg bg-amber-500/20 border border-amber-500/40 flex items-center justify-center shrink-0">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                className="h-3.5 w-3.5 text-amber-400"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2.5}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
            </div>
            <span className="text-xs font-black uppercase tracking-widest text-amber-400">
              MEDIUM RISK CAUTION
            </span>
          </div>
          {isStale && (
            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-amber-500/20 border border-amber-500/40 text-amber-300">
              Outdated
            </span>
          )}
        </div>

        <p className="text-xs text-slate-300 leading-relaxed font-medium">
          {report.summary ||
            "This website shows mixed trust indicators and should be reviewed carefully."}
        </p>

        {topRisks.length > 0 && (
          <div className="p-2 rounded-lg bg-amber-950/40 border border-amber-500/20 flex flex-col gap-1">
            <span className="text-[9px] font-bold text-amber-300 uppercase tracking-widest">
              Identified Concerns
            </span>
            <ul className="flex flex-col gap-1">
              {topRisks.map((risk, i) => (
                <li key={i} className="flex items-start gap-1.5 text-[11px] text-slate-300 leading-tight">
                  <span className="text-amber-400 shrink-0">⚠</span>
                  <span className="break-words">{risk}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {isStale && (
          <p className="text-[10px] text-amber-300/90 italic bg-amber-500/10 p-1 rounded border border-amber-500/20">
            ⚠️ Note: This result was generated &gt;10 minutes ago and may be outdated.
          </p>
        )}
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // LOW RISK UI
  // ---------------------------------------------------------------------------
  return (
    <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-between gap-2">
      <div className="flex items-center gap-2">
        <div className="w-5 h-5 rounded bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center shrink-0">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            className="h-3.5 w-3.5 text-emerald-400"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2.5}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
        </div>
        <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-widest">
          LOW RISK — Strong Trust Signals
        </span>
      </div>
      {isStale && (
        <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-amber-500/20 border border-amber-500/40 text-amber-300 shrink-0">
          Outdated
        </span>
      )}
    </div>
  );
}
