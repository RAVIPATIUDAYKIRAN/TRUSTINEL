import { useState } from "react";
import type { AIThreatAnalysisResult } from "../../../lib/api";

interface AIThreatAnalysisProps {
  aiThreat?: AIThreatAnalysisResult | null;
}

const threatConfig = {
  LOW: {
    label: "LOW THREAT",
    badgeClasses: "bg-emerald-500/15 border-emerald-500/40 text-emerald-400",
    containerBorder: "border-emerald-500/20",
    glowColor: "bg-emerald-500/5",
  },
  MEDIUM: {
    label: "MEDIUM THREAT",
    badgeClasses: "bg-amber-500/15 border-amber-500/40 text-amber-400",
    containerBorder: "border-amber-500/20",
    glowColor: "bg-amber-500/5",
  },
  HIGH: {
    label: "HIGH THREAT",
    badgeClasses: "bg-red-500/15 border-red-500/40 text-red-400",
    containerBorder: "border-red-500/30",
    glowColor: "bg-red-500/10",
  },
  UNKNOWN: {
    label: "UNKNOWN THREAT",
    badgeClasses: "bg-slate-800 border-slate-700 text-slate-400",
    containerBorder: "border-slate-800",
    glowColor: "bg-slate-900/40",
  },
} as const;

export default function AIThreatAnalysis({ aiThreat }: AIThreatAnalysisProps) {
  const [showEvidence, setShowEvidence] = useState(false);

  if (!aiThreat || !aiThreat.enabled) {
    const reasonText = aiThreat?.reasoning || "AI provider API key / model configuration is missing or unconfigured.";
    return (
      <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80 flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-amber-500/80" />
            <span className="text-[10px] font-extrabold tracking-widest text-slate-400 uppercase">
              AI Threat Assessment
            </span>
          </div>
          <span className="px-2 py-0.5 rounded border border-slate-800 bg-slate-900 text-[10px] font-bold text-amber-400 uppercase tracking-wider">
            UNAVAILABLE
          </span>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">
          {reasonText}
        </p>
        <div className="text-[10px] font-semibold text-emerald-400/90 pt-1 border-t border-slate-800/60">
          ✓ Multi-dimensional scam risk & technical security assessments remain 100% active.
        </div>
      </div>
    );
  }

  const threatLevel = aiThreat.threat_level as keyof typeof threatConfig;
  const config = threatConfig[threatLevel] || threatConfig.UNKNOWN;
  const confidencePercent = Math.round(aiThreat.confidence * 100);

  if (threatLevel === "UNKNOWN") {
    return (
      <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/60 flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] font-extrabold tracking-widest text-slate-400 uppercase">
              AI Threat Assessment
            </span>
          </div>
          <span className={`px-2 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider ${config.badgeClasses}`}>
            UNKNOWN
          </span>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">
          Available evidence was insufficient for a reliable AI threat assessment.
        </p>
      </div>
    );
  }

  return (
    <div className={`p-3.5 rounded-xl bg-slate-900/60 border ${config.containerBorder} flex flex-col gap-3 relative overflow-hidden`}>
      {/* Decorative background glow */}
      <div className={`absolute inset-0 ${config.glowColor} pointer-events-none`} />

      {/* Header */}
      <div className="flex items-center justify-between z-10">
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] font-extrabold tracking-widest text-slate-400 uppercase">
            AI Threat Assessment
          </span>
        </div>
        <span className={`px-2.5 py-0.5 rounded-full border text-[10px] font-extrabold uppercase tracking-wider ${config.badgeClasses}`}>
          {config.label}
        </span>
      </div>

      {/* Confidence */}
      <div className="flex items-center gap-2 text-[11px] font-medium text-slate-400 z-10">
        <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <span>Analysis confidence: {confidencePercent}%</span>
      </div>

      {/* Reasoning */}
      {aiThreat.reasoning && (
        <p className="text-xs text-slate-300 leading-relaxed z-10">
          {aiThreat.reasoning}
        </p>
      )}

      {/* Suspicious Indicators */}
      {aiThreat.suspicious_indicators && aiThreat.suspicious_indicators.length > 0 && (
        <div className="flex flex-col gap-1.5 z-10">
          <span className="text-[10px] font-bold text-amber-400 uppercase tracking-widest">
            Suspicious Indicators
          </span>
          <ul className="flex flex-col gap-1">
            {aiThreat.suspicious_indicators.map((ind, i) => (
              <li key={i} className="flex items-start gap-1.5 text-xs text-slate-300">
                <span className="text-amber-400 shrink-0">•</span>
                <span>{ind}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Recommended Action */}
      {aiThreat.recommended_action && (
        <div className="p-2.5 rounded-lg bg-slate-950/40 border border-slate-800/80 z-10">
          <span className="text-[10px] font-bold text-blue-400 uppercase tracking-widest">
            AI Recommendation
          </span>
          <p className="mt-0.5 text-xs text-slate-300 leading-relaxed">
            {aiThreat.recommended_action}
          </p>
        </div>
      )}

      {/* Evidence Traceability Section */}
      {aiThreat.evidence_mappings && aiThreat.evidence_mappings.length > 0 && (
        <div className="pt-2 border-t border-slate-800/60 flex flex-col z-10">
          <button
            onClick={() => setShowEvidence(!showEvidence)}
            className="flex items-center justify-between text-[10px] font-bold text-slate-400 uppercase tracking-widest hover:text-slate-200 transition-colors py-1"
          >
            <span>Evidence Used ({aiThreat.evidence_mappings.length})</span>
            <span>{showEvidence ? "▲ Hide" : "▼ Show"}</span>
          </button>

          {showEvidence && (
            <div className="mt-2 flex flex-col gap-2">
              {aiThreat.evidence_mappings.map((mapping, idx) => (
                <div key={idx} className="p-2.5 rounded-lg bg-slate-950/50 border border-slate-800/60 text-xs">
                  <div className="flex items-center justify-between mb-1">
                    <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[9px] font-extrabold uppercase tracking-wider text-slate-300">
                      {mapping.category}
                    </span>
                  </div>
                  <p className="font-semibold text-slate-200">{mapping.finding}</p>
                  <p className="mt-0.5 text-[11px] text-slate-400">{mapping.impact}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
