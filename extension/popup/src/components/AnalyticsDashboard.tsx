import { useState, useEffect } from "react";
import { getDomainAnalytics, ApiError } from "../../../lib/api";
import type { DomainAnalyticsResponse } from "../../../lib/api";

interface AnalyticsDashboardProps {
  domain: string;
  isStaleCache?: boolean;
}

function formatDate(isoString: string | null): string {
  if (!isoString) return "N/A";
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return "N/A";
    return d.toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return "N/A";
  }
}

const trendConfig = {
  IMPROVING: {
    label: "Improving Trajectory",
    icon: "↑",
    badgeClasses: "bg-emerald-500/15 border-emerald-500/40 text-emerald-400",
  },
  DEGRADING: {
    label: "Degrading Trajectory",
    icon: "↓",
    badgeClasses: "bg-red-500/15 border-red-500/40 text-red-400",
  },
  STABLE: {
    label: "Stable Performance",
    icon: "→",
    badgeClasses: "bg-blue-500/15 border-blue-500/40 text-blue-400",
  },
  INSUFFICIENT_DATA: {
    label: "Insufficient Data",
    icon: "ℹ",
    badgeClasses: "bg-slate-800 border-slate-700 text-slate-400",
  },
} as const;

export default function AnalyticsDashboard({ domain, isStaleCache }: AnalyticsDashboardProps) {
  const [data, setData] = useState<DomainAnalyticsResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isEmpty, setIsEmpty] = useState<boolean>(false);

  useEffect(() => {
    let isMounted = true;
    if (!domain) {
      setLoading(false);
      setIsEmpty(true);
      return;
    }

    setLoading(true);
    setError(null);
    setIsEmpty(false);

    getDomainAnalytics(domain)
      .then((res) => {
        if (!isMounted) return;
        setData(res);
        setLoading(false);
      })
      .catch((err) => {
        if (!isMounted) return;
        setLoading(false);
        if (err instanceof ApiError && err.statusCode === 404) {
          setIsEmpty(true);
        } else {
          setError(err instanceof ApiError ? err.message : "Failed to load domain analytics.");
        }
      });

    return () => {
      isMounted = false;
    };
  }, [domain]);

  if (loading) {
    return (
      <div className="p-4 flex flex-col gap-4 animate-pulse">
        <div className="h-6 w-1/3 bg-slate-800/60 rounded-md" />
        <div className="grid grid-cols-3 gap-2">
          <div className="h-16 bg-slate-800/50 rounded-xl" />
          <div className="h-16 bg-slate-800/50 rounded-xl" />
          <div className="h-16 bg-slate-800/50 rounded-xl" />
        </div>
        <div className="h-24 bg-slate-800/50 rounded-xl" />
      </div>
    );
  }

  if (isEmpty || (!loading && !data && !error)) {
    return (
      <div className="p-6 text-center flex flex-col items-center justify-center min-h-[220px]">
        <div className="w-12 h-12 rounded-xl bg-slate-800/60 border border-slate-700 flex items-center justify-center mb-3">
          <span className="text-slate-400 text-lg font-bold">📊</span>
        </div>
        <h3 className="text-sm font-bold text-slate-200">No Analytics History</h3>
        <p className="mt-1 text-xs text-slate-400 max-w-[240px]">
          No historical scan data available for this domain yet.
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 m-3 rounded-xl bg-red-500/10 border border-red-500/30 text-center">
        <span className="text-xs font-bold text-red-400 uppercase tracking-widest">Analytics Failure</span>
        <p className="mt-1 text-xs text-slate-300">{error}</p>
      </div>
    );
  }

  if (!data) return null;

  const trend = trendConfig[data.trend] || trendConfig.INSUFFICIENT_DATA;
  const totalScans = data.total_scans || 0;
  const lowCount = data.risk_distribution?.low || 0;
  const medCount = data.risk_distribution?.medium || 0;
  const highCount = data.risk_distribution?.high || 0;
  const totalRiskCount = lowCount + medCount + highCount || 1;

  const lowPct = Math.round((lowCount / totalRiskCount) * 100);
  const medPct = Math.round((medCount / totalRiskCount) * 100);
  const highPct = Math.round((highCount / totalRiskCount) * 100);

  const delta = data.score_delta;
  const deltaText = delta !== null && delta !== undefined ? (delta > 0 ? `+${delta}` : `${delta}`) : "N/A";
  const deltaColor = delta !== null && delta !== undefined ? (delta > 0 ? "text-emerald-400" : delta < 0 ? "text-red-400" : "text-slate-400") : "text-slate-400";

  return (
    <div className="flex flex-col p-4 gap-4">
      {/* Stale Cache Banner */}
      {isStaleCache && (
        <div className="px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center gap-2">
          <span className="text-amber-400 text-xs">⚠️</span>
          <span className="text-[11px] font-semibold text-amber-300">
            Displayed analytics are cached/stale.
          </span>
        </div>
      )}

      {/* Domain & Trend Header */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
        <div>
          <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Historical Trajectory</span>
          <h2 className="text-sm font-extrabold text-slate-100 truncate max-w-[200px]">{data.domain}</h2>
        </div>
        <span className={`px-2.5 py-1 rounded-full border text-[10px] font-bold uppercase tracking-wider flex items-center gap-1 ${trend.badgeClasses}`}>
          <span>{trend.icon}</span>
          <span>{trend.label}</span>
        </span>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-3 gap-2">
        <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/60 flex flex-col items-center text-center">
          <span className="text-[9px] font-bold text-slate-500 uppercase tracking-wider">Current</span>
          <span className="text-lg font-black text-blue-400 mt-0.5">
            {data.current_trust_score !== null ? data.current_trust_score : "N/A"}
          </span>
        </div>

        <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/60 flex flex-col items-center text-center">
          <span className="text-[9px] font-bold text-slate-500 uppercase tracking-wider">Average</span>
          <span className="text-lg font-black text-slate-200 mt-0.5">
            {data.average_trust_score !== undefined ? data.average_trust_score.toFixed(1) : "N/A"}
          </span>
        </div>

        <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/60 flex flex-col items-center text-center">
          <span className="text-[9px] font-bold text-slate-500 uppercase tracking-wider">Delta</span>
          <span className={`text-lg font-black mt-0.5 ${deltaColor}`}>{deltaText}</span>
        </div>
      </div>

      {/* Secondary Metrics Bar */}
      <div className="flex justify-between items-center px-3 py-2 rounded-xl bg-slate-900/40 border border-slate-800/40 text-xs">
        <div className="flex items-center gap-1.5">
          <span className="text-slate-500 font-medium">Range:</span>
          <span className="font-bold text-slate-300">
            {data.min_trust_score ?? "N/A"} – {data.max_trust_score ?? "N/A"}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-slate-500 font-medium">Scans:</span>
          <span className="font-bold text-slate-200">{totalScans}</span>
        </div>
      </div>

      {/* Risk Distribution Section */}
      <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800/60 flex flex-col gap-2">
        <div className="flex justify-between items-center">
          <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Risk Level Distribution</span>
          <span className="text-[10px] font-semibold text-slate-400">{totalScans} total scans</span>
        </div>

        {/* Stacked Progress Bar */}
        <div className="h-2 w-full rounded-full bg-slate-800 flex overflow-hidden">
          <div style={{ width: `${lowPct}%` }} className="bg-emerald-500 h-full" title={`Low Risk: ${lowCount}`} />
          <div style={{ width: `${medPct}%` }} className="bg-amber-500 h-full" title={`Medium Risk: ${medCount}`} />
          <div style={{ width: `${highPct}%` }} className="bg-red-500 h-full" title={`High Risk: ${highCount}`} />
        </div>

        {/* Legend */}
        <div className="flex justify-between text-[10px] text-slate-400 pt-1">
          <div className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            <span>Low: {lowCount}</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-amber-500" />
            <span>Medium: {medCount}</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-red-500" />
            <span>High: {highCount}</span>
          </div>
        </div>
      </div>

      {/* Scan History Timeline */}
      <div className="flex flex-col gap-2">
        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Scan Timeline History</span>
        {data.history_timeline && data.history_timeline.length > 0 ? (
          <div className="flex flex-col gap-2 max-h-[160px] overflow-y-auto pr-1">
            {data.history_timeline.map((item, idx) => {
              const riskBadgeClass =
                item.risk_level === "LOW"
                  ? "border-emerald-500/40 text-emerald-400 bg-emerald-500/10"
                  : item.risk_level === "MEDIUM"
                  ? "border-amber-500/40 text-amber-400 bg-amber-500/10"
                  : "border-red-500/40 text-red-400 bg-red-500/10";

              return (
                <div key={item.scan_id || idx} className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/60 flex flex-col gap-1">
                  <div className="flex justify-between items-center text-xs">
                    <span className="font-semibold text-slate-300">{formatDate(item.scanned_at)}</span>
                    <div className="flex items-center gap-1.5">
                      <span className="font-black text-slate-200">{item.trust_score}</span>
                      <span className={`px-1.5 py-0.5 rounded border text-[9px] font-bold uppercase ${riskBadgeClass}`}>
                        {item.risk_level}
                      </span>
                    </div>
                  </div>
                  {item.summary && <p className="text-[11px] text-slate-400 leading-tight truncate">{item.summary}</p>}
                </div>
              );
            })}
          </div>
        ) : (
          <p className="text-xs text-slate-500 italic">No timeline entries recorded.</p>
        )}
      </div>

      {/* Timestamps Footer */}
      <div className="flex justify-between text-[10px] text-slate-500 pt-2 border-t border-slate-800/60">
        <span>First: {formatDate(data.first_scanned_at)}</span>
        <span>Last: {formatDate(data.last_scanned_at)}</span>
      </div>
    </div>
  );
}
