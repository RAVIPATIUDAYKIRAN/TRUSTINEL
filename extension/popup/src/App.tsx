import { useState, useEffect, useCallback } from "react";
import { scanWebsite, ApiError } from "../../lib/api";
import type { ScanResponse } from "../../lib/api";
import {
  isUnsupportedUrl,
  extractHostname,
  normalizeDomain,
  cacheKey,
  getCacheStatus,
  type CachedScanResult,
  type CacheStatus,
  type DomainState,
  type DomainStateResponse,
  type ScanMessageResponse,
  type ScanHistoryEntry,
  type ScanHistoryResponse,
  type ClearHistoryResponse,
} from "../../lib/types";
import TrustScore from "./components/TrustScore";
import SecurityDetails from "./components/SecurityDetails";
import RiskWarning from "./components/RiskWarning";
import AIThreatAnalysis from "./components/AIThreatAnalysis";

type AppState = "IDLE" | "SCANNING" | "RESULT" | "ERROR" | "UNSUPPORTED";

// ---------------------------------------------------------------------------
// Risk level colors (reused across components)
// ---------------------------------------------------------------------------

const riskColors = {
  LOW: { dot: "bg-emerald-500", text: "text-emerald-400", badge: "bg-emerald-500/15 border-emerald-500/40 text-emerald-400" },
  MEDIUM: { dot: "bg-amber-500", text: "text-amber-400", badge: "bg-amber-500/15 border-amber-500/40 text-amber-400" },
  HIGH: { dot: "bg-red-500", text: "text-red-400", badge: "bg-red-500/15 border-red-500/40 text-red-400" },
} as const;

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

function timeAgo(isoString: string): string {
  const seconds = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

// ---------------------------------------------------------------------------
// Background messaging with direct-API fallback
// ---------------------------------------------------------------------------

function requestDomainState(url: string): Promise<DomainState> {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(
        { type: "GET_DOMAIN_STATE", url },
        (response: DomainStateResponse) => {
          if (chrome.runtime.lastError || !response) {
            const domain = normalizeDomain(url);
            resolve({ domain, url, state: "IDLE" });
            return;
          }
          resolve(response.state);
        }
      );
    } catch {
      const domain = normalizeDomain(url);
      resolve({ domain, url, state: "IDLE" });
    }
  });
}

function scanViaBackground(url: string): Promise<ScanResponse> {
  return new Promise((resolve, reject) => {
    try {
      chrome.runtime.sendMessage(
        { type: "SCAN_CURRENT_TAB", url },
        (response: ScanMessageResponse) => {
          if (chrome.runtime.lastError) {
            const msg = chrome.runtime.lastError.message || "Service worker unavailable";
            console.warn("[TRUSTINEL] Background unavailable:", msg, "— falling back to direct API call");
            scanWebsite(url).then(resolve).catch(reject);
            return;
          }
          if (!response) {
            console.warn("[TRUSTINEL] No response from background — falling back to direct API call");
            scanWebsite(url).then(resolve).catch(reject);
            return;
          }
          if (response.success) {
            console.log("[TRUSTINEL] Scan completed via background service worker");
            resolve(response.data);
          } else {
            reject(new ApiError(response.error));
          }
        }
      );
    } catch {
      console.warn("[TRUSTINEL] sendMessage threw — falling back to direct API call");
      scanWebsite(url).then(resolve).catch(reject);
    }
  });
}

function requestScanHistory(): Promise<ScanHistoryEntry[]> {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(
        { type: "GET_SCAN_HISTORY" },
        (response: ScanHistoryResponse) => {
          if (chrome.runtime.lastError || !response || !Array.isArray(response.history)) {
            resolve([]);
            return;
          }
          resolve(response.history);
        }
      );
    } catch {
      resolve([]);
    }
  });
}

function requestClearHistory(): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(
        { type: "CLEAR_SCAN_HISTORY" },
        (response: ClearHistoryResponse) => {
          if (chrome.runtime.lastError || !response) {
            resolve(false);
            return;
          }
          resolve(response.success);
        }
      );
    } catch {
      resolve(false);
    }
  });
}

/** Load a cached domain result directly from chrome.storage.local */
async function loadCachedDomain(domain: string): Promise<CachedScanResult | null> {
  try {
    const key = cacheKey(domain);
    const data = await chrome.storage.local.get(key);
    return (data[key] as CachedScanResult) || null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// App Component
// ---------------------------------------------------------------------------

function App() {
  const [state, setState] = useState<AppState>("IDLE");
  const [tabUrl, setTabUrl] = useState<string>("");
  const [hostname, setHostname] = useState<string>("");
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>("");
  const [isCached, setIsCached] = useState(false);
  const [cacheStatus, setCacheStatus] = useState<CacheStatus>("MISSING");

  // History state
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const [viewingHistoryDomain, setViewingHistoryDomain] = useState<string | null>(null);

  // Load history
  const loadHistory = useCallback(async () => {
    const h = await requestScanHistory();
    setHistory(h);
  }, []);

  // Detect active tab URL and load cached state + history
  useEffect(() => {
    try {
      chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        const url = tabs?.[0]?.url || "";
        setTabUrl(url);
        setHostname(extractHostname(url));

        if (!url || isUnsupportedUrl(url)) {
          setState("UNSUPPORTED");
          loadHistory();
          return;
        }

        console.log("[TRUSTINEL] Popup opened for:", extractHostname(url));

        const domainState = await requestDomainState(url);

        if (domainState.state === "COMPLETED" && domainState.cached) {
          console.log("[TRUSTINEL] Loaded cached result for:", domainState.domain);
          setScanResult(domainState.cached.scanResponse);
          setIsCached(true);
          setCacheStatus(domainState.cacheStatus || getCacheStatus(domainState.cached));
          setState("RESULT");
        } else if (domainState.state === "SCANNING") {
          setState("SCANNING");
        } else if (domainState.state === "UNSUPPORTED") {
          setState("UNSUPPORTED");
        } else {
          setState("IDLE");
        }

        loadHistory();
      });
    } catch {
      setState("UNSUPPORTED");
      loadHistory();
    }
  }, [loadHistory]);

  const handleScan = useCallback(() => {
    if (!tabUrl || isUnsupportedUrl(tabUrl)) return;

    setState("SCANNING");
    setScanResult(null);
    setErrorMessage("");
    setIsCached(false);
    setCacheStatus("MISSING");
    setViewingHistoryDomain(null);

    console.log("[TRUSTINEL] Initiating scan for:", tabUrl);

    scanViaBackground(tabUrl)
      .then((data) => {
        console.log("[TRUSTINEL] Scan result received. Score:", data.trust_report?.trust_score);
        setScanResult(data);
        setState("RESULT");
        setIsCached(false);
        setCacheStatus("FRESH");
        // Refresh history after scan completes
        loadHistory();
      })
      .catch((err) => {
        const msg =
          err instanceof ApiError
            ? err.message
            : "An unexpected error occurred during the scan.";
        console.error("[TRUSTINEL] Scan error:", msg);
        setErrorMessage(msg);
        setState("ERROR");
      });
  }, [tabUrl, loadHistory]);

  const handleHistoryClick = useCallback(async (entry: ScanHistoryEntry) => {
    console.log("[TRUSTINEL] Loading history result for:", entry.domain);
    setViewingHistoryDomain(entry.domain);

    const cached = await loadCachedDomain(entry.domain);
    if (cached?.scanResponse) {
      setScanResult(cached.scanResponse);
      setIsCached(true);
      setCacheStatus(getCacheStatus(cached));
      setState("RESULT");
    } else {
      // Cached result was cleared but history entry remains — show minimal info
      setErrorMessage("Detailed result for this domain is no longer available. Scan again to refresh.");
      setState("ERROR");
    }
  }, []);

  const handleClearHistory = useCallback(async () => {
    const success = await requestClearHistory();
    if (success) {
      setHistory([]);
      console.log("[TRUSTINEL] History cleared by user.");
    }
    setShowClearConfirm(false);
  }, []);

  const handleBackToCurrentSite = useCallback(() => {
    setViewingHistoryDomain(null);
    setIsCached(false);
    setScanResult(null);
    setErrorMessage("");
    if (!tabUrl || isUnsupportedUrl(tabUrl)) {
      setState("UNSUPPORTED");
    } else {
      // Re-check for cached result of current tab
      requestDomainState(tabUrl).then((ds) => {
        if (ds.state === "COMPLETED" && ds.cached) {
          setScanResult(ds.cached.scanResponse);
          setIsCached(true);
          setState("RESULT");
        } else {
          setState("IDLE");
        }
      });
    }
  }, [tabUrl]);

  // Determine which domain label to show
  const displayDomain = viewingHistoryDomain || (hostname ? hostname : "");

  return (
    <div className="flex flex-col min-h-[400px] w-[360px] bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white font-sans overflow-hidden border border-slate-800 rounded-lg shadow-2xl relative">
      {/* Decorative Blur Orbs */}
      <div className="absolute -top-10 -left-10 w-24 h-24 bg-blue-500/10 rounded-full blur-xl pointer-events-none" />
      <div className="absolute -bottom-10 -right-10 w-24 h-24 bg-emerald-500/10 rounded-full blur-xl pointer-events-none" />

      {/* Header */}
      <header className="flex items-center justify-between px-5 py-4 border-b border-slate-800/80 bg-slate-900/40 backdrop-blur-md z-10">
        <div className="flex items-center gap-2">
          <div className="h-7 w-7 rounded-lg bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/20">
            <span className="text-xs font-black tracking-wider text-white">T</span>
          </div>
          <span className="text-sm font-extrabold tracking-widest bg-gradient-to-r from-blue-400 via-indigo-400 to-teal-400 bg-clip-text text-transparent">
            TRUSTINEL
          </span>
        </div>
        <div className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-widest">
            Active
          </span>
        </div>
      </header>

      {/* Main Body */}
      <main className="flex-1 flex flex-col z-10 overflow-y-auto">
        {/* Current Site Bar */}
        {displayDomain && state !== "UNSUPPORTED" && (
          <div className="px-5 py-3 border-b border-slate-800/50 bg-slate-900/30">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">
                  {viewingHistoryDomain ? "Viewing Result" : "Current Website"}
                </span>
                <p className="mt-0.5 text-sm font-semibold text-slate-200 truncate">{displayDomain}</p>
              </div>
              {viewingHistoryDomain && (
                <button
                  onClick={handleBackToCurrentSite}
                  className="text-[10px] font-bold text-blue-400 uppercase tracking-widest hover:text-blue-300 transition-colors"
                >
                  ← Back
                </button>
              )}
            </div>
          </div>
        )}

        {/* --- IDLE State --- */}
        {state === "IDLE" && !viewingHistoryDomain && (
          <div className="flex flex-col justify-center items-center px-6 py-8 text-center">
            <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-blue-500 to-indigo-600 flex items-center justify-center shadow-xl shadow-blue-500/25 mb-5">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-7 w-7 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <h2 className="text-lg font-black text-slate-100 tracking-tight">Ready to Analyze</h2>
            <p className="mt-1.5 text-xs text-slate-400 max-w-[260px]">
              Click the button below to evaluate the trust and security of this website.
            </p>
            <button
              onClick={handleScan}
              className="mt-6 w-full py-3 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 text-sm font-bold uppercase tracking-widest shadow-lg shadow-blue-500/25 hover:shadow-blue-500/40 hover:brightness-110 transition-all duration-200 active:scale-[0.98]"
            >
              Scan Website
            </button>
          </div>
        )}

        {/* --- SCANNING State --- */}
        {state === "SCANNING" && (
          <div className="flex-1 flex flex-col justify-center items-center px-6 py-8 text-center">
            <div className="relative w-16 h-16 mb-5">
              <div className="absolute inset-0 rounded-full border-2 border-slate-700" />
              <div className="absolute inset-0 rounded-full border-2 border-t-blue-500 animate-spin" />
              <div className="absolute inset-3 rounded-full border-2 border-slate-700/50" />
              <div className="absolute inset-3 rounded-full border-2 border-t-indigo-400 animate-spin" style={{ animationDirection: "reverse", animationDuration: "1.5s" }} />
            </div>
            <h2 className="text-lg font-black text-slate-100">Analyzing Website...</h2>
            <div className="mt-4 flex flex-col gap-1.5 text-xs text-slate-500">
              <span className="animate-pulse">Checking SSL certificate...</span>
              <span className="animate-pulse" style={{ animationDelay: "0.2s" }}>Verifying domain registration...</span>
              <span className="animate-pulse" style={{ animationDelay: "0.4s" }}>Inspecting security headers...</span>
              <span className="animate-pulse" style={{ animationDelay: "0.6s" }}>Evaluating redirect chain...</span>
            </div>
          </div>
        )}

        {/* --- RESULT State --- */}
        {state === "RESULT" && scanResult?.trust_report && (
          <div className="flex flex-col px-5 py-5 gap-4">
            {/* Freshness indicator */}
            {isCached && cacheStatus === "FRESH" && (
              <div className="flex items-center justify-center gap-1.5 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span className="text-[10px] font-semibold text-emerald-400 uppercase tracking-widest">
                  Verified Recently
                </span>
              </div>
            )}
            {isCached && cacheStatus === "STALE" && (
              <div className="flex items-center justify-center gap-1.5 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/20">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span className="text-[10px] font-semibold text-amber-400 uppercase tracking-widest">
                  Result May Be Outdated
                </span>
              </div>
            )}
            {!isCached && cacheStatus === "FRESH" && (
              <div className="flex items-center justify-center gap-1.5 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span className="text-[10px] font-semibold text-emerald-400 uppercase tracking-widest">
                  Just Verified
                </span>
              </div>
            )}

            {/* Risk Warning & Protection UX */}
            <RiskWarning report={scanResult.trust_report} isStale={cacheStatus === "STALE"} />

            {/* Trust Score */}
            <div className="flex justify-center">
              <TrustScore report={scanResult.trust_report} />
            </div>

            {/* AI Threat Analysis */}
            <AIThreatAnalysis aiThreat={scanResult.trust_report.ai_threat_analysis} />

            {/* Summary */}
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800/60">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Summary</span>
              <p className="mt-1 text-xs text-slate-300 leading-relaxed">{scanResult.trust_report.summary}</p>
            </div>

            {/* Security Details Context */}
            <SecurityDetails report={scanResult.trust_report} />

            {/* Explanation */}
            {scanResult.trust_report.explanation && (
              <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800/60">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Explanation</span>
                <p className="mt-1 text-xs text-slate-300 leading-relaxed">{scanResult.trust_report.explanation}</p>
              </div>
            )}

            {/* Positive Signals */}
            {scanResult.trust_report.positive_signals.length > 0 && (
              <div className="p-3 rounded-xl bg-slate-900/60 border border-emerald-500/20">
                <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-widest">Positive Signals</span>
                <ul className="mt-2 flex flex-col gap-1.5">
                  {scanResult.trust_report.positive_signals.map((signal, i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-slate-300">
                      <span className="text-emerald-400 mt-0.5 shrink-0">✓</span>
                      <span>{signal}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Key Risks */}
            {scanResult.trust_report.key_risks.length > 0 && (
              <div className="p-3 rounded-xl bg-slate-900/60 border border-red-500/20">
                <span className="text-[10px] font-bold text-red-400 uppercase tracking-widest">Key Risks</span>
                <ul className="mt-2 flex flex-col gap-1.5">
                  {scanResult.trust_report.key_risks.map((risk, i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-slate-300">
                      <span className="text-red-400 mt-0.5 shrink-0">⚠</span>
                      <span>{risk}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Recommendation */}
            {scanResult.trust_report.recommendation && (
              <div className="p-3 rounded-xl bg-blue-500/5 border border-blue-500/20">
                <span className="text-[10px] font-bold text-blue-400 uppercase tracking-widest">Recommendation</span>
                <p className="mt-1 text-xs text-slate-300 leading-relaxed">{scanResult.trust_report.recommendation}</p>
              </div>
            )}

            {/* Re-scan Button */}
            <button
              onClick={handleScan}
              className="w-full py-2.5 rounded-xl bg-slate-800/80 border border-slate-700/60 text-xs font-bold uppercase tracking-widest text-slate-400 hover:text-slate-200 hover:border-slate-600 transition-all duration-200"
            >
              Scan Again
            </button>
          </div>
        )}

        {/* --- ERROR State --- */}
        {state === "ERROR" && (
          <div className="flex-1 flex flex-col justify-center items-center px-6 py-8 text-center">
            <div className="w-14 h-14 rounded-2xl bg-red-500/10 border border-red-500/30 flex items-center justify-center mb-5">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-7 w-7 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <h2 className="text-lg font-black text-slate-100">Analysis Failed</h2>
            <p className="mt-2 text-xs text-slate-400 max-w-[260px]">{errorMessage}</p>
            <button
              onClick={handleScan}
              className="mt-6 w-full py-3 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 text-sm font-bold uppercase tracking-widest shadow-lg shadow-blue-500/25 hover:shadow-blue-500/40 hover:brightness-110 transition-all duration-200 active:scale-[0.98]"
            >
              Retry Scan
            </button>
          </div>
        )}

        {/* --- UNSUPPORTED State --- */}
        {state === "UNSUPPORTED" && (
          <div className="flex flex-col justify-center items-center px-6 py-6 text-center">
            <div className="w-14 h-14 rounded-2xl bg-slate-800/60 border border-slate-700/60 flex items-center justify-center mb-5">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-7 w-7 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
              </svg>
            </div>
            <h2 className="text-lg font-black text-slate-100">Page Not Supported</h2>
            <p className="mt-2 text-xs text-slate-400 max-w-[260px]">
              This page cannot be scanned by TRUSTINEL. Navigate to a regular website and try again.
            </p>
          </div>
        )}

        {/* ================================================================= */}
        {/* Recent Scans Section                                              */}
        {/* ================================================================= */}
        {state !== "SCANNING" && (
          <div className="px-5 pt-4 pb-5 border-t border-slate-800/50">
            {/* Section header */}
            <div className="flex items-center justify-between mb-3">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">
                Recent Scans
              </span>
              {history.length > 0 && !showClearConfirm && (
                <button
                  onClick={() => setShowClearConfirm(true)}
                  className="text-[10px] font-bold text-slate-600 uppercase tracking-widest hover:text-red-400 transition-colors"
                >
                  Clear
                </button>
              )}
            </div>

            {/* Clear confirmation */}
            {showClearConfirm && (
              <div className="mb-3 p-2.5 rounded-lg bg-red-500/8 border border-red-500/20 flex items-center justify-between">
                <span className="text-[11px] text-slate-300">Clear all history?</span>
                <div className="flex gap-2">
                  <button
                    onClick={handleClearHistory}
                    className="text-[10px] font-bold text-red-400 uppercase tracking-widest hover:text-red-300 transition-colors"
                  >
                    Yes
                  </button>
                  <button
                    onClick={() => setShowClearConfirm(false)}
                    className="text-[10px] font-bold text-slate-500 uppercase tracking-widest hover:text-slate-300 transition-colors"
                  >
                    No
                  </button>
                </div>
              </div>
            )}

            {/* History list */}
            {history.length === 0 ? (
              <div className="py-4 text-center">
                <p className="text-xs text-slate-600">No recent scans yet.</p>
              </div>
            ) : (
              <div className="flex flex-col gap-1.5">
                {history.map((entry) => (
                  <button
                    key={entry.domain}
                    onClick={() => handleHistoryClick(entry)}
                    className={`w-full flex items-center gap-3 p-2.5 rounded-xl border transition-all duration-150 text-left group ${
                      viewingHistoryDomain === entry.domain
                        ? "bg-blue-500/10 border-blue-500/30"
                        : "bg-slate-900/40 border-slate-800/50 hover:bg-slate-800/60 hover:border-slate-700/60"
                    }`}
                  >
                    {/* Score circle */}
                    <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
                      entry.riskLevel === "LOW" ? "bg-emerald-500/15" :
                      entry.riskLevel === "MEDIUM" ? "bg-amber-500/15" :
                      "bg-red-500/15"
                    }`}>
                      <span className={`text-sm font-black ${riskColors[entry.riskLevel].text}`}>
                        {entry.trustScore}
                      </span>
                    </div>

                    {/* Domain + summary */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-slate-200 truncate">
                          {entry.domain}
                        </span>
                        <span className={`shrink-0 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider border ${riskColors[entry.riskLevel].badge}`}>
                          {entry.riskLevel}
                        </span>
                      </div>
                      <p className="mt-0.5 text-[10px] text-slate-500 truncate">
                        {entry.summary}
                      </p>
                    </div>

                    {/* Timestamp */}
                    <span className="text-[9px] text-slate-600 shrink-0 group-hover:text-slate-500 transition-colors">
                      {timeAgo(entry.scannedAt)}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="px-5 py-3 border-t border-slate-800/80 bg-slate-900/40 backdrop-blur-md text-center z-10">
        <span className="text-[10px] font-medium text-slate-500 tracking-wider">
          v0.1.0 &copy; 2026 TRUSTINEL Corp
        </span>
      </footer>
    </div>
  );
}

export default App;
