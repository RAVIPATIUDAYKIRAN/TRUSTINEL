import { useState, useEffect, useCallback } from "react";
import { scanWebsite, ApiError } from "../../lib/api";
import type { ScanResponse } from "../../lib/api";
import {
  isUnsupportedUrl,
  extractHostname,
  normalizeDomain,
  type DomainState,
  type DomainStateResponse,
  type ScanMessageResponse,
} from "../../lib/types";
import TrustScore from "./components/TrustScore";

type AppState = "IDLE" | "SCANNING" | "RESULT" | "ERROR" | "UNSUPPORTED";

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
            // Fallback: return IDLE so the user can manually scan
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

  // Detect active tab URL and load cached state
  useEffect(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      const url = tabs[0]?.url || "";
      setTabUrl(url);
      setHostname(extractHostname(url));

      if (!url || isUnsupportedUrl(url)) {
        setState("UNSUPPORTED");
        return;
      }

      console.log("[TRUSTINEL] Popup opened for:", extractHostname(url));

      // Ask background for current domain state (includes cache lookup)
      const domainState = await requestDomainState(url);

      if (domainState.state === "COMPLETED" && domainState.cached) {
        console.log("[TRUSTINEL] Loaded cached result for:", domainState.domain);
        setScanResult(domainState.cached.scanResponse);
        setIsCached(true);
        setState("RESULT");
      } else if (domainState.state === "SCANNING") {
        setState("SCANNING");
      } else if (domainState.state === "UNSUPPORTED") {
        setState("UNSUPPORTED");
      } else {
        setState("IDLE");
      }
    });
  }, []);

  const handleScan = useCallback(() => {
    if (!tabUrl || isUnsupportedUrl(tabUrl)) return;

    setState("SCANNING");
    setScanResult(null);
    setErrorMessage("");
    setIsCached(false);

    console.log("[TRUSTINEL] Initiating scan for:", tabUrl);

    scanViaBackground(tabUrl)
      .then((data) => {
        console.log("[TRUSTINEL] Scan result received. Score:", data.trust_report?.trust_score);
        setScanResult(data);
        setState("RESULT");
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
  }, [tabUrl]);

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
        {hostname && state !== "UNSUPPORTED" && (
          <div className="px-5 py-3 border-b border-slate-800/50 bg-slate-900/30">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Current Website</span>
            <p className="mt-0.5 text-sm font-semibold text-slate-200 truncate">{hostname}</p>
          </div>
        )}

        {/* --- IDLE State --- */}
        {state === "IDLE" && (
          <div className="flex-1 flex flex-col justify-center items-center px-6 py-8 text-center">
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
            {/* Cached indicator */}
            {isCached && (
              <div className="flex items-center justify-center gap-1.5 py-1.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span className="text-[10px] font-semibold text-indigo-400 uppercase tracking-widest">
                  Previous Result
                </span>
              </div>
            )}

            {/* Trust Score */}
            <div className="flex justify-center">
              <TrustScore report={scanResult.trust_report} />
            </div>

            {/* Summary */}
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800/60">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Summary</span>
              <p className="mt-1 text-xs text-slate-300 leading-relaxed">{scanResult.trust_report.summary}</p>
            </div>

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
          <div className="flex-1 flex flex-col justify-center items-center px-6 py-8 text-center">
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
