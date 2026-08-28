import { useState } from "react";
import type { TrustReport } from "../../../lib/api";

interface SecurityDetailsProps {
  report: TrustReport;
}

const ALL_SECURITY_HEADERS = [
  "Strict-Transport-Security",
  "Content-Security-Policy",
  "X-Frame-Options",
  "X-Content-Type-Options",
  "Referrer-Policy",
  "Permissions-Policy",
] as const;

export default function SecurityDetails({ report }: SecurityDetailsProps) {
  const [isExpanded, setIsExpanded] = useState(true);

  const allSignals = [...(report.positive_signals || []), ...(report.key_risks || [])];

  // 1. SSL Analysis
  let sslStatus: "Valid" | "Invalid" | "Could not establish validity" | "Unknown" = "Unknown";
  let sslBadge = "bg-slate-800/60 border-slate-700/60 text-slate-400";

  if (allSignals.some((s) => s.toLowerCase().includes("ssl certificate is valid"))) {
    sslStatus = "Valid";
    sslBadge = "bg-emerald-500/15 border-emerald-500/30 text-emerald-400";
  } else if (allSignals.some((s) => s.toLowerCase().includes("ssl certificate is invalid"))) {
    sslStatus = "Invalid";
    sslBadge = "bg-red-500/15 border-red-500/30 text-red-400";
  } else if (
    allSignals.some(
      (s) =>
        s.toLowerCase().includes("ssl analysis returned an error") ||
        s.toLowerCase().includes("validity could not be established")
    )
  ) {
    sslStatus = "Could not establish validity";
    sslBadge = "bg-amber-500/15 border-amber-500/30 text-amber-400";
  }

  // 2. Domain / WHOIS Analysis
  let domainStatus = "Registered";
  let domainAge: string | null = null;
  let domainBadge = "bg-emerald-500/15 border-emerald-500/30 text-emerald-400";

  if (allSignals.some((s) => s.toLowerCase().includes("older than one year"))) {
    domainAge = "1+ years";
  } else if (allSignals.some((s) => s.toLowerCase().includes("less than one year old"))) {
    domainAge = "< 1 year";
  }

  if (allSignals.some((s) => s.toLowerCase().includes("domain is not registered"))) {
    domainStatus = "Not Registered";
    domainBadge = "bg-red-500/15 border-red-500/30 text-red-400";
  } else if (allSignals.some((s) => s.toLowerCase().includes("whois analysis failed"))) {
    domainStatus = "Unknown";
    domainBadge = "bg-amber-500/15 border-amber-500/30 text-amber-400";
  }

  // 3. Security Headers Analysis
  const missingHeaders = ALL_SECURITY_HEADERS.filter((header) =>
    allSignals.some((s) => s.toLowerCase().includes(`${header.toLowerCase()} header is missing`))
  );
  const presentCount = ALL_SECURITY_HEADERS.length - missingHeaders.length;
  let headerBadge = "bg-emerald-500/15 border-emerald-500/30 text-emerald-400";
  if (presentCount < 3) {
    headerBadge = "bg-red-500/15 border-red-500/30 text-red-400";
  } else if (presentCount < 5) {
    headerBadge = "bg-amber-500/15 border-amber-500/30 text-amber-400";
  }

  // 4. Redirects Analysis
  let redirectStatus = "Safe";
  let redirectBadge = "bg-emerald-500/15 border-emerald-500/30 text-emerald-400";
  if (allSignals.some((s) => s.toLowerCase().includes("redirect chain is considered unsafe"))) {
    redirectStatus = "Unsafe";
    redirectBadge = "bg-red-500/15 border-red-500/30 text-red-400";
  }

  const hasCrossDomain = allSignals.some((s) =>
    s.toLowerCase().includes("cross-domain redirect detected")
  );
  const hasHttpsUpgrade = allSignals.some((s) =>
    s.toLowerCase().includes("http to https upgrade detected")
  );

  return (
    <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80 shadow-md flex flex-col gap-3">
      {/* Section Header */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="flex items-center justify-between w-full text-left focus:outline-none group"
      >
        <div className="flex items-center gap-2">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            className="h-4 w-4 text-blue-400"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
            />
          </svg>
          <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest group-hover:text-slate-200 transition-colors">
            Security Details
          </span>
        </div>
        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest group-hover:text-slate-400 transition-colors">
          {isExpanded ? "Collapse ▲" : "Expand ▼"}
        </span>
      </button>

      {/* Grid Content */}
      {isExpanded && (
        <div className="grid grid-cols-1 gap-2.5 pt-1 border-t border-slate-800/60">
          {/* SSL Certificate Card */}
          <div className="p-2.5 rounded-lg bg-slate-950/40 border border-slate-800/50 flex flex-col gap-1">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <span>🔒</span> SSL Certificate
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${sslBadge}`}>
                {sslStatus}
              </span>
            </div>
          </div>

          {/* Domain / WHOIS Card */}
          <div className="p-2.5 rounded-lg bg-slate-950/40 border border-slate-800/50 flex flex-col gap-1">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <span>🌐</span> Domain Registration
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${domainBadge}`}>
                {domainStatus}
              </span>
            </div>
            {domainAge && (
              <div className="flex items-center justify-between text-[11px] text-slate-400 mt-1 pl-5">
                <span>Domain Age</span>
                <span className="font-semibold text-slate-200">{domainAge}</span>
              </div>
            )}
          </div>

          {/* Security Headers Card */}
          <div className="p-2.5 rounded-lg bg-slate-950/40 border border-slate-800/50 flex flex-col gap-1.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <span>🛡</span> Security Headers
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${headerBadge}`}>
                {presentCount} / {ALL_SECURITY_HEADERS.length} Present
              </span>
            </div>
            {missingHeaders.length > 0 && (
              <div className="mt-1 pl-5">
                <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                  Missing Headers:
                </span>
                <ul className="flex flex-wrap gap-1">
                  {missingHeaders.map((header) => (
                    <li
                      key={header}
                      className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-300 break-all"
                    >
                      {header}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Redirects Card */}
          <div className="p-2.5 rounded-lg bg-slate-950/40 border border-slate-800/50 flex flex-col gap-1.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <span>↪</span> Redirect Chain
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${redirectBadge}`}>
                {redirectStatus}
              </span>
            </div>
            <div className="grid grid-cols-2 gap-2 mt-1 pl-5 text-[11px] text-slate-400">
              <div className="flex items-center justify-between">
                <span>Cross-Domain:</span>
                <span className={hasCrossDomain ? "text-amber-400 font-semibold" : "text-slate-300"}>
                  {hasCrossDomain ? "Yes" : "No"}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>HTTPS Upgrade:</span>
                <span className={hasHttpsUpgrade ? "text-emerald-400 font-semibold" : "text-slate-300"}>
                  {hasHttpsUpgrade ? "Yes" : "No"}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
