// TRUSTINEL Shared Types
// Message contract between background service worker and popup

import type { ScanResponse, TrustReport } from "./api";

// ---------------------------------------------------------------------------
// Scan State
// ---------------------------------------------------------------------------

export type ScanState = "IDLE" | "SCANNING" | "COMPLETED" | "ERROR" | "UNSUPPORTED";

/** Cached scan result stored per-domain in chrome.storage.local */
export interface CachedScanResult {
  scanId: string;
  domain: string;
  url: string;
  trustScore: number;
  riskLevel: TrustReport["risk_level"];
  summary: string;
  explanation: string | null;
  keyRisks: string[];
  positiveSignals: string[];
  recommendation: string | null;
  scannedAt: string;
  /** Full API response for re-hydration */
  scanResponse: ScanResponse;
}

/** Domain state visible to the popup */
export interface DomainState {
  domain: string;
  url: string;
  state: ScanState;
  error?: string;
  cached?: CachedScanResult;
}

// ---------------------------------------------------------------------------
// Messages: Popup → Background
// ---------------------------------------------------------------------------

export interface ScanCurrentTabMessage {
  type: "SCAN_CURRENT_TAB";
  url: string;
}

export interface GetDomainStateMessage {
  type: "GET_DOMAIN_STATE";
  url: string;
}

export type PopupMessage = ScanCurrentTabMessage | GetDomainStateMessage;

// ---------------------------------------------------------------------------
// Messages: Background → Popup (responses)
// ---------------------------------------------------------------------------

export interface ScanSuccessResponse {
  success: true;
  data: ScanResponse;
}

export interface ScanErrorResponse {
  success: false;
  error: string;
}

export type ScanMessageResponse = ScanSuccessResponse | ScanErrorResponse;

export interface DomainStateResponse {
  type: "DOMAIN_STATE";
  state: DomainState;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const UNSUPPORTED_PREFIXES = [
  "chrome://",
  "chrome-extension://",
  "edge://",
  "about:",
  "brave://",
  "opera://",
  "vivaldi://",
  "file://",
  "devtools://",
];

export function isUnsupportedUrl(url: string): boolean {
  if (!url) return true;
  return UNSUPPORTED_PREFIXES.some((prefix) => url.startsWith(prefix));
}

export function extractHostname(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

/** Normalize hostname → domain key for caching (strips www.) */
export function normalizeDomain(url: string): string {
  const hostname = extractHostname(url);
  return hostname.replace(/^www\./, "");
}

/** Storage key prefix for cached scan results */
export const CACHE_KEY_PREFIX = "trustinel_cache_";

export function cacheKey(domain: string): string {
  return `${CACHE_KEY_PREFIX}${domain}`;
}
