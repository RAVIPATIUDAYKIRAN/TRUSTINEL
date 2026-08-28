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

/** Lightweight history entry (no full scanResponse to keep storage small) */
export interface ScanHistoryEntry {
  domain: string;
  scanId: string;
  trustScore: number;
  riskLevel: TrustReport["risk_level"];
  summary: string;
  scannedAt: string;
}

/** Domain state visible to the popup */
export interface DomainState {
  domain: string;
  url: string;
  state: ScanState;
  error?: string;
  cached?: CachedScanResult;
  cacheStatus?: CacheStatus;
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

export interface GetScanHistoryMessage {
  type: "GET_SCAN_HISTORY";
}

export interface ClearScanHistoryMessage {
  type: "CLEAR_SCAN_HISTORY";
}

export type PopupMessage =
  | ScanCurrentTabMessage
  | GetDomainStateMessage
  | GetScanHistoryMessage
  | ClearScanHistoryMessage;

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

export interface ScanHistoryResponse {
  type: "SCAN_HISTORY";
  history: ScanHistoryEntry[];
}

export interface ClearHistoryResponse {
  type: "HISTORY_CLEARED";
  success: boolean;
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
  if (!url) return "";
  try {
    return new URL(url).hostname;
  } catch {
    try {
      return new URL(`http://${url}`).hostname;
    } catch {
      return "";
    }
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

/** Storage key for recent scan history */
export const SCAN_HISTORY_KEY = "trustinel_scan_history";

/** Maximum number of history entries to keep */
export const MAX_HISTORY = 10;

/** Cache TTL: 10 minutes */
export const SCAN_CACHE_TTL_MS = 10 * 60 * 1000;

/** Cache freshness status */
export type CacheStatus = "FRESH" | "STALE" | "MISSING";

/** Determine whether a cached result is still fresh */
export function getCacheStatus(cached: CachedScanResult | undefined | null): CacheStatus {
  if (!cached?.scannedAt) return "MISSING";
  const timestamp = new Date(cached.scannedAt).getTime();
  if (isNaN(timestamp)) return "MISSING";
  const age = Date.now() - timestamp;
  if (age < 0) return "FRESH";
  return age < SCAN_CACHE_TTL_MS ? "FRESH" : "STALE";
}
