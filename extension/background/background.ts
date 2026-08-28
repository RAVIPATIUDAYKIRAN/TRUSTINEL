// TRUSTINEL Background Service Worker
// Handles tab detection, scan orchestration, result caching, scan history,
// badge indicator, automatic scanning, and cache freshness management.

import { scanWebsite, ApiError } from "../lib/api";
import type { ScanResponse } from "../lib/api";
import {
  isUnsupportedUrl,
  normalizeDomain,
  cacheKey,
  getCacheStatus,
  SCAN_HISTORY_KEY,
  MAX_HISTORY,
  type CachedScanResult,
  type CacheStatus,
  type ScanHistoryEntry,
  type DomainState,
  type PopupMessage,
  type ScanMessageResponse,
  type DomainStateResponse,
  type ScanHistoryResponse,
  type ClearHistoryResponse,
} from "../lib/types";

// ---------------------------------------------------------------------------
// In-memory scan-in-progress tracker (prevents duplicate requests)
// ---------------------------------------------------------------------------

const scanningDomains = new Set<string>();

/**
 * Tracks domains that have already been auto-scanned in this service worker
 * session to prevent repeated automatic scans on rapid navigation events.
 * Cleared only when the service worker restarts.
 */
const autoScannedDomains = new Set<string>();

// ---------------------------------------------------------------------------
// Cache helpers
// ---------------------------------------------------------------------------

async function getCachedResult(domain: string): Promise<CachedScanResult | undefined> {
  const key = cacheKey(domain);
  const data = await chrome.storage.local.get(key);
  return data[key] as CachedScanResult | undefined;
}

async function setCachedResult(domain: string, result: CachedScanResult): Promise<void> {
  const key = cacheKey(domain);
  await chrome.storage.local.set({ [key]: result });
  console.log("[TRUSTINEL] Cached result for:", domain);
}

function buildCachedResult(domain: string, url: string, scan: ScanResponse): CachedScanResult {
  const report = scan.trust_report!;
  return {
    scanId: scan.id,
    domain,
    url,
    trustScore: report.trust_score,
    riskLevel: report.risk_level,
    summary: report.summary,
    explanation: report.explanation,
    keyRisks: report.key_risks,
    positiveSignals: report.positive_signals,
    recommendation: report.recommendation,
    scannedAt: new Date().toISOString(),
    scanResponse: scan,
  };
}

// ---------------------------------------------------------------------------
// Scan history helpers
// ---------------------------------------------------------------------------

async function getScanHistory(): Promise<ScanHistoryEntry[]> {
  try {
    const data = await chrome.storage.local.get(SCAN_HISTORY_KEY);
    const history = data[SCAN_HISTORY_KEY];
    if (Array.isArray(history)) {
      return history as ScanHistoryEntry[];
    }
    return [];
  } catch {
    return [];
  }
}

async function addToHistory(entry: ScanHistoryEntry): Promise<void> {
  const history = await getScanHistory();
  const filtered = history.filter((h) => h.domain !== entry.domain);
  filtered.unshift(entry);
  const trimmed = filtered.slice(0, MAX_HISTORY);
  await chrome.storage.local.set({ [SCAN_HISTORY_KEY]: trimmed });
  console.log("[TRUSTINEL] History updated. Entries:", trimmed.length);
}

async function clearHistory(): Promise<void> {
  await chrome.storage.local.remove(SCAN_HISTORY_KEY);
  console.log("[TRUSTINEL] Scan history cleared.");
}

function buildHistoryEntry(domain: string, scan: ScanResponse): ScanHistoryEntry {
  const report = scan.trust_report!;
  return {
    domain,
    scanId: scan.id,
    trustScore: report.trust_score,
    riskLevel: report.risk_level,
    summary: report.summary,
    scannedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Badge indicator
// ---------------------------------------------------------------------------

const BADGE_CONFIG = {
  LOW:         { text: "\u2713", color: "#22c55e", title: "TRUSTINEL \u2014 Low Risk" },
  MEDIUM:      { text: "!",  color: "#f59e0b", title: "TRUSTINEL \u2014 Medium Risk" },
  HIGH:        { text: "!",  color: "#ef4444", title: "TRUSTINEL \u2014 High Risk" },
  UNKNOWN:     { text: "",   color: "#64748b", title: "TRUSTINEL \u2014 Not Scanned" },
  UNSUPPORTED: { text: "",   color: "#64748b", title: "TRUSTINEL \u2014 Page Not Scannable" },
  SCANNING:    { text: "\u2026",  color: "#6366f1", title: "TRUSTINEL \u2014 Scanning..." },
} as const;

type BadgeState = keyof typeof BADGE_CONFIG;

async function updateBadge(tabId: number, badgeState: BadgeState): Promise<void> {
  const config = BADGE_CONFIG[badgeState];
  try {
    await Promise.all([
      chrome.action.setBadgeText({ text: config.text, tabId }),
      chrome.action.setBadgeBackgroundColor({ color: config.color, tabId }),
      chrome.action.setTitle({ title: config.title, tabId }),
    ]);
    console.log("[TRUSTINEL] Badge updated:", badgeState, "tab:", tabId);
  } catch {
    // Tab may have been closed
  }
}

async function updateBadgeForTab(tabId: number, url: string): Promise<void> {
  if (!url || isUnsupportedUrl(url)) {
    await updateBadge(tabId, "UNSUPPORTED");
    return;
  }

  const domain = normalizeDomain(url);
  if (!domain) {
    await updateBadge(tabId, "UNSUPPORTED");
    return;
  }

  if (scanningDomains.has(domain)) {
    await updateBadge(tabId, "SCANNING");
    return;
  }

  const cached = await getCachedResult(domain);
  if (cached?.riskLevel) {
    await updateBadge(tabId, cached.riskLevel);
  } else {
    await updateBadge(tabId, "UNKNOWN");
  }
}

// ---------------------------------------------------------------------------
// Domain state builder (now includes cacheStatus)
// ---------------------------------------------------------------------------

async function getDomainState(url: string): Promise<DomainState> {
  if (!url || isUnsupportedUrl(url)) {
    return { domain: "", url, state: "UNSUPPORTED" };
  }

  const domain = normalizeDomain(url);
  if (!domain) {
    return { domain: "", url, state: "UNSUPPORTED" };
  }

  if (scanningDomains.has(domain)) {
    return { domain, url, state: "SCANNING" };
  }

  const cached = await getCachedResult(domain);
  const status: CacheStatus = getCacheStatus(cached);

  if (cached && (status === "FRESH" || status === "STALE")) {
    return { domain, url, state: "COMPLETED", cached, cacheStatus: status };
  }

  return { domain, url, state: "IDLE", cacheStatus: "MISSING" };
}

// ---------------------------------------------------------------------------
// Scan orchestration
// ---------------------------------------------------------------------------

async function performScan(
  url: string,
  sendResponse: (response: ScanMessageResponse) => void
): Promise<void> {
  const domain = normalizeDomain(url);

  if (scanningDomains.has(domain)) {
    console.log("[TRUSTINEL] Scan already in progress for:", domain);
    sendResponse({ success: false, error: "A scan is already in progress for this domain." });
    return;
  }

  scanningDomains.add(domain);
  console.log("[TRUSTINEL] Starting scan for:", domain, "URL:", url);

  // Update badge to scanning state on the active tab
  const activeTabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const activeTabId = activeTabs[0]?.id;
  if (activeTabId) {
    await updateBadge(activeTabId, "SCANNING");
  }

  try {
    const data = await scanWebsite(url);
    console.log("[TRUSTINEL] Scan completed. Score:", data.trust_report?.trust_score);

    if (data.trust_report) {
      const cached = buildCachedResult(domain, url, data);
      await setCachedResult(domain, cached);

      const historyEntry = buildHistoryEntry(domain, data);
      await addToHistory(historyEntry);

      if (activeTabId) {
        await updateBadge(activeTabId, data.trust_report.risk_level);
      }
    }

    sendResponse({ success: true, data });
  } catch (err) {
    const errorMessage =
      err instanceof ApiError
        ? err.message
        : "An unexpected error occurred during the scan.";
    console.error("[TRUSTINEL] Scan failed:", errorMessage);
    sendResponse({ success: false, error: errorMessage });

    // On failure, restore badge from cache or reset to unknown
    if (activeTabId) {
      const existing = await getCachedResult(domain);
      if (existing?.riskLevel) {
        await updateBadge(activeTabId, existing.riskLevel);
      } else {
        await updateBadge(activeTabId, "UNKNOWN");
      }
    }
  } finally {
    scanningDomains.delete(domain);
  }
}

/**
 * Automatic scan: fire-and-forget background scan triggered by navigation.
 * Does not use sendResponse (no popup is waiting).
 */
async function performAutoScan(url: string, tabId: number): Promise<void> {
  const domain = normalizeDomain(url);

  if (scanningDomains.has(domain)) {
    console.log("[TRUSTINEL] Automatic scan skipped (already in progress):", domain);
    return;
  }

  scanningDomains.add(domain);
  autoScannedDomains.add(domain);
  console.log("[TRUSTINEL] Automatic scan started:", domain);
  await updateBadge(tabId, "SCANNING");

  try {
    const data = await scanWebsite(url);
    console.log("[TRUSTINEL] Automatic scan completed. Score:", data.trust_report?.trust_score);

    if (data.trust_report) {
      const cached = buildCachedResult(domain, url, data);
      await setCachedResult(domain, cached);

      const historyEntry = buildHistoryEntry(domain, data);
      await addToHistory(historyEntry);

      await updateBadge(tabId, data.trust_report.risk_level);
    }
  } catch (err) {
    const msg = err instanceof ApiError ? err.message : String(err);
    console.error("[TRUSTINEL] Automatic scan failed:", msg);

    // Preserve previous cached badge, or reset to unknown
    const existing = await getCachedResult(domain);
    if (existing?.riskLevel) {
      await updateBadge(tabId, existing.riskLevel);
    } else {
      await updateBadge(tabId, "UNKNOWN");
    }
  } finally {
    scanningDomains.delete(domain);
  }
}

// ---------------------------------------------------------------------------
// Automatic scan decision logic
// ---------------------------------------------------------------------------

async function handleTabNavigation(tabId: number, url: string): Promise<void> {
  // Always update badge first
  await updateBadgeForTab(tabId, url);

  if (!url || isUnsupportedUrl(url)) return;

  const domain = normalizeDomain(url);
  if (!domain) return;

  // Already scanning this domain — skip
  if (scanningDomains.has(domain)) {
    console.log("[TRUSTINEL] Automatic scan skipped (in progress):", domain);
    return;
  }

  const cached = await getCachedResult(domain);
  const status = getCacheStatus(cached);

  if (status === "FRESH") {
    console.log("[TRUSTINEL] Cache fresh for:", domain);
    return;
  }

  if (status === "STALE") {
    // Only auto-refresh stale once per service worker session
    if (autoScannedDomains.has(domain)) {
      console.log("[TRUSTINEL] Automatic scan skipped (already auto-refreshed this session):", domain);
      return;
    }
    console.log("[TRUSTINEL] Cache stale for:", domain, "— triggering refresh");
    performAutoScan(url, tabId);
    return;
  }

  // MISSING — never scanned
  if (autoScannedDomains.has(domain)) {
    console.log("[TRUSTINEL] Automatic scan skipped (already attempted this session):", domain);
    return;
  }
  console.log("[TRUSTINEL] No cache for:", domain, "— triggering automatic scan");
  performAutoScan(url, tabId);
}

// ---------------------------------------------------------------------------
// Message listener
// ---------------------------------------------------------------------------

type AnyResponse = ScanMessageResponse | DomainStateResponse | ScanHistoryResponse | ClearHistoryResponse;

chrome.runtime.onMessage.addListener(function (
  message: PopupMessage,
  _sender: chrome.runtime.MessageSender,
  sendResponse: (response: AnyResponse) => void
): boolean {
  if (message.type === "SCAN_CURRENT_TAB" && message.url) {
    console.log("[TRUSTINEL] Received SCAN_CURRENT_TAB:", message.url);
    // Manual scan: mark as auto-scanned to prevent duplicate auto-scan after
    const domain = normalizeDomain(message.url);
    if (domain) autoScannedDomains.add(domain);
    performScan(message.url, sendResponse as (r: ScanMessageResponse) => void);
    return true;
  }

  if (message.type === "GET_DOMAIN_STATE" && message.url) {
    console.log("[TRUSTINEL] Received GET_DOMAIN_STATE:", message.url);
    getDomainState(message.url).then((state) => {
      sendResponse({ type: "DOMAIN_STATE", state });
    });
    return true;
  }

  if (message.type === "GET_SCAN_HISTORY") {
    console.log("[TRUSTINEL] Received GET_SCAN_HISTORY");
    getScanHistory().then((history) => {
      sendResponse({ type: "SCAN_HISTORY", history });
    });
    return true;
  }

  if (message.type === "CLEAR_SCAN_HISTORY") {
    console.log("[TRUSTINEL] Received CLEAR_SCAN_HISTORY");
    clearHistory().then(() => {
      sendResponse({ type: "HISTORY_CLEARED", success: true });
    });
    return true;
  }

  return false;
});

// ---------------------------------------------------------------------------
// Tab navigation detection → automatic scan
// ---------------------------------------------------------------------------

chrome.tabs.onUpdated.addListener(
  (tabId: number, changeInfo: chrome.tabs.TabChangeInfo, tab: chrome.tabs.Tab) => {
    if (changeInfo.status === "complete" && tab.url && tab.active) {
      console.log("[TRUSTINEL] Tab navigated:", normalizeDomain(tab.url) || tab.url);
      handleTabNavigation(tabId, tab.url);
    }
  }
);

chrome.tabs.onActivated.addListener(async (activeInfo: chrome.tabs.TabActiveInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url) {
      console.log("[TRUSTINEL] Tab activated:", normalizeDomain(tab.url) || tab.url);
      handleTabNavigation(activeInfo.tabId, tab.url);
    }
  } catch {
    // Tab may have been closed between activation and get
  }
});

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

chrome.runtime.onInstalled.addListener((details) => {
  console.log("[TRUSTINEL] Extension installed.", details.reason);
});

console.log("[TRUSTINEL] Background Service Worker active.");
