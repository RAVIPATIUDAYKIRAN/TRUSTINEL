// TRUSTINEL Background Service Worker
// Handles tab detection, scan orchestration, result caching, scan history,
// badge indicator, automatic scanning, and cache freshness management.

import { scanWebsite, ApiError } from "../lib/api";
import type { ScanResponse } from "../lib/api";
import {
  isUnsupportedUrl,
  normalizeDomain,
  cacheKey,
  domainCacheKey,
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
 * Tracks domains/urls that have already been auto-scanned in this service worker
 * session to prevent repeated automatic scans on rapid navigation events.
 * Cleared only when the service worker restarts.
 */
const autoScannedDomains = new Set<string>();

// ---------------------------------------------------------------------------
// Cache helpers (Path-Aware with Domain Fallback)
// ---------------------------------------------------------------------------

async function getCachedResult(urlOrDomain: string): Promise<CachedScanResult | undefined> {
  try {
    const pKey = cacheKey(urlOrDomain);
    const dKey = domainCacheKey(urlOrDomain);
    const data = await chrome.storage.local.get([pKey, dKey]);
    
    const pathCached = data[pKey] as CachedScanResult | undefined;
    if (pathCached && typeof pathCached === "object" && pathCached.scanResponse && pathCached.riskLevel) {
      return pathCached;
    }

    const domainCached = data[dKey] as CachedScanResult | undefined;
    if (domainCached && typeof domainCached === "object" && domainCached.scanResponse && domainCached.riskLevel) {
      return domainCached;
    }

    return undefined;
  } catch {
    return undefined;
  }
}

async function setCachedResult(urlOrDomain: string, result: CachedScanResult): Promise<void> {
  try {
    const pKey = cacheKey(urlOrDomain);
    const dKey = domainCacheKey(urlOrDomain);
    await chrome.storage.local.set({ [pKey]: result, [dKey]: result });
    console.log("[TRUSTINEL] Path-aware cached result stored for:", urlOrDomain);
  } catch (err) {
    console.error("[TRUSTINEL] Error caching result:", err);
  }
}

function buildCachedResult(domain: string, url: string, scan: ScanResponse): CachedScanResult {
  const report = scan.trust_report!;
  const effectiveRiskLevel = (report.overall_risk_level || report.risk_level) as "LOW" | "MEDIUM" | "HIGH";
  return {
    scanId: scan.id,
    domain,
    url,
    trustScore: report.overall_risk_score ?? report.trust_score,
    riskLevel: effectiveRiskLevel,
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
      // Validate array elements
      return history.filter(
        (h) => h && typeof h === "object" && typeof h.domain === "string" && typeof h.trustScore === "number"
      ) as ScanHistoryEntry[];
    }
    return [];
  } catch {
    return [];
  }
}

async function addToHistory(entry: ScanHistoryEntry): Promise<void> {
  try {
    const history = await getScanHistory();
    const filtered = history.filter((h) => h.domain !== entry.domain);
    filtered.unshift(entry);
    const trimmed = filtered.slice(0, MAX_HISTORY);
    await chrome.storage.local.set({ [SCAN_HISTORY_KEY]: trimmed });
    console.log("[TRUSTINEL] History updated. Entries:", trimmed.length);
  } catch (err) {
    console.error("[TRUSTINEL] Error updating history:", err);
  }
}

async function clearHistory(): Promise<void> {
  try {
    await chrome.storage.local.remove(SCAN_HISTORY_KEY);
    console.log("[TRUSTINEL] Scan history cleared.");
  } catch (err) {
    console.error("[TRUSTINEL] Error clearing history:", err);
  }
}

function buildHistoryEntry(domain: string, scan: ScanResponse): ScanHistoryEntry {
  const report = scan.trust_report!;
  const effectiveRiskLevel = (report.overall_risk_level || report.risk_level) as "LOW" | "MEDIUM" | "HIGH";
  return {
    domain,
    scanId: scan.id,
    trustScore: report.overall_risk_score ?? report.trust_score,
    riskLevel: effectiveRiskLevel,
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
// Domain state builder (includes cacheStatus)
// ---------------------------------------------------------------------------

async function getDomainState(url: string): Promise<DomainState> {
  if (!url || isUnsupportedUrl(url)) {
    return { domain: "", url: url || "", state: "UNSUPPORTED" };
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

async function resolveActiveWebpageTab(targetUrl?: string): Promise<chrome.tabs.Tab | undefined> {
  const targetDomain = targetUrl ? normalizeDomain(targetUrl) : "";

  // 1. Try querying normal windows with lastFocusedWindow
  try {
    const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true, windowType: "normal" });
    for (const t of tabs) {
      if (t?.id && t?.url && !isUnsupportedUrl(t.url)) {
        if (!targetDomain || normalizeDomain(t.url) === targetDomain) {
          return t;
        }
      }
    }
  } catch {}

  // 2. Try querying non-focused normal windows (since popup window has focus when open)
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: false, windowType: "normal" });
    for (const t of tabs) {
      if (t?.id && t?.url && !isUnsupportedUrl(t.url)) {
        if (!targetDomain || normalizeDomain(t.url) === targetDomain) {
          return t;
        }
      }
    }
  } catch {}

  // 3. Fallback: query all active normal tabs
  try {
    const tabs = await chrome.tabs.query({ active: true, windowType: "normal" });
    for (const t of tabs) {
      if (t?.id && t?.url && !isUnsupportedUrl(t.url)) {
        if (!targetDomain || normalizeDomain(t.url) === targetDomain) {
          return t;
        }
      }
    }
  } catch {}

  return undefined;
}

async function getTabRenderedDom(tabId: number): Promise<string | undefined> {
  const attemptExtraction = async (): Promise<string | undefined> => {
    // A. Send message to content script with 2s timeout
    try {
      const res = await new Promise<{ success: boolean; html?: string }>((resolve) => {
        const timeout = setTimeout(() => resolve({ success: false }), 2000);
        chrome.tabs.sendMessage(tabId, { type: "GET_RENDERED_DOM" }, (response) => {
          clearTimeout(timeout);
          if (chrome.runtime.lastError || !response || !response.success) {
            resolve({ success: false });
            return;
          }
          resolve(response);
        });
      });
      if (res.success && res.html && res.html.trim().length > 100) {
        return res.html.slice(0, 500000);
      }
    } catch {}

    // B. Script injection fallback
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId },
        func: () => {
          if (!document.documentElement) return "";
          const clone = document.documentElement.cloneNode(true) as HTMLElement;
          const inputs = clone.querySelectorAll("input, textarea, select");
          inputs.forEach((el) => {
            const input = el as HTMLInputElement;
            const nameAttr = (input.name || "").toLowerCase();
            const typeAttr = (input.type || "").toLowerCase();
            if (typeAttr === "password" || nameAttr.includes("token") || nameAttr.includes("secret") || nameAttr.includes("cvv") || nameAttr.includes("card")) {
              input.value = "";
              input.removeAttribute("value");
            } else if (input.value) {
              input.value = "[REDACTED]";
            }
          });
          return clone.outerHTML ? clone.outerHTML.slice(0, 500000) : "";
        },
      });
      if (results && results[0] && typeof results[0].result === "string" && results[0].result.trim().length > 100) {
        return results[0].result;
      }
    } catch {}

    return undefined;
  };

  let html = await attemptExtraction();
  if (!html || html.length < 2000) {
    // Bounded settlement wait (500ms max) allowing dynamic SPA JS components to render
    await new Promise((resolve) => setTimeout(resolve, 500));
    const secondHtml = await attemptExtraction();
    if (secondHtml && secondHtml.length > (html?.length || 0)) {
      html = secondHtml;
    }
  }

  if (html) {
    console.log(`[TRUSTINEL-DIAGNOSTIC] DOM_CAPTURE_SUCCESS tab_id=${tabId} page_html_present=true page_html_length=${html.length}`);
  } else {
    console.warn(`[TRUSTINEL-DIAGNOSTIC] DOM_CAPTURE_FAILED tab_id=${tabId} page_html_present=false reason="content_script_and_injection_unavailable"`);
  }
  return html;
}

async function performScan(
  url: string,
  sendResponse: (response: ScanMessageResponse) => void,
  providedPageHtml?: string
): Promise<void> {
  const domain = normalizeDomain(url);

  if (scanningDomains.has(domain)) {
    console.log("[TRUSTINEL] Scan already in progress for:", domain);
    try {
      sendResponse({ success: false, error: "A scan is already in progress for this domain." });
    } catch {
      // Channel closed
    }
    return;
  }

  scanningDomains.add(domain);
  console.log("[TRUSTINEL-DIAGNOSTIC] SCAN_INITIATED domain=", domain, "url=", url);

  // Update badge to scanning state on resolved webpage tab
  const activeTab = await resolveActiveWebpageTab(url);
  const activeTabId = activeTab?.id;
  console.log(`[TRUSTINEL-DIAGNOSTIC] TAB_RESOLVED activeTabId=${activeTabId ?? "NONE"} target_domain=${domain}`);

  if (activeTabId) {
    await updateBadge(activeTabId, "SCANNING");
  }

  try {
    const pageHtml = providedPageHtml || (activeTabId ? await getTabRenderedDom(activeTabId) : undefined);
    console.log(`[TRUSTINEL-DIAGNOSTIC] API_REQUEST_PREPARED page_html_present=${Boolean(pageHtml)} page_html_length=${pageHtml?.length || 0}`);
    const data = await scanWebsite(url, pageHtml);
    const contentSource = data.trust_report?.content_source || "unknown";
    console.log(`[TRUSTINEL-DIAGNOSTIC] SCAN_COMPLETED score=${data.trust_report?.trust_score} content_source=${contentSource}`);

    if (data.trust_report) {
      const cached = buildCachedResult(domain, url, data);
      await setCachedResult(url, cached);

      const historyEntry = buildHistoryEntry(domain, data);
      await addToHistory(historyEntry);

      if (activeTabId) {
        const effectiveLevel = (data.trust_report.overall_risk_level || data.trust_report.risk_level) as "LOW" | "MEDIUM" | "HIGH";
        await updateBadge(activeTabId, effectiveLevel);
      }
    }

    try {
      sendResponse({ success: true, data });
    } catch {
      // Channel closed
    }
  } catch (err) {
    const errorMessage =
      err instanceof ApiError
        ? err.message
        : "An unexpected error occurred during the scan.";
    console.error("[TRUSTINEL] Scan failed:", errorMessage);
    try {
      sendResponse({ success: false, error: errorMessage });
    } catch {
      // Channel closed
    }

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
    const pageHtml = await getTabRenderedDom(tabId);
    const data = await scanWebsite(url, pageHtml);
    console.log("[TRUSTINEL] Automatic scan completed. Score:", data.trust_report?.trust_score);

    if (data.trust_report) {
      const cached = buildCachedResult(domain, url, data);
      await setCachedResult(url, cached);

      const historyEntry = buildHistoryEntry(domain, data);
      await addToHistory(historyEntry);

      const effectiveLevel = (data.trust_report.overall_risk_level || data.trust_report.risk_level) as "LOW" | "MEDIUM" | "HIGH";
      await updateBadge(tabId, effectiveLevel);

      // D3 fix: Send scan result to content script so the in-page Shadow DOM
      // floating indicator stays synchronized with the background badge.
      try {
        chrome.tabs.sendMessage(tabId, {
          type: "UPDATE_FLOATING_INDICATOR",
          data: data.trust_report
        });
      } catch {
        // Content script may not be available (e.g. tab closed)
      }
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
  if (!message || typeof message !== "object" || !message.type) {
    return false;
  }

  if (message.type === "SCAN_CURRENT_TAB" && message.url) {
    console.log("[TRUSTINEL] Received SCAN_CURRENT_TAB:", message.url);
    const domain = normalizeDomain(message.url);
    if (domain) autoScannedDomains.add(domain);
    performScan(message.url, sendResponse as (r: ScanMessageResponse) => void);
    return true;
  }

  if (message.type === "SCAN_CURRENT_TAB_AUTO" && message.url) {
    console.log("[TRUSTINEL] Received SCAN_CURRENT_TAB_AUTO:", message.url);
    const domain = normalizeDomain(message.url);
    if (domain) autoScannedDomains.add(domain);
    performScan(message.url, sendResponse as (r: ScanMessageResponse) => void, message.page_html);
    return true;
  }

  if (message.type === "OPEN_SIDE_PANEL") {
    console.log("[TRUSTINEL] Received OPEN_SIDE_PANEL request.");
    if (chrome.sidePanel && typeof chrome.sidePanel.open === "function") {
      if (_sender.tab?.id) {
        chrome.sidePanel.open({ tabId: _sender.tab.id }).catch((err) => console.error("Side panel open error:", err));
      }
    }
    return false;
  }

  if (message.type === "GET_DOMAIN_STATE" && message.url) {
    console.log("[TRUSTINEL] Received GET_DOMAIN_STATE:", message.url);
    getDomainState(message.url)
      .then((state) => {
        try {
          sendResponse({ type: "DOMAIN_STATE", state });
        } catch {
          // Channel closed
        }
      })
      .catch(() => {
        try {
          sendResponse({ type: "DOMAIN_STATE", state: { domain: "", url: message.url, state: "IDLE" } });
        } catch {
          // Channel closed
        }
      });
    return true;
  }

  if (message.type === "GET_SCAN_HISTORY") {
    console.log("[TRUSTINEL] Received GET_SCAN_HISTORY");
    getScanHistory()
      .then((history) => {
        try {
          sendResponse({ type: "SCAN_HISTORY", history });
        } catch {
          // Channel closed
        }
      })
      .catch(() => {
        try {
          sendResponse({ type: "SCAN_HISTORY", history: [] });
        } catch {
          // Channel closed
        }
      });
    return true;
  }

  if (message.type === "CLEAR_SCAN_HISTORY") {
    console.log("[TRUSTINEL] Received CLEAR_SCAN_HISTORY");
    clearHistory()
      .then(() => {
        try {
          sendResponse({ type: "HISTORY_CLEARED", success: true });
        } catch {
          // Channel closed
        }
      })
      .catch(() => {
        try {
          sendResponse({ type: "HISTORY_CLEARED", success: false });
        } catch {
          // Channel closed
        }
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

// Re-initialize active tab badge on worker startup/wake
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (tabs[0]?.id && tabs[0]?.url) {
    updateBadgeForTab(tabs[0].id, tabs[0].url);
  }
});

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

chrome.runtime.onInstalled.addListener((details) => {
  console.log("[TRUSTINEL] Extension installed.", details.reason);
});

console.log("[TRUSTINEL] Background Service Worker active.");
