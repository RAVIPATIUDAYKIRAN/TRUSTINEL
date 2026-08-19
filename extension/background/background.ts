// TRUSTINEL Background Service Worker
// Handles tab detection, scan orchestration, and result caching.

import { scanWebsite, ApiError } from "../lib/api";
import type { ScanResponse } from "../lib/api";
import {
  isUnsupportedUrl,
  normalizeDomain,
  cacheKey,
  type CachedScanResult,
  type DomainState,
  type PopupMessage,
  type ScanMessageResponse,
  type DomainStateResponse,
} from "../lib/types";

// ---------------------------------------------------------------------------
// In-memory scan-in-progress tracker (prevents duplicate requests)
// ---------------------------------------------------------------------------

const scanningDomains = new Set<string>();

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
// Domain state builder
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
  if (cached) {
    return { domain, url, state: "COMPLETED", cached };
  }

  return { domain, url, state: "IDLE" };
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

  try {
    const data = await scanWebsite(url);
    console.log("[TRUSTINEL] Scan completed. Score:", data.trust_report?.trust_score);

    // Cache the result if trust_report is present
    if (data.trust_report) {
      const cached = buildCachedResult(domain, url, data);
      await setCachedResult(domain, cached);
    }

    sendResponse({ success: true, data });
  } catch (err) {
    const errorMessage =
      err instanceof ApiError
        ? err.message
        : "An unexpected error occurred during the scan.";
    console.error("[TRUSTINEL] Scan failed:", errorMessage);
    sendResponse({ success: false, error: errorMessage });
  } finally {
    scanningDomains.delete(domain);
  }
}

// ---------------------------------------------------------------------------
// Message listener
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener(function (
  message: PopupMessage,
  _sender: chrome.runtime.MessageSender,
  sendResponse: (response: ScanMessageResponse | DomainStateResponse) => void
): boolean {
  if (message.type === "SCAN_CURRENT_TAB" && message.url) {
    console.log("[TRUSTINEL] Received SCAN_CURRENT_TAB:", message.url);
    performScan(message.url, sendResponse as (r: ScanMessageResponse) => void);
    return true; // keep channel open for async
  }

  if (message.type === "GET_DOMAIN_STATE" && message.url) {
    console.log("[TRUSTINEL] Received GET_DOMAIN_STATE:", message.url);
    getDomainState(message.url).then((state) => {
      sendResponse({ type: "DOMAIN_STATE", state });
    });
    return true; // keep channel open for async
  }

  return false;
});

// ---------------------------------------------------------------------------
// Tab navigation detection
// ---------------------------------------------------------------------------

chrome.tabs.onUpdated.addListener(
  (_tabId: number, changeInfo: chrome.tabs.TabChangeInfo, tab: chrome.tabs.Tab) => {
    // Only react to completed navigation with a URL
    if (changeInfo.status === "complete" && tab.url) {
      const domain = normalizeDomain(tab.url);
      if (domain && !isUnsupportedUrl(tab.url)) {
        console.log("[TRUSTINEL] Tab navigated:", domain);
      }
    }
  }
);

chrome.tabs.onActivated.addListener(async (activeInfo: chrome.tabs.TabActiveInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url) {
      const domain = normalizeDomain(tab.url);
      if (domain && !isUnsupportedUrl(tab.url)) {
        console.log("[TRUSTINEL] Tab activated:", domain);
      }
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
