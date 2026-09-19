// TRUSTINEL Content Script
// 1. Safely extracts bounded rendered DOM from active tab with sensitive input redaction.
// 2. Injects an isolated Shadow DOM Floating Lightning Indicator (⚡ TRUSTINEL).
// 3. Implements automatic page protection & SPA navigation detection.

const MAX_DOM_BYTES = 500_000; // 500 KB MAX
const AUTO_SCAN_COOLDOWN_MS = 2000;

let lastAutoScanTime = 0;
let lastAutoScanUrl = "";
let protectionEnabled = true;
let disabledSites: string[] = [];

// D1 fix: Monotonic scan generation counter prevents stale responses
// from overwriting newer scan results after navigation.
let scanGeneration = 0;

// ---------------------------------------------------------------------------
// 1. DOM Capture & Redaction Helper
// ---------------------------------------------------------------------------

// D5: Bounded patterns for sensitive values in text nodes.
// These match common structured formats (SSN, credit card, email) without
// destroying legitimate page content or reducing scam-detection quality.
const SENSITIVE_TEXT_PATTERNS: RegExp[] = [
  /\b\d{3}[- ]?\d{2}[- ]?\d{4}\b/g,               // SSN-like (XXX-XX-XXXX)
  /\b(?:\d[ -]*?){13,19}\b/g,                        // Credit card numbers (13-19 digits)
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, // Email addresses
];

function getRedactedRenderedDom(): string {
  try {
    const clone = document.documentElement.cloneNode(true) as HTMLElement;

    // 1. Existing: redact form inputs (input, textarea, select)
    const inputs = clone.querySelectorAll("input, textarea, select");
    inputs.forEach((el) => {
      const input = el as HTMLInputElement;
      const nameAttr = (input.name || "").toLowerCase();
      const typeAttr = (input.type || "").toLowerCase();
      if (
        typeAttr === "password" ||
        nameAttr.includes("token") ||
        nameAttr.includes("secret") ||
        nameAttr.includes("cvv") ||
        nameAttr.includes("card")
      ) {
        input.value = "";
        input.removeAttribute("value");
      } else if (input.value) {
        input.value = "[REDACTED]";
      }
    });

    // 2. D5: Redact contenteditable elements
    const editables = clone.querySelectorAll("[contenteditable=\"true\"], [contenteditable=\"\"]");
    editables.forEach((el) => {
      (el as HTMLElement).textContent = "[REDACTED]";
    });

    // 3. D5: Redact obvious sensitive values in text nodes (bounded, deterministic)
    const walker = document.createTreeWalker(clone, NodeFilter.SHOW_TEXT, null);
    const textNodes: Text[] = [];
    let node: Text | null;
    while ((node = walker.nextNode() as Text | null)) {
      textNodes.push(node);
    }
    for (const textNode of textNodes) {
      const text = textNode.nodeValue;
      if (!text || text.length < 5 || text.length > 2000) continue;
      let replaced = text;
      for (const pattern of SENSITIVE_TEXT_PATTERNS) {
        // Reset lastIndex for global patterns
        pattern.lastIndex = 0;
        replaced = replaced.replace(pattern, "[REDACTED]");
      }
      if (replaced !== text) {
        textNode.nodeValue = replaced;
      }
    }

    const html = clone.outerHTML || "";
    return html.slice(0, MAX_DOM_BYTES);
  } catch (err) {
    console.warn("[TRUSTINEL] DOM capture error:", err);
    return "";
  }
}

// Listen for direct background/popup GET_RENDERED_DOM requests
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message && typeof message === "object") {
    if (message.type === "GET_RENDERED_DOM") {
      const boundedHtml = getRedactedRenderedDom();
      sendResponse({ success: true, html: boundedHtml, length: boundedHtml.length });
      return true;
    }
    if (message.type === "UPDATE_FLOATING_INDICATOR" && message.data) {
      updateIndicatorResult(message.data);
      sendResponse({ success: true });
      return true;
    }
  }
  return false;
});

// ---------------------------------------------------------------------------
// 2. Isolated Shadow DOM Floating Lightning Indicator
// ---------------------------------------------------------------------------

let shadowHost: HTMLElement | null = null;
let shadowRoot: ShadowRoot | null = null;
let isPopoverOpen = false;

function initShadowDomIndicator() {
  if (shadowHost) return;
  
  shadowHost = document.createElement("trustinel-indicator");
  shadowHost.id = "trustinel-indicator-host";
  shadowHost.style.cssText = "all: initial; position: fixed; z-index: 2147483647; top: 40%; right: 0; pointer-events: auto;";

  shadowRoot = shadowHost.attachShadow({ mode: "closed" });

  const style = document.createElement("style");
  style.textContent = `
    :host {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      font-size: 13px;
      color-scheme: dark;
    }
    *, *::before, *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    .indicator-badge {
      display: flex;
      items-center;
      gap: 6px;
      padding: 8px 12px;
      background: rgba(15, 23, 42, 0.92);
      backdrop-filter: blur(8px);
      border: 1px solid rgba(51, 65, 85, 0.8);
      border-right: none;
      border-radius: 20px 0 0 20px;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
      cursor: pointer;
      user-select: none;
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .indicator-badge:hover {
      transform: translateX(-4px);
      background: rgba(30, 41, 59, 0.96);
    }
    .icon {
      font-size: 14px;
      line-height: 1;
    }
    .text {
      font-weight: 800;
      font-size: 11px;
      letter-spacing: 0.8px;
      text-transform: uppercase;
    }
    .status-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
    }
    
    /* Verdict Styles */
    .verdict-LEGITIMATE { color: #34d399; border-color: rgba(52, 211, 153, 0.4); }
    .verdict-LEGITIMATE .status-dot { background: #34d399; }
    
    .verdict-PROBABLY_LEGITIMATE { color: #a7f3d0; border-color: rgba(167, 243, 208, 0.4); }
    .verdict-PROBABLY_LEGITIMATE .status-dot { background: #6ee7b7; }
    
    .verdict-SUSPICIOUS { color: #fbbf24; border-color: rgba(251, 191, 36, 0.4); }
    .verdict-SUSPICIOUS .status-dot { background: #fbbf24; animation: pulse-slow 2s infinite; }
    
    .verdict-LIKELY_SCAM { color: #f87171; border-color: rgba(248, 113, 113, 0.5); }
    .verdict-LIKELY_SCAM .status-dot { background: #ef4444; animation: pulse-fast 1s infinite; }
    
    .verdict-HIGH_CONFIDENCE_SCAM { color: #fca5a5; border-color: rgba(239, 68, 68, 0.8); background: rgba(69, 10, 10, 0.95); }
    .verdict-HIGH_CONFIDENCE_SCAM .status-dot { background: #dc2626; box-shadow: 0 0 10px #dc2626; }
    .verdict-HIGH_CONFIDENCE_SCAM.attention-shake { animation: attention-shake 0.6s ease-in-out 3; }
    
    .verdict-UNKNOWN, .verdict-LOADING { color: #94a3b8; border-color: rgba(148, 163, 184, 0.3); }
    .verdict-UNKNOWN .status-dot, .verdict-LOADING .status-dot { background: #94a3b8; }
    
    .verdict-DISABLED { color: #64748b; border-color: rgba(100, 116, 139, 0.3); }
    .verdict-DISABLED .status-dot { background: #64748b; }

    @keyframes pulse-slow {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(1.15); }
    }
    @keyframes pulse-fast {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.2; transform: scale(1.3); }
    }
    @keyframes attention-shake {
      0%, 100% { transform: translateX(-4px); }
      20%, 60% { transform: translateX(-12px); }
      40%, 80% { transform: translateX(0); }
    }
    @media (prefers-reduced-motion: reduce) {
      .status-dot, .verdict-HIGH_CONFIDENCE_SCAM.attention-shake { animation: none !important; }
    }

    /* Popover Container */
    .popover {
      display: none;
      position: absolute;
      right: 100%;
      top: -20px;
      margin-right: 12px;
      width: 320px;
      background: rgba(15, 23, 42, 0.96);
      backdrop-filter: blur(16px);
      border: 1px solid rgba(51, 65, 85, 0.8);
      border-radius: 14px;
      padding: 16px;
      box-shadow: 0 20px 40px -10px rgba(0, 0, 0, 0.7);
      flex-direction: column;
      gap: 12px;
    }
    .popover.open {
      display: flex;
    }
    .popover-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-b: 1px solid rgba(51, 65, 85, 0.5);
      padding-bottom: 10px;
    }
    .domain-name {
      font-weight: 700;
      font-size: 13px;
      color: #f8fafc;
      truncate;
      max-width: 200px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .close-btn {
      background: transparent;
      border: none;
      color: #64748b;
      font-size: 16px;
      cursor: pointer;
    }
    .close-btn:hover { color: #f8fafc; }

    .verdict-badge-box {
      display: flex;
      flex-direction: column;
      gap: 4px;
      padding: 10px 12px;
      border-radius: 8px;
      background: rgba(30, 41, 59, 0.6);
      border: 1px solid rgba(51, 65, 85, 0.5);
    }
    .verdict-title {
      font-weight: 900;
      font-size: 12px;
      letter-spacing: 0.5px;
      text-transform: uppercase;
    }
    .verdict-action {
      font-size: 11px;
      line-height: 1.4;
      color: #cbd5e1;
    }
    .score-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 11px;
      color: #94a3b8;
    }
    .score-val {
      font-weight: 800;
      font-size: 14px;
      color: #f8fafc;
    }
    .bullets {
      display: flex;
      flex-direction: column;
      gap: 6px;
      max-height: 120px;
      overflow-y: auto;
    }
    .bullet-item {
      display: flex;
      align-items: start;
      gap: 6px;
      font-size: 11px;
      color: #94a3b8;
      line-height: 1.3;
    }
    .source-tag {
      font-size: 9px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #38bdf8;
      background: rgba(56, 189, 248, 0.1);
      padding: 3px 6px;
      border-radius: 4px;
      align-self: start;
    }
    .full-report-btn {
      width: 100%;
      padding: 8px;
      background: linear-gradient(135deg, #2563eb, #4f46e5);
      border: none;
      border-radius: 8px;
      color: white;
      font-weight: 700;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      cursor: pointer;
      box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3);
      transition: all 0.2s;
    }
    .full-report-btn:hover {
      filter: brightness(1.1);
    }
    .toggle-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-t: 1px solid rgba(51, 65, 85, 0.5);
      padding-top: 8px;
      font-size: 10px;
      color: #64748b;
    }
    .disable-btn {
      background: transparent;
      border: none;
      color: #f87171;
      font-size: 10px;
      cursor: pointer;
      text-decoration: underline;
    }
  `;

  const container = document.createElement("div");
  container.className = "trustinel-root";
  container.innerHTML = `
    <div className="indicator-badge verdict-LOADING" id="badge">
      <span class="icon">⚡</span>
      <span class="text">TRUSTINEL</span>
      <span class="status-dot"></span>
    </div>
    <div class="popover" id="popover">
      <div class="popover-header">
        <span class="domain-name" id="pop-domain">${window.location.hostname}</span>
        <button class="close-btn" id="pop-close">✕</button>
      </div>
      <div class="verdict-badge-box" id="verdict-box">
        <div class="verdict-title" id="pop-verdict">ANALYZING PAGE...</div>
        <div class="verdict-action" id="pop-action">TRUSTINEL is verifying website security signals.</div>
      </div>
      <div class="score-row">
        <span>Risk Score</span>
        <span class="score-val" id="pop-score">-- / 100</span>
      </div>
      <div class="bullets" id="pop-bullets"></div>
      <span class="source-tag" id="pop-source">SOURCE: LIVE BROWSER RENDERED DOM</span>
      <button class="full-report-btn" id="pop-full">VIEW FULL REPORT</button>
      <div class="toggle-row">
        <span id="pop-prot-status">PROTECTION: ON ●</span>
        <button class="disable-btn" id="pop-disable">DISABLE ON THIS SITE</button>
      </div>
    </div>
  `;

  shadowRoot.appendChild(style);
  shadowRoot.appendChild(container);

  if (document.body) {
    document.body.appendChild(shadowHost);
  } else {
    document.documentElement.appendChild(shadowHost);
  }

  // Event Listeners inside Shadow DOM
  const badge = shadowRoot.getElementById("badge");
  const popover = shadowRoot.getElementById("popover");
  const popClose = shadowRoot.getElementById("pop-close");
  const popFull = shadowRoot.getElementById("pop-full");
  const popDisable = shadowRoot.getElementById("pop-disable");

  badge?.addEventListener("click", () => {
    isPopoverOpen = !isPopoverOpen;
    if (isPopoverOpen) popover?.classList.add("open");
    else popover?.classList.remove("open");
  });

  popClose?.addEventListener("click", () => {
    isPopoverOpen = false;
    popover?.classList.remove("open");
  });

  popFull?.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "OPEN_SIDE_PANEL" });
  });

  popDisable?.addEventListener("click", async () => {
    const domain = window.location.hostname;
    if (!disabledSites.includes(domain)) {
      disabledSites.push(domain);
      await chrome.storage.local.set({ trustinel_disabled_sites: disabledSites });
      updateIndicatorResult({
        user_facing_verdict: "DISABLED",
        recommended_user_action: "TRUSTINEL protection is OFF for this website.",
        overall_risk_score: 0,
        risk_factors: [],
        content_source: "none"
      });
    }
  });
}

function updateIndicatorResult(data: any) {
  if (!shadowRoot) initShadowDomIndicator();
  if (!shadowRoot) return;

  const badge = shadowRoot.getElementById("badge");
  const popVerdict = shadowRoot.getElementById("pop-verdict");
  const popAction = shadowRoot.getElementById("pop-action");
  const popScore = shadowRoot.getElementById("pop-score");
  const popBullets = shadowRoot.getElementById("pop-bullets");
  const popSource = shadowRoot.getElementById("pop-source");
  const popProtStatus = shadowRoot.getElementById("pop-prot-status");

  const verdict = data.user_facing_verdict || "UNKNOWN";
  const action = data.recommended_user_action || data.summary || "No specific action required.";
  const score = data.overall_risk_score ?? data.trust_score ?? 0;
  const factors: string[] = data.risk_factors || data.key_risks || [];
  const source = (data.content_source === "rendered_dom" || data.content_source === "LIVE BROWSER RENDERED DOM")
    ? "SOURCE: LIVE BROWSER RENDERED DOM"
    : "SOURCE: SERVER HTTP FETCH (FALLBACK)";

  // Update Badge Class
  if (badge) {
    badge.className = `indicator-badge verdict-${verdict}`;
    if (verdict === "HIGH_CONFIDENCE_SCAM") {
      badge.classList.add("attention-shake");
      setTimeout(() => badge.classList.remove("attention-shake"), 2000);
    }
  }

  if (popVerdict) popVerdict.textContent = verdict.replace(/_/g, " ");
  if (popAction) popAction.textContent = action;
  if (popScore) popScore.textContent = `${score} / 100`;
  if (popSource) popSource.textContent = source;

  if (popBullets) {
    popBullets.innerHTML = factors.length > 0
      ? factors.slice(0, 4).map(f => `<div class="bullet-item"><span>⚠️</span><span>${f}</span></div>`).join("")
      : `<div class="bullet-item"><span>✓</span><span>No high risk scam factors identified.</span></div>`;
  }

  if (popProtStatus) {
    popProtStatus.textContent = protectionEnabled ? "PROTECTION: ON ●" : "PROTECTION: OFF ⚪";
  }
}

// ---------------------------------------------------------------------------
// 3. Automatic Scan & SPA Route Detection
// ---------------------------------------------------------------------------

async function triggerAutoScan(reason: string) {
  const currentUrl = window.location.href;
  const currentDomain = window.location.hostname;
  const now = Date.now();

  // Check protection state & disabled sites
  try {
    const store = await chrome.storage.local.get(["trustinel_protection_enabled", "trustinel_disabled_sites"]);
    protectionEnabled = store.trustinel_protection_enabled !== false;
    disabledSites = Array.isArray(store.trustinel_disabled_sites) ? store.trustinel_disabled_sites : [];
  } catch { /* ignore */ }

  if (!protectionEnabled || disabledSites.includes(currentDomain)) {
    updateIndicatorResult({
      user_facing_verdict: "DISABLED",
      recommended_user_action: "TRUSTINEL protection is OFF for this website.",
      overall_risk_score: 0,
      risk_factors: [],
      content_source: "none"
    });
    return;
  }

  // Cooldown check
  if (currentUrl === lastAutoScanUrl && (now - lastAutoScanTime) < AUTO_SCAN_COOLDOWN_MS) {
    return;
  }

  lastAutoScanTime = now;
  lastAutoScanUrl = currentUrl;

  // D1 fix: Increment scan generation and capture both generation and URL
  // at the moment the scan is initiated. When the response arrives, verify
  // both still match to prevent stale responses from updating the indicator.
  scanGeneration++;
  const thisScanGeneration = scanGeneration;
  const initiatingUrl = currentUrl;

  console.log(`[TRUSTINEL] Automatic page protection scan triggered (${reason}):`, currentDomain);

  const boundedHtml = getRedactedRenderedDom();

  chrome.runtime.sendMessage(
    {
      type: "SCAN_CURRENT_TAB_AUTO",
      url: currentUrl,
      page_html: boundedHtml
    },
    (response) => {
      if (chrome.runtime.lastError) {
        console.warn("[TRUSTINEL] Auto scan message error:", chrome.runtime.lastError.message);
        return;
      }

      // D1 fix: Discard stale responses.
      // 1. If a newer scan has been initiated, this response is outdated.
      // 2. If the URL has changed since scan initiation, the user navigated away.
      if (thisScanGeneration !== scanGeneration) {
        console.log(`[TRUSTINEL] Discarding stale scan response (generation ${thisScanGeneration} < ${scanGeneration}).`);
        return;
      }
      if (window.location.href !== initiatingUrl) {
        console.log(`[TRUSTINEL] Discarding stale scan response (URL changed from ${initiatingUrl}).`);
        return;
      }

      if (response && response.success && response.data?.trust_report) {
        updateIndicatorResult(response.data.trust_report);
      }
    }
  );
}

// Attach listeners once DOM is ready
function setupAutoProtection() {
  initShadowDomIndicator();

  // Initial scan on document settlement
  if (document.readyState === "complete" || document.readyState === "interactive") {
    setTimeout(() => triggerAutoScan("page_settled"), 500);
  } else {
    window.addEventListener("DOMContentLoaded", () => {
      setTimeout(() => triggerAutoScan("page_settled"), 500);
    });
  }

  // SPA Route Navigation hooks
  window.addEventListener("popstate", () => triggerAutoScan("popstate_navigation"));

  const originalPushState = history.pushState;
  history.pushState = function (...args) {
    originalPushState.apply(this, args);
    setTimeout(() => triggerAutoScan("pushState_navigation"), 300);
  };

  const originalReplaceState = history.replaceState;
  history.replaceState = function (...args) {
    originalReplaceState.apply(this, args);
    setTimeout(() => triggerAutoScan("replaceState_navigation"), 300);
  };
}

setupAutoProtection();

export {};
