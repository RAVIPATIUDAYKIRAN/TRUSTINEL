// TRUSTINEL Content Script injection
// Safely extracts bounded rendered DOM from active tab when requested by background/popup.

const MAX_DOM_BYTES = 500_000; // 500 KB MAX

console.log("[TRUSTINEL] Content script successfully injected on site:", window.location.hostname);

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message && typeof message === "object" && message.type === "GET_RENDERED_DOM") {
    try {
      const html = document.documentElement ? document.documentElement.outerHTML : "";
      const boundedHtml = html.slice(0, MAX_DOM_BYTES);
      sendResponse({ success: true, html: boundedHtml, length: boundedHtml.length });
    } catch (err) {
      sendResponse({ success: false, html: "", error: String(err) });
    }
    return true;
  }
  return false;
});

export {};
