// TRUSTINEL Background Worker (Service Worker)

chrome.runtime.onInstalled.addListener((details) => {
  console.log("[TRUSTINEL] Extension installed successfully.", details);
});

console.log("[TRUSTINEL] Background Service Worker active.");
export {};
