const FS_WA_SCANNED_ELEMENTS = new WeakSet();
const FS_WA_SOURCE = "whatsapp";

const WA_MESSAGE_SELECTORS = [
  ".message-in",
  "[data-id^='false_']",
  "[data-testid='msg-container']"
];

const WA_TEXT_SELECTORS = [
  ".selectable-text span[dir]",
  "span.selectable-text",
  "[data-pre-plain-text] span[dir]",
  "span[dir='ltr']",
  "span[dir='auto']"
];

function processWhatsAppMessage(element) {
  if (!element || FS_WA_SCANNED_ELEMENTS.has(element)) return;

  if (element.closest("[data-fs-alert='true']")) return;
  const text = extractWhatsAppText(element);
  if (!text || text.length < 10) return;

  FS_WA_SCANNED_ELEMENTS.add(element);

  scanMessage(text, (result) => {
    insertAlertBefore(element, result);
  }, FS_WA_SOURCE);
}

function extractWhatsAppText(element) {
  for (const selector of WA_TEXT_SELECTORS) {
    const parts = [...element.querySelectorAll(selector)]
      .map((node) => node.innerText || node.textContent || "")
      .map((text) => text.trim())
      .filter(Boolean);
    if (parts.length) return [...new Set(parts)].join(" ");
  }
  return "";
}

function scanVisibleWhatsAppMessages() {
  const selector = WA_MESSAGE_SELECTORS.join(",");
  [...document.querySelectorAll(selector)]
    .slice(-8)
    .forEach(processWhatsAppMessage);
}

function startWhatsAppObserver() {
  scanVisibleWhatsAppMessages();

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        if (WA_MESSAGE_SELECTORS.some((selector) => node.matches?.(selector))) {
          processWhatsAppMessage(node);
        }
        node.querySelectorAll?.(WA_MESSAGE_SELECTORS.join(",")).forEach(processWhatsAppMessage);
      }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });
  setInterval(scanVisibleWhatsAppMessages, 5000);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => setTimeout(startWhatsAppObserver, 2000));
} else {
  setTimeout(startWhatsAppObserver, 2000);
}
