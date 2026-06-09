const FS_SOCIAL_SCANNED_ELEMENTS = new WeakSet();
const FS_SOCIAL_SOURCE = "social";

const SOCIAL_MESSAGE_SELECTORS = [
  "div[data-testid='messageEntry']",          // X (Twitter) DMs
  "article[data-testid='tweet']",              // X (Twitter) Feed posts
  "div[data-testid='message-container']",      // Facebook Messenger DMs
  "div[role='row'] .ljqsnud1",                  // Meta Messenger DMs alternative
  "div[role='none'] div[dir='auto']",          // Instagram DMs (Option A)
  "div[role='row'] div[dir='auto']",           // Instagram DMs (Option B)
  "div[role='row'] span[dir='auto']",          // Instagram DMs (Option C)
  ".msg-s-event-listitem__body",               // LinkedIn DMs
  ".feed-shared-update-v2__description",       // LinkedIn Feed updates
  "div[class^='messageContent_']",             // Discord DMs/Channels
  "li[class^='message_']"                      // Discord generic lists
];

function processSocialMessage(element) {
  if (!element || FS_SOCIAL_SCANNED_ELEMENTS.has(element)) return;

  if (element.closest("[data-fs-alert='true']")) return;
  const text = extractSocialText(element);
  if (!text || text.length < 15) return;

  // Mark as scanned only when valid text is found
  FS_SOCIAL_SCANNED_ELEMENTS.add(element);

  // Filter feed items heuristically to only scan posts/DMs containing link or payment elements
  const lowerText = text.toLowerCase();
  const suspiciousKeywords = [
    "http", "www", "verify", "secure", "login", "password", "bank", "account", "transfer",
    "card", "crypto", "bitcoin", "gift", "prize", "win", "claim", "urgent", "support", "helpdesk"
  ];
  const isSuspicious = suspiciousKeywords.some(keyword => lowerText.includes(keyword));
  if (!isSuspicious) return;

  scanMessage(text, (result) => {
    insertAlertBefore(element, result);
  }, FS_SOCIAL_SOURCE);
}

function extractSocialText(element) {
  const text = element.innerText || element.textContent || "";
  return text.trim();
}

function scanVisibleSocialMessages() {
  const selector = SOCIAL_MESSAGE_SELECTORS.join(",");
  document.querySelectorAll(selector).forEach(processSocialMessage);
}

function startSocialObserver() {
  scanVisibleSocialMessages();

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        SOCIAL_MESSAGE_SELECTORS.forEach(selector => {
          if (node.matches?.(selector)) {
            processSocialMessage(node);
          }
          node.querySelectorAll?.(selector).forEach(processSocialMessage);
        });
      }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });
  setInterval(scanVisibleSocialMessages, 4000);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => setTimeout(startSocialObserver, 2000));
} else {
  setTimeout(startSocialObserver, 2000);
}
