const FS_GMAIL_SCANNED_ELEMENTS = new WeakSet();
const FS_GMAIL_SOURCE = "gmail";

const GMAIL_BODY_SELECTOR = ".a3s.aiL";
const GMAIL_SUBJECT_SELECTOR = "h2.hP";
const GMAIL_SENDER_SELECTOR = ".gD";
const GMAIL_COMPOSE_BODY_SELECTOR = "div[aria-label='Message Body'][contenteditable='true'], div[g_editable='true'][role='textbox']";
const FS_GMAIL_COMPOSE_TIMERS = new WeakMap();

function processGmailEmail(bodyElement) {
  if (!bodyElement || FS_GMAIL_SCANNED_ELEMENTS.has(bodyElement)) return;

  const subject = document.querySelector(GMAIL_SUBJECT_SELECTOR)?.innerText?.trim() || "";
  const sender = document.querySelector(GMAIL_SENDER_SELECTOR)?.getAttribute("email")
    || document.querySelector(GMAIL_SENDER_SELECTOR)?.innerText?.trim()
    || "";
  const body = bodyElement.innerText?.trim() || "";
  if (body.length < 10) return;

  FS_GMAIL_SCANNED_ELEMENTS.add(bodyElement);

  const fullText = [
    subject ? `Subject: ${subject}` : "",
    sender ? `Sender: ${sender}` : "",
    body
  ].filter(Boolean).join("\n\n");

  scanMessage(fullText, (result) => {
    insertAlertInside(bodyElement, result);
  }, FS_GMAIL_SOURCE);
}

function scanCurrentGmailEmail() {
  document.querySelectorAll(GMAIL_BODY_SELECTOR).forEach(processGmailEmail);
  document.querySelectorAll(GMAIL_COMPOSE_BODY_SELECTOR).forEach(processGmailCompose);
}

function processGmailCompose(bodyElement) {
  if (!bodyElement) return;

  clearTimeout(FS_GMAIL_COMPOSE_TIMERS.get(bodyElement));
  const timer = setTimeout(() => {
    const body = bodyElement.innerText?.trim() || "";
    if (body.length < 10) return;

    const composeDialog = bodyElement.closest("div[role='dialog']") || bodyElement.closest("table") || document;
    if (composeDialog.querySelector?.("[data-fs-alert='true']")) return;

    const subject = composeDialog.querySelector("input[name='subjectbox']")?.value?.trim() || "";
    const fullText = [
      subject ? `Subject: ${subject}` : "",
      body
    ].filter(Boolean).join("\n\n");

    scanMessage(fullText, (result) => {
      const alert = buildAlert(result);
      const insertTarget = bodyElement.closest("td") || bodyElement.parentElement || bodyElement;
      insertTarget.parentNode?.insertBefore(alert, insertTarget);
      if (result.risk_level === "HIGH") showDelayOverlay(result);
    }, FS_GMAIL_SOURCE);
  }, 900);

  FS_GMAIL_COMPOSE_TIMERS.set(bodyElement, timer);
}

function startGmailObserver() {
  scanCurrentGmailEmail();

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        if (node.matches?.(GMAIL_BODY_SELECTOR)) {
          setTimeout(() => processGmailEmail(node), 300);
        }
        if (node.matches?.(GMAIL_COMPOSE_BODY_SELECTOR)) {
          setTimeout(() => processGmailCompose(node), 300);
        }
        node.querySelectorAll?.(GMAIL_BODY_SELECTOR)
          .forEach((body) => setTimeout(() => processGmailEmail(body), 300));
        node.querySelectorAll?.(GMAIL_COMPOSE_BODY_SELECTOR)
          .forEach((body) => setTimeout(() => processGmailCompose(body), 300));
      }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });
  document.body.addEventListener("input", (event) => {
    const composeBody = event.target?.closest?.(GMAIL_COMPOSE_BODY_SELECTOR);
    if (composeBody) processGmailCompose(composeBody);
  }, true);
  setInterval(scanCurrentGmailEmail, 5000);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", startGmailObserver);
} else {
  startGmailObserver();
}
