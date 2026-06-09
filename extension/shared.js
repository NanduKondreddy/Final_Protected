const FS_DEFAULT_API = "http://127.0.0.1:8000";
const fsScannedTextKeys = new Set();

let fsApiBase = FS_DEFAULT_API;
let fsAuthToken = "";

chrome.storage?.sync?.get(["apiBase", "authToken"], (settings) => {
  if (settings.apiBase) fsApiBase = cleanApiBase(settings.apiBase);
  if (settings.authToken) fsAuthToken = settings.authToken;
});

chrome.storage?.onChanged?.addListener((changes, area) => {
  if (area === "sync") {
    if (changes.apiBase?.newValue) {
      fsApiBase = cleanApiBase(changes.apiBase.newValue);
    }
    if (changes.authToken?.newValue) {
      fsAuthToken = changes.authToken.newValue;
    }
  }
});

async function scanMessage(text, onResult, source = "extension") {
  const message = String(text || "").replace(/\s+/g, " ").trim();
  if (message.length < 10) return;

  // Verify that protection is enabled by the user
  const isEnabled = await new Promise((resolve) => {
    chrome.storage.sync.get(["protectionEnabled"], (settings) => {
      resolve(!!settings.protectionEnabled);
    });
  });
  if (!isEnabled) return;

  const key = `${source}:${message.slice(0, 260)}`;
  if (fsScannedTextKeys.has(key)) return;
  fsScannedTextKeys.add(key);
  trimScanCache();

  try {
    const headers = { "Content-Type": "application/json" };
    if (fsAuthToken) {
      headers["Authorization"] = `Bearer ${fsAuthToken}`;
    }
    const response = await fetch(`${fsApiBase}/scan/json`, {
      method: "POST",
      headers,
      body: JSON.stringify({ message })
    });

    if (!response.ok) return;

    const raw = await response.json();
    const result = normalizeScanResult(raw);
    await recordLocalScan(result, source);

    if (result.risk_level === "LOW") return;
    onResult(result);
  } catch (error) {
    console.debug("FraudShield scan failed", error);
  }
}

function normalizeScanResult(result) {
  const score = Number(result.risk_score ?? 0);
  const level = normalizeRiskLevel(result.risk_level || result.risk_band, score);
  return {
    risk_score: Math.max(0, Math.min(100, Number.isFinite(score) ? score : 0)),
    risk_level: level,
    summary: result.summary || result.verdict_summary || "Suspicious message detected.",
    reasons: Array.isArray(result.reasons) ? result.reasons.slice(0, 3) : [],
    action: result.action || actionFromLevel(level),
    what_to_do: result.what_to_do || result.recommendation || defaultRecommendation(level),
    pass1_blocked: Boolean(result.pass1_blocked)
  };
}

function buildAlert(result) {
  const levelClass = result.risk_level.toLowerCase();
  const color = result.risk_level === "HIGH" ? "#ff4757" : "#f59e0b";
  const wrap = document.createElement("div");
  wrap.className = `fs-alert fs-${levelClass}`;
  wrap.setAttribute("data-fs-alert", "true");

  const reasons = ensureReasons(result.reasons, result.risk_level)
    .map((reason, index) => `
      <li class="fs-reason">
        <span class="fs-num">${index + 1}</span>
        <span>${escapeHtml(reason)}</span>
      </li>
    `).join("");

  wrap.innerHTML = `
    <div class="fs-topline" style="background:${color}"></div>
    <div class="fs-header">
      <div class="fs-verdict">
        <span class="fs-risk-pill">${result.risk_level} RISK</span>
        <span class="fs-action-pill">${escapeHtml(result.action)}</span>
      </div>
      <div class="fs-score"><strong>${result.risk_score}</strong><span>/100</span></div>
      <button class="fs-dismiss" title="Dismiss">x</button>
    </div>
    <div class="fs-title">${escapeHtml(result.summary)}</div>
    <ul class="fs-reasons">${reasons}</ul>
    <div class="fs-rec">
      <span>What to do</span>
      <p>${escapeHtml(result.what_to_do)}</p>
    </div>
  `;

  wrap.querySelector(".fs-dismiss").addEventListener("click", () => wrap.remove());
  return wrap;
}

function showDelayOverlay(result) {
  if (result.risk_level !== "HIGH") return;
  if (document.querySelector("[data-fs-delay-overlay]")) return;

  const overlay = document.createElement("div");
  overlay.className = "fs-delay-overlay";
  overlay.setAttribute("data-fs-delay-overlay", "true");
  overlay.innerHTML = `
    <div class="fs-delay-card">
      <div class="fs-delay-warning">HIGH FRAUD RISK</div>
      <div class="fs-delay-title">Pause before you act</div>
      <div class="fs-delay-text">${escapeHtml(result.summary)} Fraudsters rely on panic. Take a moment before clicking or replying.</div>
      <button class="fs-delay-safe">I will not act on this message</button>
      <button class="fs-delay-proceed">Dismiss warning</button>
    </div>
  `;
  document.body.appendChild(overlay);

  overlay.querySelector(".fs-delay-safe").addEventListener("click", () => overlay.remove());
  overlay.querySelector(".fs-delay-proceed").addEventListener("click", () => overlay.remove());
}

async function recordLocalScan(result, source) {
  chrome.storage?.local?.get(["scanStats", "recentScans"], (data) => {
    const stats = data.scanStats || { LOW: 0, MEDIUM: 0, HIGH: 0 };
    stats[result.risk_level] = (stats[result.risk_level] || 0) + 1;

    const recent = Array.isArray(data.recentScans) ? data.recentScans : [];
    recent.unshift({
      risk_level: result.risk_level,
      risk_score: result.risk_score,
      source,
      summary: result.summary,
      scanned_at: new Date().toISOString()
    });

    chrome.storage.local.set({
      scanStats: stats,
      recentScans: recent.slice(0, 10)
    });
  });
}

function insertAlertBefore(target, result) {
  if (!target || target.querySelector?.("[data-fs-alert]")) return;
  const alert = buildAlert(result);
  target.parentNode?.insertBefore(alert, target);
  if (result.risk_level === "HIGH") showDelayOverlay(result);
}

function insertAlertInside(target, result) {
  if (!target || target.querySelector?.("[data-fs-alert]")) return;
  const alert = buildAlert(result);
  target.insertBefore(alert, target.firstChild);
  setTimeout(() => alert.scrollIntoView({ behavior: "smooth", block: "nearest" }), 80);
  if (result.risk_level === "HIGH") showDelayOverlay(result);
}

function cleanApiBase(value) {
  return String(value || FS_DEFAULT_API).replace(/\/+$/, "");
}

function trimScanCache() {
  if (fsScannedTextKeys.size <= 500) return;
  [...fsScannedTextKeys].slice(0, 120).forEach((key) => fsScannedTextKeys.delete(key));
}

function normalizeRiskLevel(level, score) {
  const normalized = String(level || "").toUpperCase().replace("SAFE", "LOW").replace("CAUTION", "MEDIUM").replace("HIGH_RISK", "HIGH");
  if (["LOW", "MEDIUM", "HIGH"].includes(normalized)) return normalized;
  if (score <= 30) return "LOW";
  if (score <= 69) return "MEDIUM";
  return "HIGH";
}

function actionFromLevel(level) {
  if (level === "HIGH") return "BLOCK";
  if (level === "MEDIUM") return "CAUTION";
  return "TRUST";
}

function defaultRecommendation(level) {
  if (level === "HIGH") return "Do not click, reply, pay, or share details. Verify through an official channel.";
  if (level === "MEDIUM") return "Pause and verify through a trusted channel before acting.";
  return "This appears safe, but keep using official apps or websites for sensitive actions.";
}

function ensureReasons(reasons, level) {
  const fallback = level === "HIGH"
    ? ["Strong fraud signals were detected", "The message may pressure you to act quickly", "Following it could risk money or account access"]
    : ["Some details look suspicious", "The sender or request should be verified", "Do not act until you confirm independently"];
  return [...(reasons || []), ...fallback].filter(Boolean).slice(0, 3);
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = String(text ?? "");
  return div.innerHTML;
}
