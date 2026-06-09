const DEFAULT_API = "http://127.0.0.1:8000";
const apiInput = document.getElementById("apiBase");
const tokenInput = document.getElementById("authToken");

chrome.storage.sync.get(["apiBase", "authToken"], (settings) => {
  apiInput.value = settings.apiBase || DEFAULT_API;
  tokenInput.value = settings.authToken || "";
});

document.getElementById("saveSettings").onclick = () => {
  const base = (apiInput.value || DEFAULT_API).replace(/\/+$/, "");
  const tokenVal = (tokenInput.value || "").trim();
  chrome.storage.sync.set({ apiBase: base, authToken: tokenVal }, () => {
    const btn = document.getElementById("saveSettings");
    const originalText = btn.textContent;
    btn.textContent = "Saved ✓";
    btn.style.background = "#00b98a";
    setTimeout(() => {
      btn.textContent = originalText;
      btn.style.background = "#00d4a0";
    }, 1500);
  });
};

const saveSettingsBtn = document.getElementById("saveSettings");
apiInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") saveSettingsBtn.click();
});
tokenInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") saveSettingsBtn.click();
});

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const url = tabs[0]?.url || "";
  setState("waState", url.includes("web.whatsapp.com"));
  setState("gmState", url.includes("mail.google.com"));
  
  const isSocial = ["x.com", "twitter.com", "facebook.com", "instagram.com", "linkedin.com", "discord.com"].some(domain => url.includes(domain));
  setState("socState", isSocial);
});

function setState(id, active) {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = active ? "Scanning" : "Not open";
    el.className = active ? "on" : "off";
  }
}

function loadStats() {
  chrome.storage.local.get(["scanStats", "recentScans"], (data) => {
    const stats = data.scanStats || {};
    document.getElementById("lowCount").textContent = stats.LOW || 0;
    document.getElementById("medCount").textContent = stats.MEDIUM || 0;
    document.getElementById("highCount").textContent = stats.HIGH || 0;

    const recent = data.recentScans || [];
    const wrap = document.getElementById("recentScans");
    if (!recent) return;
    if (!recent.length) {
      wrap.innerHTML = '<div class="empty">No scans yet.</div>';
      return;
    }
    wrap.innerHTML = recent.slice(0, 5).map((scan) => `
      <div class="scan">
        <div class="dot ${scan.risk_level}"></div>
        <div class="scan-main">
          <div class="scan-title">${escapeHtml(scan.summary)}</div>
          <div class="scan-meta">${escapeHtml(scan.source)} - ${new Date(scan.scanned_at).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"})}</div>
        </div>
        <div class="score">${scan.risk_score}</div>
      </div>
    `).join("");
  });
}

document.getElementById("openScanner").onclick = () => {
  const base = (apiInput.value || DEFAULT_API).replace(/\/+$/, "");
  chrome.tabs.create({ url: `${base}/scan` });
};

document.getElementById("resetStats").onclick = () => {
  chrome.storage.local.set({ scanStats: { LOW: 0, MEDIUM: 0, HIGH: 0 }, recentScans: [] }, loadStats);
};

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = String(text || "");
  return div.innerHTML;
}

loadStats();
