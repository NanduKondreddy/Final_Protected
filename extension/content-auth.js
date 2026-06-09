// extension/content-auth.js
(function() {
  console.log("🛡️ ShieldIQ Extension Bridge: Script loaded (v1.0.5)");

  function syncAuth() {
    // Safety check for context invalidation
    if (!chrome.runtime || !chrome.runtime.id) return;

    if (!document.body) return;

    // Tag the body to let the website know the extension is active and listening
    if (!document.body.hasAttribute('data-shieldiq-extension-installed')) {
      document.body.setAttribute('data-shieldiq-extension-installed', 'true');
    }

    if (!chrome.storage || !chrome.storage.sync) return;

    const token = document.body.getAttribute('data-shieldiq-token-bridge');
    const userStr = document.body.getAttribute('data-shieldiq-user-bridge');
    const isDomActive = document.body.hasAttribute('data-shieldiq-extension-active');
    const wantPaused = document.body.getAttribute('data-shieldiq-want-paused');

    try {
      chrome.storage.sync.get(["protectionEnabled", "authToken", "apiBase"], (settings) => {
        if (!chrome.runtime || !chrome.runtime.id) return;
        if (chrome.runtime.lastError) return;

        const updates = {};
        let needsUpdate = false;

        if (wantPaused === 'true') {
          document.body.removeAttribute('data-shieldiq-want-paused');
          document.body.removeAttribute('data-shieldiq-extension-active');
          updates.protectionEnabled = false;
          needsUpdate = true;
          console.log("🛡️ ShieldIQ: Protection paused via wantPaused attribute.");
        } else if (isDomActive && !settings?.protectionEnabled) {
          updates.protectionEnabled = true;
          needsUpdate = true;
          console.log("🛡️ ShieldIQ: Syncing protectionEnabled = true to storage.");
        } else if (!isDomActive && settings?.protectionEnabled && !wantPaused) {
          // Restore active attribute on DOM
          document.body.setAttribute('data-shieldiq-extension-active', 'true');
          console.log("🛡️ ShieldIQ: Restoring active state to DOM body from storage.");
        }

        if (token && userStr) {
          try {
            const user = JSON.parse(userStr);
            if (user.plan === 'pro' || user.plan === 'plus' || user.plan === 'enterprise') {
              if (settings?.authToken !== token) {
                updates.authToken = token;
                needsUpdate = true;
              }
              const currentOrigin = window.location.origin;
              if (settings?.apiBase !== currentOrigin) {
                updates.apiBase = currentOrigin;
                needsUpdate = true;
              }
            } else {
              if (settings?.authToken) {
                updates.authToken = "";
                needsUpdate = true;
              }
              if (settings?.protectionEnabled) {
                updates.protectionEnabled = false;
                needsUpdate = true;
                document.body.removeAttribute('data-shieldiq-extension-active');
              }
            }
          } catch (e) {
            console.error("ShieldIQ parse error:", e);
          }
        } else {
          if (settings?.authToken) {
            updates.authToken = "";
            needsUpdate = true;
          }
        }

        if (needsUpdate) {
          chrome.storage.sync.set(updates);
        }
      });
    } catch (err) {
      // Ignore
    }
  }

  // Initial sync on script load
  if (document.body) {
    syncAuth();

    // Watch for DOM bridge attribute changes instead of using a polling interval.
    // This removes the need for setInterval, preventing "Extension context invalidated" errors when reloaded.
    const observer = new MutationObserver(() => {
      try {
        syncAuth();
      } catch (e) {
        observer.disconnect();
      }
    });

    observer.observe(document.body, {
      attributes: true,
      attributeFilter: [
        'data-shieldiq-extension-active',
        'data-shieldiq-want-paused',
        'data-shieldiq-token-bridge',
        'data-shieldiq-user-bridge'
      ]
    });

    // Also sync changes from extension storage back to the DOM
    try {
      chrome.storage.onChanged.addListener((changes, area) => {
        if (!chrome.runtime || !chrome.runtime.id) return;
        if (area === "sync" && changes.protectionEnabled) {
          if (changes.protectionEnabled.newValue) {
            document.body.setAttribute('data-shieldiq-extension-active', 'true');
          } else {
            document.body.removeAttribute('data-shieldiq-extension-active');
          }
        }
      });
    } catch (e) {
      // Ignore
    }
  }
})();
