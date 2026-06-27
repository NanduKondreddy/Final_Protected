chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.get(["apiBase"], (settings) => {
    if (!settings.apiBase) {
      chrome.storage.sync.set({ apiBase: "http://127.0.0.1:8000" });
    }
  });
});
