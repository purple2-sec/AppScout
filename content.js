// ================= CAPABILITY DETECTION =================
const findings = [];

if ("mediaDevices" in navigator) findings.push("Camera / Microphone APIs available");
if ("geolocation" in navigator) findings.push("Location API available");
if ("clipboard" in navigator) findings.push("Clipboard API available");
if ("usb" in navigator) findings.push("USB device API available");
if ("bluetooth" in navigator) findings.push("Bluetooth API available");
if ("hid" in navigator) findings.push("HID device API available");

chrome.runtime.sendMessage({ type: "CAPABILITIES_DETECTED", findings });

// ================= CLIPBOARD MONITORING =================
let clipboardMonitorEnabled = true;

chrome.runtime.sendMessage({ type: "GET_CLIPBOARD_STATUS" }, (response) => {
  if (response) clipboardMonitorEnabled = response.enabled;
});

// Monitor COPY events
document.addEventListener('copy', (e) => {
  if (!clipboardMonitorEnabled) return;
  
  setTimeout(async () => {
    try {
      const text = await navigator.clipboard.readText();
      
      if (text && text.length > 10) {
        chrome.runtime.sendMessage({
          type: "CHECK_CLIPBOARD",
          content: text
        }, (response) => {
          if (response && response.malicious) {
            showThreatWarning(response.threats, text);
          }
        });
      }
    } catch (err) {
      console.log("Clipboard read failed:", err);
    }
  }, 100);
});

// Show threat warning overlay
function showThreatWarning(threats, clipboardContent) {
  // Remove any existing warnings
  const existing = document.getElementById('appscout-threat-warning');
  if (existing) existing.remove();
  
  const overlay = document.createElement('div');
  overlay.id = 'appscout-threat-warning';
  overlay.innerHTML = `
    <div style="
      position: fixed;
      top: 20px;
      right: 20px;
      background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
      color: white;
      padding: 20px;
      border-radius: 12px;
      box-shadow: 0 10px 40px rgba(239, 68, 68, 0.5);
      z-index: 2147483647;
      max-width: 400px;
      font-family: system-ui, -apple-system, sans-serif;
      animation: slideInRight 0.3s ease-out;
    ">
      <div style="display: flex; align-items: center; margin-bottom: 12px;">
        <span style="font-size: 28px; margin-right: 10px;">⚠️</span>
        <strong style="font-size: 18px;">MALICIOUS COMMAND DETECTED!</strong>
      </div>
      <div style="font-size: 14px; margin-bottom: 12px; line-height: 1.5;">
        <strong style="color: #fef2f2;">${threats[0].threat}</strong><br>
        <span style="opacity: 0.95; font-size: 13px;">❌ DO NOT paste this into your terminal!</span>
      </div>
      <div style="background: rgba(0,0,0,0.2); padding: 10px; border-radius: 6px; margin: 10px 0; font-size: 11px; font-family: monospace; max-height: 60px; overflow: hidden;">
        ${escapeHtml(clipboardContent.substring(0, 150))}...
      </div>
      <div style="display: flex; gap: 10px; margin-top: 15px;">
        <button id="appscout-clear-clipboard" style="
          flex: 1;
          background: white;
          color: #ef4444;
          border: none;
          padding: 12px;
          border-radius: 6px;
          font-weight: bold;
          cursor: pointer;
          font-size: 13px;
        ">🗑️ Clear Clipboard</button>
        <button id="appscout-dismiss" style="
          flex: 1;
          background: rgba(255,255,255,0.2);
          color: white;
          border: 1px solid rgba(255,255,255,0.4);
          padding: 12px;
          border-radius: 6px;
          font-weight: bold;
          cursor: pointer;
          font-size: 13px;
        ">Dismiss</button>
      </div>
    </div>
  `;
  
  // Add animation
  if (!document.getElementById('appscout-animations')) {
    const style = document.createElement('style');
    style.id = 'appscout-animations';
    style.textContent = `
      @keyframes slideInRight {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
    `;
    document.head.appendChild(style);
  }
  
  document.body.appendChild(overlay);
  
  // Clear clipboard button
  document.getElementById('appscout-clear-clipboard').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText('');
      overlay.remove();
    } catch (err) {
      console.error('Failed to clear clipboard:', err);
    }
  });
  
  // Dismiss button
  document.getElementById('appscout-dismiss').addEventListener('click', () => {
    overlay.remove();
  });
  
  // Auto-dismiss after 15 seconds
  setTimeout(() => {
    if (overlay.parentNode) overlay.remove();
  }, 15000);
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ================= OVERLAY DETECTION =================
let overlayCheckInterval;
let knownOverlays = new Set();

function detectSuspiciousOverlays() {
  const elements = document.querySelectorAll('*');
  
  elements.forEach(el => {
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    
    // Detect full-screen overlays
    if (
      (style.position === 'fixed' || style.position === 'absolute') &&
      style.zIndex > 1000 &&
      rect.width > window.innerWidth * 0.8 &&
      rect.height > window.innerHeight * 0.8 &&
      !knownOverlays.has(el)
    ) {
      // Check if it contains form inputs (phishing indicator)
      const hasInputs = el.querySelector('input[type="password"], input[type="email"], input[type="text"]');
      
      if (hasInputs) {
        knownOverlays.add(el);
        chrome.runtime.sendMessage({ type: "OVERLAY_DETECTED" });
        
        // Visual warning on the overlay itself
        el.style.border = '5px solid red';
        el.style.boxShadow = '0 0 20px red';
        
        const warning = document.createElement('div');
        warning.style.cssText = `
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          background: #ef4444;
          color: white;
          padding: 10px;
          text-align: center;
          font-weight: bold;
          z-index: 999999999;
        `;
        warning.textContent = '⚠️ APPSCOUT WARNING: Suspicious login form detected! This may be phishing!';
        el.insertBefore(warning, el.firstChild);
      }
    }
  });
}

// Start overlay detection after page load
setTimeout(() => {
  detectSuspiciousOverlays();
  overlayCheckInterval = setInterval(detectSuspiciousOverlays, 2000);
}, 2000);

// ================= POPUP SPAM DETECTION =================
let popupCount = 0;
let popupResetTimer;

const originalWindowOpen = window.open;
window.open = function(...args) {
  popupCount++;
  
  clearTimeout(popupResetTimer);
  popupResetTimer = setTimeout(() => {
    popupCount = 0;
  }, 5000);
  
  if (popupCount > 2) {
    chrome.runtime.sendMessage({ type: "POPUP_SPAM_DETECTED" });
    alert('⚠️ AppScout blocked popup spam!\n\nThis page tried to open multiple popups.');
    return null;
  }
  
  return originalWindowOpen.apply(this, args);
};

// ================= LISTEN FOR MONITOR TOGGLE =================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "CLIPBOARD_MONITOR_TOGGLED") {
    clipboardMonitorEnabled = msg.enabled;
  }
});
