// ================= BACKGROUND SERVICE WORKER =================
let clipboardMonitorEnabled = true;
let threatHistory = [];
let tabThreats = {}; // Track threats per tab

// Initialize
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    clipboardMonitorEnabled: true,
    threatHistory: [],
    autoBlockEnabled: false
  });
  console.log("AppScout Protection enabled");
});

// Load settings
chrome.storage.local.get(['clipboardMonitorEnabled', 'threatHistory'], (result) => {
  if (result.clipboardMonitorEnabled !== undefined) {
    clipboardMonitorEnabled = result.clipboardMonitorEnabled;
  }
  if (result.threatHistory) {
    threatHistory = result.threatHistory;
  }
});

// ================= MALICIOUS PATTERNS =================
const MALICIOUS_PATTERNS = [
  { pattern: /powershell/i, threat: "PowerShell execution detected", severity: "critical" },
  { pattern: /pwsh/i, threat: "PowerShell Core detected", severity: "critical" },
  { pattern: /invoke-expression/i, threat: "PowerShell Invoke-Expression", severity: "critical" },
  { pattern: /\biex\b/i, threat: "PowerShell IEX command", severity: "critical" },
  { pattern: /invoke-webrequest/i, threat: "PowerShell web request", severity: "high" },
  { pattern: /downloadstring/i, threat: "PowerShell download", severity: "critical" },
  { pattern: /-encodedcommand/i, threat: "Encoded PowerShell command", severity: "critical" },
  { pattern: /-enc\s/i, threat: "Encoded command", severity: "critical" },
  { pattern: /curl.*\|.*sh/i, threat: "Curl piped to shell", severity: "critical" },
  { pattern: /curl.*\|.*bash/i, threat: "Curl piped to bash", severity: "critical" },
  { pattern: /wget.*\|.*sh/i, threat: "Wget piped to shell", severity: "critical" },
  { pattern: /wget.*\|.*bash/i, threat: "Wget piped to bash", severity: "critical" },
  { pattern: /base64\s+-d/i, threat: "Base64 decoding", severity: "medium" },
  { pattern: /certutil.*-decode/i, threat: "Certutil decode", severity: "high" },
  { pattern: /mshta\s+http/i, threat: "MSHTA remote execution", severity: "critical" },
  { pattern: /rundll32/i, threat: "Rundll32 execution", severity: "high" },
  { pattern: /reg\s+add/i, threat: "Registry modification", severity: "high" },
  { pattern: /schtasks.*\/create/i, threat: "Scheduled task creation", severity: "high" }
];

function checkForMaliciousContent(text) {
  const threats = [];
  for (const { pattern, threat, severity } of MALICIOUS_PATTERNS) {
    if (pattern.test(text)) {
      threats.push({ threat, severity, pattern: pattern.toString() });
    }
  }
  return threats;
}

// ================= BADGE MANAGEMENT =================
function updateBadge(tabId, severity) {
  let color, text;
  
  switch(severity) {
    case 'critical':
      color = '#ef4444';
      text = '!';
      break;
    case 'high':
      color = '#f97316';
      text = '⚠';
      break;
    case 'medium':
      color = '#facc15';
      text = '⚠';
      break;
    case 'safe':
      color = '#22c55e';
      text = '✓';
      break;
    default:
      color = '#94a3b8';
      text = '';
  }
  
  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text, tabId });
}

function calculateTabThreatLevel(tabId) {
  const threats = tabThreats[tabId] || [];
  
  if (threats.some(t => t.severity === 'critical')) return 'critical';
  if (threats.some(t => t.severity === 'high')) return 'high';
  if (threats.some(t => t.severity === 'medium')) return 'medium';
  return 'safe';
}

// ================= MESSAGE HANDLERS =================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  
  // Clipboard check
  if (msg.type === "CHECK_CLIPBOARD") {
    if (!clipboardMonitorEnabled) {
      sendResponse({ malicious: false, threats: [] });
      return;
    }
    
    const threats = checkForMaliciousContent(msg.content);
    
    if (threats.length > 0) {
      const threatEntry = {
        timestamp: new Date().toISOString(),
        content: msg.content.substring(0, 200),
        threats: threats,
        url: sender.url || "unknown",
        tabId: sender.tab?.id
      };
      
      threatHistory.unshift(threatEntry);
      if (threatHistory.length > 50) threatHistory.pop();
      chrome.storage.local.set({ threatHistory });
      
      // Track threat for this tab
      const tabId = sender.tab?.id;
      if (tabId) {
        if (!tabThreats[tabId]) tabThreats[tabId] = [];
        tabThreats[tabId].push({
          type: 'clipboard',
          severity: threats[0].severity,
          threat: threats[0].threat,
          timestamp: Date.now()
        });
        
        updateBadge(tabId, calculateTabThreatLevel(tabId));
      }
      
      // Show notification
      chrome.notifications.create({
        type: "basic",
        title: "⚠️ Malicious Command Detected!",
        message: `${threats[0].threat}\n\nDO NOT paste this into your terminal!`,
        priority: 2,
        requireInteraction: true
      });
      
      sendResponse({ malicious: true, threats });
    } else {
      sendResponse({ malicious: false, threats: [] });
    }
    return true;
  }
  
  // Overlay detected
  if (msg.type === "OVERLAY_DETECTED") {
    const tabId = sender.tab?.id;
    if (tabId) {
      if (!tabThreats[tabId]) tabThreats[tabId] = [];
      tabThreats[tabId].push({
        type: 'overlay',
        severity: 'high',
        threat: 'Suspicious overlay detected',
        timestamp: Date.now()
      });
      
      updateBadge(tabId, calculateTabThreatLevel(tabId));
      
      chrome.notifications.create({
        type: "basic",
        title: "⚠️ Suspicious Overlay Detected!",
        message: "This page has a suspicious overlay that may be phishing. Be careful!",
        priority: 2
      });
    }
    sendResponse({ success: true });
    return true;
  }
  
  // Popup spam detected
  if (msg.type === "POPUP_SPAM_DETECTED") {
    const tabId = sender.tab?.id;
    if (tabId) {
      if (!tabThreats[tabId]) tabThreats[tabId] = [];
      tabThreats[tabId].push({
        type: 'popup',
        severity: 'medium',
        threat: 'Popup spam detected',
        timestamp: Date.now()
      });
      
      updateBadge(tabId, calculateTabThreatLevel(tabId));
      
      chrome.notifications.create({
        type: "basic",
        title: "⚠️ Popup Spam Detected!",
        message: "This page is trying to open multiple popups!",
        priority: 1
      });
    }
    sendResponse({ success: true });
    return true;
  }
  
  // Get tab threats
  if (msg.type === "GET_TAB_THREATS") {
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      const threats = tabThreats[tab?.id] || [];
      sendResponse({ threats });
    });
    return true;
  }
  
  // Toggle clipboard monitor
  if (msg.type === "TOGGLE_CLIPBOARD_MONITOR") {
    clipboardMonitorEnabled = msg.enabled;
    chrome.storage.local.set({ clipboardMonitorEnabled });
    sendResponse({ success: true, enabled: clipboardMonitorEnabled });
    return true;
  }
  
  // Get threat history
  if (msg.type === "GET_THREAT_HISTORY") {
    sendResponse({ history: threatHistory });
    return true;
  }
  
  // Clear threat history
  if (msg.type === "CLEAR_THREAT_HISTORY") {
    threatHistory = [];
    chrome.storage.local.set({ threatHistory: [] });
    sendResponse({ success: true });
    return true;
  }
  
  // Get clipboard status
  if (msg.type === "GET_CLIPBOARD_STATUS") {
    chrome.storage.local.get(['clipboardMonitorEnabled'], (result) => {
      sendResponse({ enabled: result.clipboardMonitorEnabled ?? true });
    });
    return true;
  }
  
  // Domain info (simplified - no RDAP for now)
  if (msg.type === "GET_DOMAIN_INFO") {
    sendResponse({
      success: true,
      data: {
        createdDate: null,
        expiresDate: null,
        registrar: null,
        country: null,
        domainAgeDays: null
      }
    });
    return true;
  }
});

// Clear badge when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabThreats[tabId];
  chrome.action.setBadgeText({ text: '', tabId });
});

// Update badge when tab becomes active
chrome.tabs.onActivated.addListener(({ tabId }) => {
  const severity = calculateTabThreatLevel(tabId);
  updateBadge(tabId, severity);
});
