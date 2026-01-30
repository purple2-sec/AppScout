// ================= BACKGROUND SERVICE WORKER =================
// Handles clipboard monitoring and malicious command detection

let clipboardMonitorEnabled = true;
let threatHistory = [];

// Initialize storage on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    clipboardMonitorEnabled: true,
    threatHistory: [],
    autoBlockEnabled: false
  });
  console.log("AppScout ClickFix Protection enabled");
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

// ================= MALICIOUS PATTERN DETECTION =================

const MALICIOUS_PATTERNS = [
  // PowerShell commands
  { pattern: /powershell/i, threat: "PowerShell execution detected", severity: "high" },
  { pattern: /pwsh/i, threat: "PowerShell Core execution detected", severity: "high" },
  { pattern: /invoke-expression/i, threat: "PowerShell code injection (Invoke-Expression)", severity: "critical" },
  { pattern: /\biex\b/i, threat: "PowerShell IEX command (code execution)", severity: "critical" },
  { pattern: /invoke-webrequest/i, threat: "PowerShell web request (potential download)", severity: "high" },
  { pattern: /downloadstring/i, threat: "PowerShell download command", severity: "critical" },
  { pattern: /-encodedcommand/i, threat: "Encoded PowerShell command", severity: "critical" },
  { pattern: /-enc\s/i, threat: "Encoded PowerShell command", severity: "critical" },
  
  // Shell commands piped to execution
  { pattern: /curl.*\|.*sh/i, threat: "Curl piped to shell execution", severity: "critical" },
  { pattern: /curl.*\|.*bash/i, threat: "Curl piped to bash execution", severity: "critical" },
  { pattern: /wget.*\|.*sh/i, threat: "Wget piped to shell execution", severity: "critical" },
  { pattern: /wget.*\|.*bash/i, threat: "Wget piped to bash execution", severity: "critical" },
  
  // Base64 decoding (common in attacks)
  { pattern: /base64\s+-d/i, threat: "Base64 decoding detected", severity: "medium" },
  { pattern: /frombase64string/i, threat: "Base64 string conversion", severity: "medium" },
  
  // Windows utilities abuse
  { pattern: /certutil.*-decode/i, threat: "Certutil decode (malware technique)", severity: "high" },
  { pattern: /mshta\s+http/i, threat: "MSHTA remote execution", severity: "critical" },
  { pattern: /rundll32/i, threat: "Rundll32 execution (suspicious)", severity: "high" },
  { pattern: /regsvr32.*\/s.*\/i/i, threat: "Regsvr32 silent install", severity: "high" },
  
  // Registry modifications
  { pattern: /reg\s+add/i, threat: "Registry modification command", severity: "high" },
  { pattern: /set-itemproperty.*hkcu/i, threat: "Registry modification (PowerShell)", severity: "high" },
  
  // Scheduled tasks
  { pattern: /schtasks.*\/create/i, threat: "Scheduled task creation", severity: "high" },
  { pattern: /new-scheduledtask/i, threat: "PowerShell scheduled task", severity: "high" },
  
  // Privilege escalation
  { pattern: /runas.*\/user/i, threat: "Privilege escalation attempt", severity: "high" },
  { pattern: /start-process.*-verb\s+runas/i, threat: "PowerShell privilege escalation", severity: "high" },
  
  // Command chaining (multiple commands)
  { pattern: /&&.*&&/i, threat: "Multiple chained commands", severity: "medium" },
  { pattern: /;.*;.*;/i, threat: "Multiple chained commands", severity: "medium" },
  
  // Suspicious downloads
  { pattern: /\.exe.*http/i, threat: "Executable download detected", severity: "critical" },
  { pattern: /\.dll.*http/i, threat: "DLL download detected", severity: "high" },
  { pattern: /\.scr.*http/i, threat: "Screensaver download (potential malware)", severity: "high" },
  { pattern: /\.vbs.*http/i, threat: "VBScript download detected", severity: "high" }
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

// ================= MESSAGE HANDLERS =================

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Check clipboard content
  if (msg.type === "CHECK_CLIPBOARD") {
    if (!clipboardMonitorEnabled) {
      sendResponse({ malicious: false, threats: [] });
      return;
    }
    
    const threats = checkForMaliciousContent(msg.content);
    
    if (threats.length > 0) {
      // Add to threat history
      const threatEntry = {
        timestamp: new Date().toISOString(),
        content: msg.content.substring(0, 200), // Store first 200 chars
        threats: threats,
        url: sender.url || "unknown"
      };
      
      threatHistory.unshift(threatEntry);
      if (threatHistory.length > 50) threatHistory.pop(); // Keep last 50
      
      // Save to storage
      chrome.storage.local.set({ threatHistory });
      
      // Show notification
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icon128.png",
        title: "⚠️ Malicious Command Detected!",
        message: `${threats[0].threat}\n\nDO NOT paste this into your terminal!`,
        priority: 2
      });
      
      sendResponse({ malicious: true, threats });
    } else {
      sendResponse({ malicious: false, threats: [] });
    }
    
    return true; // Keep channel open for async response
  }
  
  // Toggle clipboard monitoring
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
});

// Listen for clipboard monitor status requests
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_CLIPBOARD_STATUS") {
    chrome.storage.local.get(['clipboardMonitorEnabled'], (result) => {
      sendResponse({ enabled: result.clipboardMonitorEnabled ?? true });
    });
    return true;
  }
});
