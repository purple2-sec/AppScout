// ... existing code ...

/* ================= ACTIVE THREATS DISPLAY ================= */

function loadActiveThreats() {
  chrome.runtime.sendMessage({ type: "GET_TAB_THREATS" }, (response) => {
    if (response && response.threats) {
      const threatsList = document.getElementById("active-threats-list");
      threatsList.innerHTML = "";
      
      if (response.threats.length === 0) {
        const li = document.createElement("li");
        li.textContent = "✅ No threats detected on this page";
        li.className = "low";
        threatsList.appendChild(li);
      } else {
        response.threats.forEach(threat => {
          const li = document.createElement("li");
          const time = new Date(threat.timestamp).toLocaleTimeString();
          li.innerHTML = `<strong>${time}</strong> - ${threat.threat}`;
          li.className = threat.severity === "critical" ? "high" : threat.severity === "high" ? "medium" : "low";
          threatsList.appendChild(li);
        });
      }
    }
  });
}

// Load active threats when popup opens
loadActiveThreats();

// Refresh every 2 seconds
setInterval(loadActiveThreats, 2000);

// ... rest of existing popup.js code ...
