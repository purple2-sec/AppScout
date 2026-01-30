// ================= WHOIS / DOMAIN INFO LOOKUP =================

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // ... existing message handlers ...
  
  // Get domain WHOIS info
  if (msg.type === "GET_DOMAIN_INFO") {
    fetchWhoisData(msg.domain).then(data => {
      sendResponse({ success: true, data });
    }).catch(error => {
      console.error("WHOIS lookup error:", error);
      sendResponse({ success: false, error: error.message });
    });
    return true; // Keep channel open for async response
  }
});

async function fetchWhoisData(domain) {
  try {
    // Using RDAP (Registration Data Access Protocol) - Free and public
    const response = await fetch(`https://rdap.org/domain/${domain}`);
    
    if (!response.ok) {
      throw new Error("WHOIS lookup failed");
    }
    
    const data = await response.json();
    
    // Parse RDAP response
    const createdDate = data.events?.find(e => e.eventAction === "registration")?.eventDate || null;
    const expiresDate = data.events?.find(e => e.eventAction === "expiration")?.eventDate || null;
    const updatedDate = data.events?.find(e => e.eventAction === "last changed")?.eventDate || null;
    
    // Calculate domain age in days
    let domainAgeDays = null;
    if (createdDate) {
      const created = new Date(createdDate);
      const now = new Date();
      domainAgeDays = Math.floor((now - created) / (1000 * 60 * 60 * 24));
    }
    
    // Extract registrar and country
    const registrar = data.entities?.find(e => e.roles?.includes("registrar"))?.vcardArray?.[1]?.find(v => v[0] === "fn")?.[3] || "Unknown";
    const country = data.entities?.[0]?.vcardArray?.[1]?.find(v => v[0] === "adr")?.[3]?.cc || "Unknown";
    
    return {
      createdDate: createdDate ? new Date(createdDate).toLocaleDateString() : null,
      expiresDate: expiresDate ? new Date(expiresDate).toLocaleDateString() : null,
      updatedDate: updatedDate ? new Date(updatedDate).toLocaleDateString() : null,
      registrar: registrar,
      country: country,
      domainAgeDays: domainAgeDays
    };
    
  } catch (error) {
    console.error("RDAP lookup failed, trying alternative...", error);
    
    // Fallback: Return null data if RDAP fails
    return {
      createdDate: null,
      expiresDate: null,
      updatedDate: null,
      registrar: null,
      country: null,
      domainAgeDays: null
    };
  }
}
