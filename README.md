# AppScout

## AppScout v2.0.0 - Release Notes
### Major Release: ClickFix Attack Protection
Release Date: January 30, 2026
Version: 2.0.0
Previous Version: 1.1

## What's New
### ClickFix Attack Protection
AppScout now includes comprehensive protection against ClickFix attacks - a dangerous social engineering technique where attackers trick users into copying and executing malicious commands in their terminal or PowerShell.

 ## Key Features
1. ### Real-Time Clipboard Monitoring
📋 Automatically scans clipboard content when you copy text
🔍 Detects 30+ malicious command patterns including:
PowerShell execution commands (powershell, iex, Invoke-Expression)
Shell injection attacks (curl | sh, wget | bash)
Encoded payloads (Base64 commands, -encodedcommand)
Windows utility abuse (certutil, mshta, rundll32)
Registry modifications and scheduled tasks
Privilege escalation attempts
⚡ Instant on-page warning overlays when threats are detected
🔔 Desktop notifications for critical threats
📊 Threat history tracking (stores last 50 detections)
2. One-Click Permission Blocking
🛡️ Block buttons next to each risky permission - no more navigating to Chrome settings!
🚀 "Block All Risky Permissions" button for instant protection
✅ Real-time UI updates after blocking
🎯 Automatic exposure score recalculation
3. Quick Actions Dashboard
🎛️ Clipboard Monitor Toggle - enable/disable monitoring on the fly
🔴 Block All Button - one click to block all recommended permissions
📈 Clean, intuitive controls for non-technical users
4. Enhanced Threat Intelligence
📜 Clipboard Threats Section showing:
Number of threats detected (badge counter)
Recent threat history with timestamps
Threat severity levels (Critical, High, Medium)
Clear history option
🎨 Color-coded threat indicators (Red = Critical, Yellow = Medium, Green = Safe)
5. Improved Security Advisories
New ClickFix-specific warnings:

⚠️ "ClickFix attacks trick users into running malicious commands"
⚠️ "Never paste commands from untrusted websites into your terminal"
⚠️ "Clipboard monitoring helps detect malicious PowerShell/bash commands"
🔧 Technical Improvements
New Components
background.js - Service worker for clipboard monitoring and threat detection
Enhanced content.js with real-time clipboard event listeners
Updated manifest.json with new permissions
New Permissions
clipboardRead - Required for clipboard monitoring
clipboardWrite - Allows clearing malicious clipboard content
notifications - Desktop alerts for threats
storage - Persist user preferences and threat history
activeTab - Improved tab interaction
host_permissions: <all_urls> - Enhanced cross-site protection
Architecture Changes
✅ Manifest V3 compliance
✅ Service Worker implementation (replaces background pages)
✅ Improved content script injection (run_at: "document_start")
✅ Chrome Storage API integration
🎨 UI/UX Enhancements
Visual Improvements
🎨 Modern gradient backgrounds
💎 Enhanced color scheme with better contrast
📐 Improved spacing and typography
🖱️ Hover effects and smooth transitions on buttons
📱 Responsive layout (420px width, optimized for popup)
New UI Elements
Toggle switches with smooth animations
Gradient action buttons with hover effects
Threat counter badges
Scrollable lists with custom scrollbars
Warning overlays with auto-dismiss
Accessibility
Clear visual hierarchy
Color-coded risk levels
Non-technical language in warnings
One-click actions for common tasks
## Security Enhancements
Malicious Pattern Detection
AppScout can now detect:

PowerShell Attacks: powershell, pwsh, iex, Invoke-Expression, -encodedcommand
Shell Injection: curl | sh, wget | bash, command chaining
Windows Exploits: certutil -decode, mshta, rundll32, regsvr32
Persistence Mechanisms: Scheduled tasks, registry modifications
Privilege Escalation: runas, UAC bypass techniques
Malware Downloads: .exe, .dll, .scr, .vbs downloads
Threat Response
Immediate visual warnings (on-page overlay)
Desktop notifications
Option to clear clipboard instantly
Threat logging for security analysis
## Installation & Upgrade
New Installation
Download AppScout v2.0.0
Navigate to chrome://extensions/
Enable "Developer mode"
Click "Load unpacked"
Select the AppScout folder
Grant requested permissions
Upgrading from v1.1
Important: Backup your settings (if any)
Remove the old version
Install v2.0.0 following the steps above
New permissions will be requested - these are required for clipboard monitoring
⚙️ Configuration
User Preferences
Clipboard Monitoring: Toggle on/off from the popup
Notifications: Managed through browser settings
Threat History: Automatically saved, can be cleared manually
Default Settings
✅ Clipboard monitoring: Enabled
✅ Desktop notifications: Enabled
✅ Threat history: Enabled (max 50 entries)
🐛 Bug Fixes & Performance
✅ Fixed permission detection for Edge/Brave browsers
✅ Improved clipboard read performance (< 50ms)
✅ Optimized threat pattern matching
✅ Fixed UI overflow issues on smaller screens
✅ Enhanced error handling for clipboard operations
🔮 What's Coming Next (v2.1 Roadmap)
🌐 Multi-language support
🤖 AI-powered threat detection
📊 Detailed security reports
🔗 Integration with security databases
⚙️ Custom pattern definitions
📱 Firefox and Safari support
📚 Documentation & Support
GitHub Repository: w3shinew/AppScout
Issue Tracker: Report bugs or request features
Documentation: See README.md for detailed usage instructions
🙏 Acknowledgments
Special thanks to:
@slvignesh05 @sachin9551
Security researchers identifying ClickFix attack vectors
Community contributors and testers
Users providing valuable feedback
⚠️ ## Important Notes
### Privacy & Data
✅ All processing happens locally - clipboard data is never sent to external servers
✅ Threat history is stored locally in browser storage only
✅ No telemetry or tracking
### Compatibility
✅ Chrome 88+
✅ Edge 88+
✅ Brave (latest)
✅ Chromium-based browsers
### Known Limitations
⚠️ Clipboard monitoring requires clipboardRead permission
⚠️ Some enterprise environments may restrict clipboard access
⚠️ Does not work on chrome:// or edge:// internal pages
### Changelog Summary
Code
```
v2.0.0 (2026-01-30)
-------------------
+ Added real-time clipboard monitoring
+ Added malicious command detection (30+ patterns)
+ Added one-click permission blocking buttons
+ Added "Block All Risky Permissions" feature
+ Added clipboard monitor toggle
+ Added threat history tracking
+ Added on-page warning overlays
+ Added desktop notifications for threats
+ Enhanced UI with modern design
+ Updated manifest to v3 specifications
+ Added background service worker
+ Added Chrome Storage API integration
+ Improved security advisories with ClickFix warnings
+ Enhanced exposure score calculations
* Updated version to 2.0.0
* Improved performance and error handling
```
### Get Started
Ready to protect yourself from ClickFix attacks? Update to AppScout v2.0.0 today!

Stay safe, stay secure! 🛡️

### License
MIT License - See LICENSE file for details
