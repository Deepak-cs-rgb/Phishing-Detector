# PhishGuard Chrome Extension

A powerful Chrome extension that provides real-time protection against phishing attacks and malicious websites using advanced JavaScript-based URL analysis and threat detection.

## Features

- **Real-time Phishing Detection**: Automatically scans websites as you browse
- **Advanced Threat Analysis**: Multi-layered security checks including:
  - Known phishing domain detection
  - Typosquatting analysis
  - SSL certificate validation
  - URL structure analysis
  - Domain reputation checking
- **Instant Blocking**: Prevents access to dangerous sites with detailed warning pages
- **Smart Whitelist**: Add trusted sites to bypass false positives
- **User-Friendly Interface**: Clean popup with statistics and controls
- **Privacy Focused**: All analysis happens locally - no data sent to external servers

## Installation Instructions

### Method 1: Developer Mode (Recommended)

1. **Open Chrome Extensions Page**
   - Type `chrome://extensions/` in your address bar
   - Or go to Chrome Menu → More Tools → Extensions

2. **Enable Developer Mode**
   - Toggle the "Developer mode" switch in the top right corner

3. **Load the Extension**
   - Click "Load unpacked" button
   - Select the `phishguard-extension` folder
   - The PhishGuard icon should appear in your Chrome toolbar

4. **Verify Installation**
   - Click the PhishGuard icon in the toolbar
   - You should see the popup interface with protection status

### Method 2: ZIP Package

1. Download the extension files as a ZIP
2. Extract to a folder on your computer
3. Follow steps 1-3 from Method 1 above

## How It Works

### Background Protection
- Monitors all web navigation in real-time
- Analyzes URLs using multiple security algorithms
- Automatically blocks high-risk sites before they load

### Content Script Analysis
- Scans page content for suspicious patterns
- Shows warning banners for medium-risk sites
- Monitors for dynamic content changes and redirects

### User Controls
- **Enable/Disable**: Toggle protection on/off
- **Whitelist Sites**: Mark trusted sites to bypass warnings
- **Report Phishing**: Help improve detection by reporting false positives
- **View Statistics**: Track blocked threats and scanned sites

## Security Checks Performed

1. **Known Phishing Domains**: Checks against database of confirmed malicious sites
2. **Suspicious Patterns**: Detects IP addresses, excessive subdomains, suspicious TLDs
3. **URL Shorteners**: Identifies potentially dangerous redirect services
4. **Typosquatting**: Compares against legitimate domains for character substitution
5. **SSL Status**: Verifies HTTPS encryption and certificate validity
6. **URL Structure**: Analyzes for malicious encoding and suspicious parameters

## Privacy & Security

- **Local Processing**: All threat analysis happens on your device
- **No Data Collection**: Extension doesn't track or store personal information
- **Minimal Permissions**: Only requests necessary Chrome API access
- **Open Source**: Fully transparent JavaScript implementation

## Configuration

Access settings through the popup interface:

- **Protection Level**: Adjust sensitivity of threat detection
- **Show Warnings**: Control display of warning notifications
- **Block Suspicious**: Automatically block medium-risk sites
- **Statistics**: Enable/disable usage tracking

## Troubleshooting

### Extension Not Loading
- Ensure all files are in the same folder
- Check that manifest.json is present and valid
- Verify Developer mode is enabled in Chrome

### False Positives
- Use the "Trust Site" button in the popup
- Report false positives to help improve detection
- Check whitelist settings if sites are incorrectly blocked

### Performance Issues
- Extension uses minimal resources
- Disable on trusted internal sites if needed
- Check Chrome's task manager for resource usage

## Technical Details

### File Structure
```
phishguard-extension/
├── manifest.json          # Extension configuration
├── background.js          # Background service worker
├── content.js            # Content script for page monitoring
├── phishing-detector.js  # Core threat detection engine
├── storage-manager.js    # Data storage and settings
├── popup.html           # Popup interface HTML
├── popup.js             # Popup functionality
├── popup.css            # Popup styling
├── warning.html         # Blocked site warning page
├── warning.js           # Warning page functionality
├── warning.css          # Warning page styling
└── README.md            # This file
```

### Browser Compatibility
- Chrome 88+ (Manifest V3 support required)
- Chromium-based browsers (Edge, Brave, etc.)

### Permissions Explained
- `activeTab`: Access current tab for analysis
- `tabs`: Monitor navigation events
- `storage`: Save settings and whitelist
- `webNavigation`: Detect page loads and redirects
- `scripting`: Inject content scripts for analysis

## Support

For issues, feature requests, or security reports:
1. Check the troubleshooting section above
2. Review Chrome's extension error logs
3. Test with a fresh Chrome profile
4. Report persistent issues with detailed steps to reproduce

## Version History

### v1.0.0 (Current)
- Initial release with core phishing detection
- Real-time URL analysis and blocking
- User-friendly popup interface
- Comprehensive warning system
- Whitelist and reporting functionality

---

**Important**: This extension provides an additional layer of security but should not be your only protection. Always keep Chrome updated and use reputable antivirus software.