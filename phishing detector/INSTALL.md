# PhishGuard Chrome Extension - Installation Guide

## Quick Installation Steps

### Step 1: Download Extension Files
The extension files are located in the `phishguard-extension` folder. All necessary files are included:
- manifest.json (extension configuration)
- JavaScript files (detection engine, popup, background scripts)
- HTML/CSS files (user interface)

### Step 2: Open Chrome Extensions
1. Open Google Chrome
2. Type `chrome://extensions/` in the address bar and press Enter
3. Alternatively: Chrome Menu (⋮) → More Tools → Extensions

### Step 3: Enable Developer Mode
1. In the top-right corner of the Extensions page, toggle "Developer mode" ON
2. You should now see additional buttons: "Load unpacked", "Pack extension", "Update"

### Step 4: Load the Extension
1. Click the "Load unpacked" button
2. Navigate to and select the `phishguard-extension` folder
3. Click "Select Folder" (Windows) or "Open" (Mac/Linux)

### Step 5: Verify Installation
1. Look for the PhishGuard icon in your Chrome toolbar (shield icon)
2. If you don't see it, click the puzzle piece icon and pin PhishGuard
3. Click the PhishGuard icon to open the popup interface

## Expected Results

After successful installation:
- PhishGuard icon appears in Chrome toolbar
- Popup shows "Protected" status with green indicator
- Extension will automatically analyze websites as you browse
- High-risk sites will be blocked with a warning page
- Medium-risk sites will show warning banners

## Troubleshooting

### "Manifest file is missing or unreadable"
- Ensure you selected the `phishguard-extension` folder (not individual files)
- Verify the manifest.json file exists in the selected folder
- Check that all extension files are in the same directory

### Extension not appearing
- Refresh the Extensions page (F5)
- Check that Developer mode is enabled
- Look for error messages in red text on the Extensions page

### Permission errors
- The extension requires several permissions for security analysis
- These are necessary for the phishing detection features
- All permissions are clearly listed in the manifest file

## File Verification

Your `phishguard-extension` folder should contain these files:
```
✓ manifest.json
✓ background.js
✓ content.js
✓ phishing-detector.js
✓ storage-manager.js
✓ popup.html
✓ popup.js
✓ popup.css
✓ warning.html
✓ warning.js
✓ warning.css
✓ README.md
```

If any files are missing, ensure you copied the complete folder contents.

## Testing the Extension

1. **Open the popup**: Click the PhishGuard icon
2. **Check a safe site**: Visit a legitimate website (e.g., google.com)
3. **Test detection**: The extension analyzes URLs automatically
4. **View statistics**: Numbers should update as you browse

## Security Notice

This extension provides additional protection but:
- Keep Chrome updated to the latest version
- Use alongside standard security practices
- Report any false positives to improve detection
- Review the whitelist feature for trusted sites

## Support

If you encounter issues:
1. Check Chrome's Developer Console for errors
2. Verify all files are present and unmodified
3. Try disabling other extensions temporarily
4. Test in an incognito window to isolate conflicts