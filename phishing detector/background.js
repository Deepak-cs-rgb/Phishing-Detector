// PhishGuard Background Service Worker
// Note: In Manifest V3, we use importScripts instead of ES6 imports
// importScripts('storage-manager.js', 'phishing-detector.js');

class PhishGuardBackground {
  constructor() {
    this.init();
  }

  async init() {
    // Initialize storage on extension startup
    await this.initializeStorage();
    
    // Set up event listeners
    this.setupEventListeners();
    
    // Set up periodic updates for threat database
    this.setupPeriodicUpdates();
    
    console.log('PhishGuard Background Service Worker initialized');
  }

  async initializeStorage() {
    try {
      const settings = await chrome.storage.sync.get({
        enabled: true,
        showWarnings: true,
        blockSuspicious: false,
        checkSubdomains: true,
        scanDelay: 500,
        whitelistedDomains: [],
        customBlacklist: []
      });
      
      // Initialize with default settings if not present
      await chrome.storage.sync.set(settings);
      
      // Initialize threat database if empty
      const threatDb = await chrome.storage.local.get('threatDatabase');
      if (!threatDb.threatDatabase) {
        await this.updateThreatDatabase();
      }
    } catch (error) {
      console.error('Failed to initialize storage:', error);
    }
  }

  setupEventListeners() {
    // Listen for navigation events
    chrome.webNavigation.onBeforeNavigate.addListener(
      this.handleNavigation.bind(this),
      { url: [{ schemes: ['http', 'https'] }] }
    );

    // Listen for tab updates
    chrome.tabs.onUpdated.addListener(this.handleTabUpdate.bind(this));

    // Listen for messages from content scripts
    chrome.runtime.onMessage.addListener(this.handleMessage.bind(this));

    // Listen for extension icon clicks
    chrome.action.onClicked.addListener(this.handleIconClick.bind(this));
  }

  setupPeriodicUpdates() {
    // Update threat database every 6 hours
    chrome.alarms.create('updateThreatDb', { 
      delayInMinutes: 1, 
      periodInMinutes: 360 
    });
    
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === 'updateThreatDb') {
        this.updateThreatDatabase();
      }
    });
  }

  async handleNavigation(details) {
    if (details.frameId !== 0) return; // Only check main frame

    const settings = await chrome.storage.sync.get(['enabled']);
    if (!settings.enabled) return;

    try {
      const url = new URL(details.url);
      const riskLevel = await this.analyzeUrl(url);
      
      if (riskLevel === 'high') {
        // Block immediately for high-risk sites
        chrome.tabs.update(details.tabId, {
          url: chrome.runtime.getURL('warning.html') + '?blocked=' + encodeURIComponent(details.url)
        });
      }
    } catch (error) {
      console.error('Navigation analysis failed:', error);
    }
  }

  async handleTabUpdate(tabId, changeInfo, tab) {
    if (changeInfo.status !== 'complete' || !tab.url) return;
    
    const settings = await chrome.storage.sync.get(['enabled']);
    if (!settings.enabled) return;

    try {
      const url = new URL(tab.url);
      if (url.protocol !== 'http:' && url.protocol !== 'https:') return;

      const riskLevel = await this.analyzeUrl(url);
      
      // Update extension badge
      await this.updateBadge(tabId, riskLevel);
      
      // Send risk assessment to content script
      chrome.tabs.sendMessage(tabId, {
        type: 'RISK_ASSESSMENT',
        riskLevel: riskLevel,
        url: tab.url
      }).catch(() => {}); // Ignore errors if content script not ready
      
    } catch (error) {
      console.error('Tab update analysis failed:', error);
    }
  }

  async handleMessage(message, sender, sendResponse) {
    try {
      switch (message.type) {
        case 'ANALYZE_URL':
          const riskLevel = await this.analyzeUrl(new URL(message.url));
          sendResponse({ riskLevel });
          break;
          
        case 'ADD_TO_WHITELIST':
          await this.addToWhitelist(message.domain);
          sendResponse({ success: true });
          break;
          
        case 'REPORT_PHISHING':
          await this.reportPhishing(message.url, message.details);
          sendResponse({ success: true });
          break;
          
        case 'GET_STATISTICS':
          const stats = await this.getStatistics();
          sendResponse(stats);
          break;
          
        default:
          sendResponse({ error: 'Unknown message type' });
      }
    } catch (error) {
      console.error('Message handling failed:', error);
      sendResponse({ error: error.message });
    }
    
    return true; // Keep message channel open for async response
  }

  async handleIconClick(tab) {
    // Open popup - handled by default popup behavior
  }

  async analyzeUrl(url) {
    try {
      // Basic threat analysis (simplified version for background script)
      if (typeof url === 'string') {
        url = new URL(url);
      }
      
      const hostname = url.hostname.toLowerCase();
      
      // Check against basic threat patterns
      const threats = [
        // Known phishing patterns
        /paypal.*secure/i,
        /amazon.*security/i,
        /google.*verification/i,
        /microsoft.*security/i,
        /apple.*support/i,
        /facebook.*security/i
      ];
      
      // Check for IP addresses
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
        return 'high';
      }
      
      // Check for suspicious patterns
      for (const threat of threats) {
        if (threat.test(hostname)) {
          return 'high';
        }
      }
      
      // Check for excessive subdomains
      if (hostname.split('.').length > 4) {
        return 'medium';
      }
      
      // Check for suspicious TLDs
      const suspiciousTlds = ['.tk', '.ml', '.cf', '.ga'];
      if (suspiciousTlds.some(tld => hostname.endsWith(tld))) {
        return 'medium';
      }
      
      return 'safe';
    } catch (error) {
      console.error('URL analysis failed:', error);
      return 'unknown';
    }
  }

  async updateBadge(tabId, riskLevel) {
    let badgeText = '';
    let badgeColor = '#2563eb'; // blue

    switch (riskLevel) {
      case 'high':
        badgeText = '!';
        badgeColor = '#dc2626'; // red
        break;
      case 'medium':
        badgeText = '?';
        badgeColor = '#f59e0b'; // amber
        break;
      case 'low':
      case 'safe':
        badgeText = '';
        badgeColor = '#16a34a'; // green
        break;
    }

    await chrome.action.setBadgeText({ text: badgeText, tabId });
    await chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });
  }

  async updateThreatDatabase() {
    try {
      // In a real implementation, this would fetch from threat intelligence APIs
      // For now, we'll use a basic hardcoded list of known patterns
      const threatDatabase = {
        phishingDomains: [
          // Common phishing domain patterns
          'paypal-secure.com',
          'amazon-security.com',
          'google-verification.com',
          'microsoft-security.net',
          'apple-support.com',
          'facebook-security.org'
        ],
        suspiciousPatterns: [
          /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, // IP addresses
          /[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.(tk|ml|cf|ga)$/i, // Free domains with dashes
          /[a-z]{20,}\.(com|net|org)$/i, // Very long domain names
        ],
        urlShorteners: [
          'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
          'is.gd', 'buff.ly', 'adf.ly', 'short.link'
        ],
        lastUpdated: Date.now()
      };
      
      await chrome.storage.local.set({ threatDatabase });
      console.log('Threat database updated');
      
    } catch (error) {
      console.error('Failed to update threat database:', error);
    }
  }

  async addToWhitelist(domain) {
    const settings = await chrome.storage.sync.get(['whitelistedDomains']);
    const whitelist = settings.whitelistedDomains || [];
    
    if (!whitelist.includes(domain)) {
      whitelist.push(domain);
      await chrome.storage.sync.set({ whitelistedDomains: whitelist });
    }
  }

  async reportPhishing(url, details) {
    // In a real implementation, this would report to threat intelligence services
    console.log('Phishing report:', { url, details, timestamp: Date.now() });
    
    // Store locally for statistics
    const reports = await chrome.storage.local.get(['phishingReports']);
    const reportList = reports.phishingReports || [];
    reportList.push({
      url,
      details,
      timestamp: Date.now()
    });
    
    // Keep only last 100 reports
    if (reportList.length > 100) {
      reportList.splice(0, reportList.length - 100);
    }
    
    await chrome.storage.local.set({ phishingReports: reportList });
  }

  async getStatistics() {
    const local = await chrome.storage.local.get(['phishingReports', 'blockedSites']);
    const sync = await chrome.storage.sync.get(['whitelistedDomains']);
    
    return {
      reportsCount: (local.phishingReports || []).length,
      blockedCount: (local.blockedSites || []).length,
      whitelistCount: (sync.whitelistedDomains || []).length,
      lastUpdate: local.threatDatabase?.lastUpdated || 0
    };
  }
}

// Initialize background service worker
new PhishGuardBackground();
