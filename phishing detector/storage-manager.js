// PhishGuard Storage Manager
class StorageManager {
  constructor() {
    this.defaultSettings = {
      enabled: true,
      showWarnings: true,
      blockSuspicious: false,
      checkSubdomains: true,
      scanDelay: 500,
      whitelistedDomains: [],
      customBlacklist: [],
      notificationSound: true,
      autoUpdate: true,
      statisticsEnabled: true
    };
    
    this.defaultLocalData = {
      threatDatabase: null,
      blockedSites: [],
      phishingReports: [],
      scanHistory: [],
      lastDatabaseUpdate: 0
    };
  }

  // Initialize storage with default values
  async initialize() {
    try {
      // Initialize sync storage (user settings)
      const syncData = await chrome.storage.sync.get();
      const syncDefaults = { ...this.defaultSettings };
      
      // Only set defaults for missing keys
      for (const [key, defaultValue] of Object.entries(syncDefaults)) {
        if (!(key in syncData)) {
          await chrome.storage.sync.set({ [key]: defaultValue });
        }
      }

      // Initialize local storage (temporary data)
      const localData = await chrome.storage.local.get();
      const localDefaults = { ...this.defaultLocalData };
      
      for (const [key, defaultValue] of Object.entries(localDefaults)) {
        if (!(key in localData)) {
          await chrome.storage.local.set({ [key]: defaultValue });
        }
      }

      console.log('Storage initialized successfully');
      return true;
    } catch (error) {
      console.error('Failed to initialize storage:', error);
      return false;
    }
  }

  // Settings Management
  async getSettings() {
    try {
      const settings = await chrome.storage.sync.get(this.defaultSettings);
      return settings;
    } catch (error) {
      console.error('Failed to get settings:', error);
      return this.defaultSettings;
    }
  }

  async updateSetting(key, value) {
    try {
      await chrome.storage.sync.set({ [key]: value });
      console.log(`Setting updated: ${key} = ${value}`);
      return true;
    } catch (error) {
      console.error(`Failed to update setting ${key}:`, error);
      return false;
    }
  }

  async updateSettings(settings) {
    try {
      await chrome.storage.sync.set(settings);
      console.log('Settings updated:', Object.keys(settings));
      return true;
    } catch (error) {
      console.error('Failed to update settings:', error);
      return false;
    }
  }

  // Whitelist Management
  async getWhitelist() {
    try {
      const data = await chrome.storage.sync.get(['whitelistedDomains']);
      return data.whitelistedDomains || [];
    } catch (error) {
      console.error('Failed to get whitelist:', error);
      return [];
    }
  }

  async addToWhitelist(domain) {
    try {
      const whitelist = await this.getWhitelist();
      
      if (!whitelist.includes(domain)) {
        whitelist.push(domain);
        await chrome.storage.sync.set({ whitelistedDomains: whitelist });
        console.log(`Added to whitelist: ${domain}`);
      }
      
      return true;
    } catch (error) {
      console.error(`Failed to add ${domain} to whitelist:`, error);
      return false;
    }
  }

  async removeFromWhitelist(domain) {
    try {
      const whitelist = await this.getWhitelist();
      const updatedWhitelist = whitelist.filter(d => d !== domain);
      
      await chrome.storage.sync.set({ whitelistedDomains: updatedWhitelist });
      console.log(`Removed from whitelist: ${domain}`);
      
      return true;
    } catch (error) {
      console.error(`Failed to remove ${domain} from whitelist:`, error);
      return false;
    }
  }

  async isWhitelisted(domain) {
    try {
      const whitelist = await this.getWhitelist();
      return whitelist.some(whitelistedDomain => {
        return domain === whitelistedDomain || 
               domain.endsWith(`.${whitelistedDomain}`);
      });
    } catch (error) {
      console.error('Failed to check whitelist:', error);
      return false;
    }
  }

  // Blacklist Management
  async getBlacklist() {
    try {
      const data = await chrome.storage.sync.get(['customBlacklist']);
      return data.customBlacklist || [];
    } catch (error) {
      console.error('Failed to get blacklist:', error);
      return [];
    }
  }

  async addToBlacklist(domain) {
    try {
      const blacklist = await this.getBlacklist();
      
      if (!blacklist.includes(domain)) {
        blacklist.push(domain);
        await chrome.storage.sync.set({ customBlacklist: blacklist });
        console.log(`Added to blacklist: ${domain}`);
      }
      
      return true;
    } catch (error) {
      console.error(`Failed to add ${domain} to blacklist:`, error);
      return false;
    }
  }

  async removeFromBlacklist(domain) {
    try {
      const blacklist = await this.getBlacklist();
      const updatedBlacklist = blacklist.filter(d => d !== domain);
      
      await chrome.storage.sync.set({ customBlacklist: updatedBlacklist });
      console.log(`Removed from blacklist: ${domain}`);
      
      return true;
    } catch (error) {
      console.error(`Failed to remove ${domain} from blacklist:`, error);
      return false;
    }
  }

  // Threat Database Management
  async getThreatDatabase() {
    try {
      const data = await chrome.storage.local.get(['threatDatabase']);
      return data.threatDatabase || null;
    } catch (error) {
      console.error('Failed to get threat database:', error);
      return null;
    }
  }

  async updateThreatDatabase(database) {
    try {
      database.lastUpdated = Date.now();
      await chrome.storage.local.set({ 
        threatDatabase: database,
        lastDatabaseUpdate: database.lastUpdated
      });
      
      console.log('Threat database updated');
      return true;
    } catch (error) {
      console.error('Failed to update threat database:', error);
      return false;
    }
  }

  // Statistics and History
  async getStatistics() {
    try {
      const localData = await chrome.storage.local.get([
        'blockedSites', 
        'phishingReports', 
        'scanHistory'
      ]);
      
      const syncData = await chrome.storage.sync.get(['whitelistedDomains']);
      
      return {
        blockedCount: (localData.blockedSites || []).length,
        reportsCount: (localData.phishingReports || []).length,
        scansCount: (localData.scanHistory || []).length,
        whitelistCount: (syncData.whitelistedDomains || []).length,
        lastUpdate: localData.lastDatabaseUpdate || 0
      };
    } catch (error) {
      console.error('Failed to get statistics:', error);
      return {
        blockedCount: 0,
        reportsCount: 0,
        scansCount: 0,
        whitelistCount: 0,
        lastUpdate: 0
      };
    }
  }

  async addBlockedSite(url, reason, timestamp = Date.now()) {
    try {
      const data = await chrome.storage.local.get(['blockedSites']);
      const blockedSites = data.blockedSites || [];
      
      // Add new blocked site
      blockedSites.push({
        url,
        reason,
        timestamp,
        domain: new URL(url).hostname
      });
      
      // Keep only last 500 entries
      if (blockedSites.length > 500) {
        blockedSites.splice(0, blockedSites.length - 500);
      }
      
      await chrome.storage.local.set({ blockedSites });
      console.log(`Blocked site recorded: ${url}`);
      
      return true;
    } catch (error) {
      console.error('Failed to record blocked site:', error);
      return false;
    }
  }

  async addPhishingReport(url, details, timestamp = Date.now()) {
    try {
      const data = await chrome.storage.local.get(['phishingReports']);
      const reports = data.phishingReports || [];
      
      // Add new report
      reports.push({
        url,
        details,
        timestamp,
        domain: new URL(url).hostname,
        reported: false // Flag for actual reporting to external services
      });
      
      // Keep only last 200 reports
      if (reports.length > 200) {
        reports.splice(0, reports.length - 200);
      }
      
      await chrome.storage.local.set({ phishingReports: reports });
      console.log(`Phishing report recorded: ${url}`);
      
      return true;
    } catch (error) {
      console.error('Failed to record phishing report:', error);
      return false;
    }
  }

  async addScanHistory(url, riskLevel, details, timestamp = Date.now()) {
    try {
      const settings = await this.getSettings();
      if (!settings.statisticsEnabled) return true; // Skip if disabled
      
      const data = await chrome.storage.local.get(['scanHistory']);
      const history = data.scanHistory || [];
      
      // Add new scan record
      history.push({
        url,
        riskLevel,
        details,
        timestamp,
        domain: new URL(url).hostname
      });
      
      // Keep only last 1000 scans
      if (history.length > 1000) {
        history.splice(0, history.length - 1000);
      }
      
      await chrome.storage.local.set({ scanHistory: history });
      
      return true;
    } catch (error) {
      console.error('Failed to record scan history:', error);
      return false;
    }
  }

  // Data Export/Import
  async exportData() {
    try {
      const syncData = await chrome.storage.sync.get();
      const localData = await chrome.storage.local.get();
      
      return {
        version: '1.0.0',
        exportDate: new Date().toISOString(),
        settings: syncData,
        statistics: {
          blockedSites: localData.blockedSites || [],
          phishingReports: localData.phishingReports || [],
          scanHistory: localData.scanHistory || []
        }
      };
    } catch (error) {
      console.error('Failed to export data:', error);
      throw error;
    }
  }

  async importData(data) {
    try {
      if (!data.version || !data.settings) {
        throw new Error('Invalid import data format');
      }
      
      // Import settings (excluding sensitive data)
      const safeSettings = { ...data.settings };
      delete safeSettings.threatDatabase; // Don't import threat database
      
      await chrome.storage.sync.set(safeSettings);
      
      // Import statistics if available
      if (data.statistics) {
        const localData = {};
        if (data.statistics.blockedSites) {
          localData.blockedSites = data.statistics.blockedSites;
        }
        if (data.statistics.phishingReports) {
          localData.phishingReports = data.statistics.phishingReports;
        }
        if (data.statistics.scanHistory) {
          localData.scanHistory = data.statistics.scanHistory;
        }
        
        await chrome.storage.local.set(localData);
      }
      
      console.log('Data imported successfully');
      return true;
    } catch (error) {
      console.error('Failed to import data:', error);
      throw error;
    }
  }

  // Cleanup and Maintenance
  async cleanupOldData() {
    try {
      const data = await chrome.storage.local.get([
        'scanHistory', 
        'blockedSites', 
        'phishingReports'
      ]);
      
      const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
      let cleaned = false;
      
      // Clean old scan history
      if (data.scanHistory) {
        const filtered = data.scanHistory.filter(item => item.timestamp > thirtyDaysAgo);
        if (filtered.length !== data.scanHistory.length) {
          await chrome.storage.local.set({ scanHistory: filtered });
          cleaned = true;
        }
      }
      
      // Clean old blocked sites (keep for longer - 90 days)
      const ninetyDaysAgo = Date.now() - (90 * 24 * 60 * 60 * 1000);
      if (data.blockedSites) {
        const filtered = data.blockedSites.filter(item => item.timestamp > ninetyDaysAgo);
        if (filtered.length !== data.blockedSites.length) {
          await chrome.storage.local.set({ blockedSites: filtered });
          cleaned = true;
        }
      }
      
      if (cleaned) {
        console.log('Old data cleaned up');
      }
      
      return true;
    } catch (error) {
      console.error('Failed to cleanup old data:', error);
      return false;
    }
  }

  // Storage usage monitoring
  async getStorageUsage() {
    try {
      const syncUsage = await chrome.storage.sync.getBytesInUse();
      const localUsage = await chrome.storage.local.getBytesInUse();
      
      return {
        sync: {
          used: syncUsage,
          quota: chrome.storage.sync.QUOTA_BYTES,
          percentage: (syncUsage / chrome.storage.sync.QUOTA_BYTES) * 100
        },
        local: {
          used: localUsage,
          quota: chrome.storage.local.QUOTA_BYTES,
          percentage: (localUsage / chrome.storage.local.QUOTA_BYTES) * 100
        }
      };
    } catch (error) {
      console.error('Failed to get storage usage:', error);
      return null;
    }
  }
}

// Make StorageManager available globally
if (typeof window !== 'undefined') {
  window.StorageManager = StorageManager;
}

// Export for use in background script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = StorageManager;
}
