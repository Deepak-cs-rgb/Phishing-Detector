// PhishGuard Popup Script
class PhishGuardPopup {
  constructor() {
    this.currentTab = null;
    this.init();
  }

  async init() {
    try {
      // Get current tab
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      this.currentTab = tabs[0];

      await this.loadSettings();
      await this.loadCurrentSiteStatus();
      await this.loadStatistics();
      this.setupEventListeners();
      
      // Hide loading overlay
      document.getElementById('loadingOverlay').style.display = 'none';
    } catch (error) {
      console.error('Popup initialization failed:', error);
      this.showToast('Failed to initialize popup', 'error');
    }
  }

  async loadSettings() {
    try {
      const settings = await chrome.storage.sync.get({
        enabled: true,
        showWarnings: true,
        blockSuspicious: false
      });

      document.getElementById('enabledToggle').checked = settings.enabled;
      document.getElementById('warningsToggle').checked = settings.showWarnings;
      document.getElementById('blockToggle').checked = settings.blockSuspicious;

      // Update status indicator
      this.updateStatusIndicator(settings.enabled);
    } catch (error) {
      console.error('Failed to load settings:', error);
    }
  }

  async loadCurrentSiteStatus() {
    if (!this.currentTab || !this.currentTab.url) {
      document.getElementById('siteUrl').textContent = 'No active tab';
      document.getElementById('siteRisk').textContent = 'N/A';
      return;
    }

    try {
      const url = new URL(this.currentTab.url);
      const domain = url.hostname;

      // Update UI with current site info
      document.getElementById('siteUrl').textContent = domain;
      document.getElementById('siteRisk').textContent = 'Analyzing...';

      // Get risk assessment from background script
      const response = await chrome.runtime.sendMessage({
        type: 'ANALYZE_URL',
        url: this.currentTab.url
      });

      this.updateSiteStatus(response.riskLevel);
    } catch (error) {
      console.error('Failed to analyze current site:', error);
      document.getElementById('siteRisk').textContent = 'Analysis failed';
    }
  }

  updateSiteStatus(riskLevel) {
    const siteIcon = document.getElementById('siteIcon');
    const siteRisk = document.getElementById('siteRisk');
    const siteStatus = document.getElementById('siteStatus');

    // Remove existing risk classes
    siteStatus.className = 'site-status';

    switch (riskLevel) {
      case 'high':
        siteIcon.textContent = '🚨';
        siteRisk.textContent = 'High Risk - Dangerous';
        siteStatus.classList.add('risk-high');
        break;
      case 'medium':
        siteIcon.textContent = '⚠️';
        siteRisk.textContent = 'Medium Risk - Suspicious';
        siteStatus.classList.add('risk-medium');
        break;
      case 'low':
        siteIcon.textContent = '🔍';
        siteRisk.textContent = 'Low Risk - Minor concerns';
        siteStatus.classList.add('risk-low');
        break;
      case 'safe':
        siteIcon.textContent = '🔒';
        siteRisk.textContent = 'Safe - No threats detected';
        siteStatus.classList.add('risk-safe');
        break;
      default:
        siteIcon.textContent = '❓';
        siteRisk.textContent = 'Unknown - Unable to analyze';
        siteStatus.classList.add('risk-unknown');
    }
  }

  async loadStatistics() {
    try {
      const stats = await chrome.runtime.sendMessage({
        type: 'GET_STATISTICS'
      });

      document.getElementById('blockedCount').textContent = stats.blockedCount || 0;
      document.getElementById('reportsCount').textContent = stats.reportsCount || 0;
      document.getElementById('whitelistCount').textContent = stats.whitelistCount || 0;
    } catch (error) {
      console.error('Failed to load statistics:', error);
    }
  }

  setupEventListeners() {
    // Settings toggles
    document.getElementById('enabledToggle').addEventListener('change', (e) => {
      this.updateSetting('enabled', e.target.checked);
      this.updateStatusIndicator(e.target.checked);
    });

    document.getElementById('warningsToggle').addEventListener('change', (e) => {
      this.updateSetting('showWarnings', e.target.checked);
    });

    document.getElementById('blockToggle').addEventListener('change', (e) => {
      this.updateSetting('blockSuspicious', e.target.checked);
    });

    // Action buttons
    document.getElementById('whitelistBtn').addEventListener('click', () => {
      this.addToWhitelist();
    });

    document.getElementById('reportBtn').addEventListener('click', () => {
      this.reportPhishing();
    });

    document.getElementById('settingsBtn').addEventListener('click', () => {
      this.openSettings();
    });
  }

  async updateSetting(key, value) {
    try {
      await chrome.storage.sync.set({ [key]: value });
      this.showToast(`${key} ${value ? 'enabled' : 'disabled'}`, 'success');
    } catch (error) {
      console.error('Failed to update setting:', error);
      this.showToast('Failed to update setting', 'error');
    }
  }

  updateStatusIndicator(enabled) {
    const indicator = document.getElementById('statusIndicator');
    const statusText = document.getElementById('statusText');

    if (enabled) {
      indicator.classList.remove('disabled');
      statusText.textContent = 'Protected';
    } else {
      indicator.classList.add('disabled');
      statusText.textContent = 'Disabled';
    }
  }

  async addToWhitelist() {
    if (!this.currentTab || !this.currentTab.url) {
      this.showToast('No active tab to whitelist', 'error');
      return;
    }

    try {
      const url = new URL(this.currentTab.url);
      const domain = url.hostname;

      await chrome.runtime.sendMessage({
        type: 'ADD_TO_WHITELIST',
        domain: domain
      });

      this.showToast(`${domain} added to trusted sites`, 'success');
      await this.loadStatistics();
      await this.loadCurrentSiteStatus();
    } catch (error) {
      console.error('Failed to add to whitelist:', error);
      this.showToast('Failed to add to trusted sites', 'error');
    }
  }

  async reportPhishing() {
    if (!this.currentTab || !this.currentTab.url) {
      this.showToast('No active tab to report', 'error');
      return;
    }

    try {
      await chrome.runtime.sendMessage({
        type: 'REPORT_PHISHING',
        url: this.currentTab.url,
        details: 'User reported from popup'
      });

      this.showToast('Phishing report sent successfully', 'success');
      await this.loadStatistics();
    } catch (error) {
      console.error('Failed to report phishing:', error);
      this.showToast('Failed to send report', 'error');
    }
  }

  openSettings() {
    // In a full implementation, this would open a dedicated settings page
    this.showToast('Settings page coming soon', 'info');
  }

  showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;

    container.appendChild(toast);

    // Animate in
    setTimeout(() => toast.classList.add('show'), 10);

    // Remove after 3 seconds
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => {
        if (toast.parentNode) {
          toast.parentNode.removeChild(toast);
        }
      }, 300);
    }, 3000);
  }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new PhishGuardPopup();
});
