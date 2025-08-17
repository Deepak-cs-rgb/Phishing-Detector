// PhishGuard Warning Page Script
class PhishGuardWarning {
  constructor() {
    this.blockedUrl = '';
    this.init();
  }

  init() {
    this.extractBlockedUrl();
    this.setupEventListeners();
    this.displayWarningDetails();
    
    console.log('PhishGuard warning page initialized');
  }

  extractBlockedUrl() {
    const urlParams = new URLSearchParams(window.location.search);
    this.blockedUrl = urlParams.get('blocked') || 'Unknown URL';
    
    // Update UI with blocked URL
    document.getElementById('blockedUrl').textContent = this.blockedUrl;
    
    // Set page title with domain
    try {
      const url = new URL(this.blockedUrl);
      document.title = `PhishGuard Warning - ${url.hostname} Blocked`;
    } catch (error) {
      console.error('Invalid blocked URL:', error);
    }
  }

  setupEventListeners() {
    // Primary action buttons
    document.getElementById('goBackBtn').addEventListener('click', () => {
      this.goBack();
    });

    document.getElementById('reportBtn').addEventListener('click', () => {
      this.reportSite();
    });

    // Advanced options buttons
    document.getElementById('addWhitelistBtn').addEventListener('click', () => {
      this.addToWhitelist();
    });

    document.getElementById('proceedAnywayBtn').addEventListener('click', () => {
      this.proceedAnyway();
    });

    // Footer links
    document.getElementById('learnMoreLink').addEventListener('click', (e) => {
      e.preventDefault();
      this.showLearnMore();
    });

    document.getElementById('feedbackLink').addEventListener('click', (e) => {
      e.preventDefault();
      this.showFeedback();
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' || (e.key === 'Backspace' && !e.target.matches('input, textarea'))) {
        this.goBack();
      }
    });
  }

  displayWarningDetails() {
    try {
      const url = new URL(this.blockedUrl);
      const reasons = this.analyzeThreats(url);
      
      // Update threat reasons
      const reasonsList = document.getElementById('warningReasons');
      reasonsList.innerHTML = '';
      
      reasons.forEach(reason => {
        const li = document.createElement('li');
        li.textContent = reason;
        reasonsList.appendChild(li);
      });

      // Update threat type based on analysis
      const threatType = this.determineThreatType(url);
      document.getElementById('threatType').textContent = threatType;
      
    } catch (error) {
      console.error('Failed to analyze blocked URL:', error);
    }
  }

  analyzeThreats(url) {
    const reasons = [];
    const hostname = url.hostname.toLowerCase();
    
    // Check for IP address
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      reasons.push('Website uses IP address instead of domain name (suspicious)');
    }
    
    // Check for suspicious domain patterns
    if (hostname.includes('-') && hostname.split('-').length > 3) {
      reasons.push('Domain contains excessive hyphens (common in phishing)');
    }
    
    // Check for typosquatting patterns
    const suspiciousKeywords = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'secure', 'verify', 'update', 'confirm'];
    const containsSuspiciousKeywords = suspiciousKeywords.some(keyword => 
      hostname.includes(keyword) && !hostname.endsWith(`${keyword}.com`)
    );
    
    if (containsSuspiciousKeywords) {
      reasons.push('Domain mimics legitimate websites (potential typosquatting)');
    }
    
    // Check for free hosting domains
    const freeHostingDomains = ['.tk', '.ml', '.cf', '.ga'];
    if (freeHostingDomains.some(domain => hostname.endsWith(domain))) {
      reasons.push('Website uses free hosting service commonly abused by scammers');
    }
    
    // Check for suspicious URL structure
    if (url.pathname.includes('login') || url.pathname.includes('signin') || url.search.includes('redirect')) {
      reasons.push('URL structure suggests credential harvesting attempt');
    }
    
    // Default reasons if none found
    if (reasons.length === 0) {
      reasons.push(
        'This website has been flagged by our threat detection system',
        'The site may contain malicious content or attempt data theft',
        'Proceeding could compromise your personal information'
      );
    }
    
    return reasons;
  }

  determineThreatType(url) {
    const hostname = url.hostname.toLowerCase();
    
    if (hostname.includes('paypal') || hostname.includes('bank') || hostname.includes('secure')) {
      return 'Suspected Phishing (Financial)';
    } else if (hostname.includes('amazon') || hostname.includes('shop')) {
      return 'Suspected Phishing (E-commerce)';
    } else if (hostname.includes('google') || hostname.includes('microsoft')) {
      return 'Suspected Phishing (Tech Services)';
    } else {
      return 'Malicious/Suspicious Website';
    }
  }

  goBack() {
    // Try different methods to go back safely
    if (window.history.length > 1) {
      window.history.back();
    } else {
      // Fallback to a safe homepage
      window.location.href = 'about:blank';
    }
  }

  async reportSite() {
    try {
      // Send report to background script
      await chrome.runtime.sendMessage({
        type: 'REPORT_PHISHING',
        url: this.blockedUrl,
        details: 'User confirmed phishing from warning page'
      });
      
      this.showToast('Thank you! The suspicious site has been reported.', 'success');
      
      // Update button to show reported state
      const reportBtn = document.getElementById('reportBtn');
      reportBtn.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M20 6L9 17L4 12" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        Reported
      `;
      reportBtn.disabled = true;
      reportBtn.classList.add('reported');
      
    } catch (error) {
      console.error('Failed to report site:', error);
      this.showToast('Failed to send report. Please try again.', 'error');
    }
  }

  async addToWhitelist() {
    try {
      const url = new URL(this.blockedUrl);
      const domain = url.hostname;
      
      // Confirm action
      const confirmed = confirm(`Are you absolutely sure you want to trust "${domain}"?\n\nThis will allow the site to load without warnings in the future.`);
      
      if (!confirmed) return;
      
      // Send to background script
      await chrome.runtime.sendMessage({
        type: 'ADD_TO_WHITELIST',
        domain: domain
      });
      
      this.showToast(`${domain} added to trusted sites`, 'success');
      
      // Enable proceed button
      const proceedBtn = document.getElementById('proceedAnywayBtn');
      proceedBtn.textContent = 'Continue to Trusted Site';
      proceedBtn.classList.remove('btn-danger');
      proceedBtn.classList.add('btn-primary');
      
    } catch (error) {
      console.error('Failed to add to whitelist:', error);
      this.showToast('Failed to add to trusted sites', 'error');
    }
  }

  proceedAnyway() {
    const confirmed = confirm(
      '⚠️ FINAL WARNING ⚠️\n\n' +
      'You are about to visit a site that has been flagged as dangerous.\n\n' +
      'This could result in:\n' +
      '• Identity theft\n' +
      '• Financial loss\n' +
      '• Malware infection\n' +
      '• Data breach\n\n' +
      'Are you absolutely sure you want to continue?'
    );
    
    if (confirmed) {
      // Log the override for security audit
      console.warn('User chose to override PhishGuard protection for:', this.blockedUrl);
      
      // Navigate to the blocked URL
      window.location.href = this.blockedUrl;
    }
  }

  showLearnMore() {
    const modal = this.createModal('Learn More About Phishing', `
      <div class="learn-more-content">
        <h4>What is Phishing?</h4>
        <p>Phishing is a type of social engineering attack where criminals attempt to steal sensitive information by pretending to be trustworthy organizations.</p>
        
        <h4>Common Signs of Phishing:</h4>
        <ul>
          <li>Urgent requests for personal information</li>
          <li>Suspicious email addresses or URLs</li>
          <li>Poor grammar and spelling</li>
          <li>Requests to verify account information</li>
          <li>Threatening language about account closure</li>
        </ul>
        
        <h4>How to Stay Safe:</h4>
        <ul>
          <li>Always verify URLs before entering sensitive information</li>
          <li>Look for HTTPS and legitimate domain names</li>
          <li>Use two-factor authentication when available</li>
          <li>Keep your browser and security software updated</li>
          <li>Trust security warnings from PhishGuard</li>
        </ul>
      </div>
    `);
    
    document.body.appendChild(modal);
  }

  showFeedback() {
    const modal = this.createModal('Send Feedback', `
      <div class="feedback-content">
        <p>Help us improve PhishGuard by sharing your feedback:</p>
        <textarea id="feedbackText" placeholder="Tell us about your experience, report false positives, or suggest improvements..." rows="4"></textarea>
        <div class="feedback-actions">
          <button class="btn btn-primary" onclick="this.closest('.modal').remove()">Send Feedback</button>
          <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Cancel</button>
        </div>
      </div>
    `);
    
    document.body.appendChild(modal);
  }

  createModal(title, content) {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
      <div class="modal-content">
        <div class="modal-header">
          <h3>${title}</h3>
          <button class="modal-close" onclick="this.closest('.modal').remove()">×</button>
        </div>
        <div class="modal-body">
          ${content}
        </div>
      </div>
    `;
    
    // Close on click outside
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.remove();
      }
    });
    
    return modal;
  }

  showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;

    container.appendChild(toast);

    // Animate in
    setTimeout(() => toast.classList.add('show'), 10);

    // Remove after 4 seconds
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => {
        if (toast.parentNode) {
          toast.parentNode.removeChild(toast);
        }
      }, 300);
    }, 4000);
  }
}

// Initialize warning page when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new PhishGuardWarning();
});
