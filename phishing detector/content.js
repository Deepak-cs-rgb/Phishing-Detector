// PhishGuard Content Script
class PhishGuardContent {
  constructor() {
    this.init();
  }

  init() {
    // Only run on main frame
    if (window.top !== window.self) return;
    
    this.setupMessageListener();
    this.checkCurrentPage();
    this.monitorPageChanges();
    
    console.log('PhishGuard content script initialized');
  }

  setupMessageListener() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      switch (message.type) {
        case 'RISK_ASSESSMENT':
          this.handleRiskAssessment(message);
          break;
        case 'SHOW_WARNING':
          this.showWarningOverlay(message);
          break;
      }
    });
  }

  async checkCurrentPage() {
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'ANALYZE_URL',
        url: window.location.href
      });
      
      if (response.riskLevel === 'high' || response.riskLevel === 'medium') {
        this.handleRiskAssessment({ 
          riskLevel: response.riskLevel, 
          url: window.location.href 
        });
      }
    } catch (error) {
      console.error('Page check failed:', error);
    }
  }

  handleRiskAssessment(assessment) {
    const { riskLevel, url } = assessment;
    
    switch (riskLevel) {
      case 'high':
        this.showWarningBanner('danger', 'Dangerous Website Detected!', 
          'This website has been identified as potentially malicious. We strongly recommend leaving immediately.');
        break;
      case 'medium':
        this.showWarningBanner('warning', 'Suspicious Website Detected', 
          'This website shows signs of being potentially unsafe. Exercise caution.');
        break;
    }
  }

  showWarningBanner(level, title, message) {
    // Remove existing banner
    const existing = document.getElementById('phishguard-banner');
    if (existing) existing.remove();

    // Create warning banner
    const banner = document.createElement('div');
    banner.id = 'phishguard-banner';
    banner.className = `phishguard-banner phishguard-${level}`;
    
    banner.innerHTML = `
      <div class="phishguard-banner-content">
        <div class="phishguard-banner-icon">
          ${level === 'danger' ? '⚠️' : '⚠️'}
        </div>
        <div class="phishguard-banner-text">
          <strong>${title}</strong>
          <p>${message}</p>
        </div>
        <div class="phishguard-banner-actions">
          <button class="phishguard-btn phishguard-btn-primary" onclick="window.history.back()">
            Go Back
          </button>
          <button class="phishguard-btn phishguard-btn-secondary" onclick="this.closest('.phishguard-banner').style.display='none'">
            Dismiss
          </button>
        </div>
        <button class="phishguard-banner-close" onclick="this.closest('.phishguard-banner').remove()">
          ×
        </button>
      </div>
    `;

    // Add styles
    if (!document.getElementById('phishguard-styles')) {
      const styles = document.createElement('style');
      styles.id = 'phishguard-styles';
      styles.textContent = `
        .phishguard-banner {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          z-index: 2147483647;
          padding: 12px 16px;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          font-size: 14px;
          line-height: 1.4;
          box-shadow: 0 2px 8px rgba(0,0,0,0.15);
          animation: phishguard-slide-down 0.3s ease-out;
        }
        
        .phishguard-banner.phishguard-danger {
          background: linear-gradient(135deg, #dc2626, #b91c1c);
          color: white;
        }
        
        .phishguard-banner.phishguard-warning {
          background: linear-gradient(135deg, #f59e0b, #d97706);
          color: white;
        }
        
        .phishguard-banner-content {
          display: flex;
          align-items: center;
          max-width: 1200px;
          margin: 0 auto;
          gap: 12px;
        }
        
        .phishguard-banner-icon {
          font-size: 24px;
          flex-shrink: 0;
        }
        
        .phishguard-banner-text {
          flex: 1;
        }
        
        .phishguard-banner-text strong {
          display: block;
          margin-bottom: 4px;
          font-weight: 600;
        }
        
        .phishguard-banner-text p {
          margin: 0;
          opacity: 0.9;
        }
        
        .phishguard-banner-actions {
          display: flex;
          gap: 8px;
          flex-shrink: 0;
        }
        
        .phishguard-btn {
          padding: 8px 16px;
          border: none;
          border-radius: 6px;
          font-size: 13px;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .phishguard-btn-primary {
          background: rgba(255,255,255,0.9);
          color: #1f2937;
        }
        
        .phishguard-btn-primary:hover {
          background: white;
        }
        
        .phishguard-btn-secondary {
          background: rgba(255,255,255,0.2);
          color: white;
          border: 1px solid rgba(255,255,255,0.3);
        }
        
        .phishguard-btn-secondary:hover {
          background: rgba(255,255,255,0.3);
        }
        
        .phishguard-banner-close {
          background: none;
          border: none;
          color: white;
          font-size: 20px;
          cursor: pointer;
          padding: 4px;
          margin: -4px;
          border-radius: 4px;
          flex-shrink: 0;
        }
        
        .phishguard-banner-close:hover {
          background: rgba(255,255,255,0.2);
        }
        
        @keyframes phishguard-slide-down {
          from { transform: translateY(-100%); }
          to { transform: translateY(0); }
        }
        
        @media (max-width: 768px) {
          .phishguard-banner-content {
            flex-direction: column;
            text-align: center;
            gap: 8px;
          }
          
          .phishguard-banner-actions {
            order: 3;
          }
        }
      `;
      document.head.appendChild(styles);
    }

    // Insert banner
    document.body.insertBefore(banner, document.body.firstChild);

    // Auto-dismiss after 10 seconds for warnings (not for dangers)
    if (level === 'warning') {
      setTimeout(() => {
        if (banner.parentNode) {
          banner.style.opacity = '0';
          setTimeout(() => banner.remove(), 300);
        }
      }, 10000);
    }
  }

  monitorPageChanges() {
    // Monitor for dynamic content changes that might indicate redirects
    let lastUrl = window.location.href;
    
    const observer = new MutationObserver(() => {
      if (window.location.href !== lastUrl) {
        lastUrl = window.location.href;
        setTimeout(() => this.checkCurrentPage(), 500);
      }
    });
    
    observer.observe(document, {
      childList: true,
      subtree: true
    });

    // Also monitor pushState/replaceState
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;
    
    history.pushState = function(...args) {
      originalPushState.apply(history, args);
      setTimeout(() => new PhishGuardContent().checkCurrentPage(), 500);
    };
    
    history.replaceState = function(...args) {
      originalReplaceState.apply(history, args);
      setTimeout(() => new PhishGuardContent().checkCurrentPage(), 500);
    };
  }
}

// Initialize content script
new PhishGuardContent();
