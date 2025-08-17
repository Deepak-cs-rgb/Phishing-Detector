// PhishGuard Phishing Detection Engine
class PhishingDetector {
  constructor() {
    this.threatDatabase = null;
    this.loadThreatDatabase();
  }

  async loadThreatDatabase() {
    try {
      const result = await chrome.storage.local.get('threatDatabase');
      this.threatDatabase = result.threatDatabase || {
        phishingDomains: [],
        suspiciousPatterns: [],
        urlShorteners: [],
        lastUpdated: 0
      };
    } catch (error) {
      console.error('Failed to load threat database:', error);
      this.threatDatabase = {
        phishingDomains: [],
        suspiciousPatterns: [],
        urlShorteners: [],
        lastUpdated: 0
      };
    }
  }

  async analyzeUrl(url) {
    if (!url || typeof url === 'string') {
      try {
        url = new URL(url);
      } catch (error) {
        console.error('Invalid URL provided:', error);
        return 'unknown';
      }
    }

    try {
      // Load fresh threat database if needed
      if (!this.threatDatabase || Date.now() - this.threatDatabase.lastUpdated > 3600000) {
        await this.loadThreatDatabase();
      }

      // Check whitelist first
      const isWhitelisted = await this.isWhitelisted(url.hostname);
      if (isWhitelisted) {
        return 'safe';
      }

      // Perform various security checks
      const checks = await Promise.all([
        this.checkKnownPhishingDomains(url),
        this.checkSuspiciousPatterns(url),
        this.checkUrlShorteners(url),
        this.checkDomainReputation(url),
        this.checkSSLStatus(url),
        this.checkUrlStructure(url),
        this.checkTyposquatting(url)
      ]);

      // Aggregate risk score
      const riskScore = this.calculateRiskScore(checks);
      return this.determineRiskLevel(riskScore);

    } catch (error) {
      console.error('URL analysis failed:', error);
      return 'unknown';
    }
  }

  async isWhitelisted(hostname) {
    try {
      const settings = await chrome.storage.sync.get(['whitelistedDomains']);
      const whitelist = settings.whitelistedDomains || [];
      
      // Check exact match and parent domains
      return whitelist.some(domain => {
        return hostname === domain || hostname.endsWith(`.${domain}`);
      });
    } catch (error) {
      console.error('Whitelist check failed:', error);
      return false;
    }
  }

  async checkKnownPhishingDomains(url) {
    const hostname = url.hostname.toLowerCase();
    const phishingDomains = this.threatDatabase.phishingDomains || [];
    
    // Check exact matches and similar domains
    const isKnownPhishing = phishingDomains.some(domain => {
      return hostname === domain || 
             hostname.includes(domain) || 
             this.calculateStringSimilarity(hostname, domain) > 0.8;
    });

    return {
      type: 'knownPhishing',
      risk: isKnownPhishing ? 100 : 0,
      details: isKnownPhishing ? 'Domain matches known phishing site' : null
    };
  }

  async checkSuspiciousPatterns(url) {
    const hostname = url.hostname.toLowerCase();
    const fullUrl = url.href.toLowerCase();
    let riskScore = 0;
    const details = [];

    // IP address instead of domain
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      riskScore += 80;
      details.push('Using IP address instead of domain name');
    }

    // Excessive subdomains
    const subdomainCount = hostname.split('.').length - 2;
    if (subdomainCount > 3) {
      riskScore += 40;
      details.push('Excessive number of subdomains');
    }

    // Suspicious TLDs
    const suspiciousTlds = ['.tk', '.ml', '.cf', '.ga', '.pw', '.cc'];
    if (suspiciousTlds.some(tld => hostname.endsWith(tld))) {
      riskScore += 60;
      details.push('Using suspicious top-level domain');
    }

    // Long domain names
    if (hostname.length > 50) {
      riskScore += 30;
      details.push('Unusually long domain name');
    }

    // Excessive hyphens
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount > 3) {
      riskScore += 50;
      details.push('Excessive hyphens in domain name');
    }

    // URL contains suspicious keywords
    const suspiciousKeywords = [
      'secure', 'verify', 'update', 'confirm', 'urgent', 
      'suspended', 'locked', 'expired', 'billing'
    ];
    
    const foundKeywords = suspiciousKeywords.filter(keyword => 
      fullUrl.includes(keyword)
    );
    
    if (foundKeywords.length > 0) {
      riskScore += foundKeywords.length * 15;
      details.push(`Contains suspicious keywords: ${foundKeywords.join(', ')}`);
    }

    // Suspicious path patterns
    if (url.pathname.includes('signin') || url.pathname.includes('login')) {
      if (url.search.includes('redirect') || url.search.includes('return')) {
        riskScore += 40;
        details.push('Login page with redirect parameters');
      }
    }

    return {
      type: 'suspiciousPatterns',
      risk: Math.min(riskScore, 100),
      details: details.length > 0 ? details.join('; ') : null
    };
  }

  async checkUrlShorteners(url) {
    const hostname = url.hostname.toLowerCase();
    const shorteners = this.threatDatabase.urlShorteners || [];
    
    const isShortener = shorteners.includes(hostname);
    
    return {
      type: 'urlShortener',
      risk: isShortener ? 30 : 0,
      details: isShortener ? 'URL shortener detected (potential redirect)' : null
    };
  }

  async checkDomainReputation(url) {
    const hostname = url.hostname.toLowerCase();
    let riskScore = 0;
    const details = [];

    // Check for recently registered domains (simulation)
    // In a real implementation, this would check domain age via WHOIS
    const suspiciousNewDomains = ['temp', 'new', '2024', '2025'];
    if (suspiciousNewDomains.some(term => hostname.includes(term))) {
      riskScore += 25;
      details.push('Potentially recently registered domain');
    }

    // Check for DGA (Domain Generation Algorithm) patterns
    const dgaPattern = /^[a-z]{8,}\.com$/i;
    if (dgaPattern.test(hostname) && !this.isCommonWord(hostname.split('.')[0])) {
      riskScore += 60;
      details.push('Domain appears to be algorithmically generated');
    }

    // Check for homograph attacks (basic)
    if (this.containsSuspiciousCharacters(hostname)) {
      riskScore += 70;
      details.push('Domain contains suspicious unicode characters');
    }

    return {
      type: 'domainReputation',
      risk: riskScore,
      details: details.length > 0 ? details.join('; ') : null
    };
  }

  async checkSSLStatus(url) {
    // Note: Content scripts cannot directly check SSL certificates
    // This is a basic check based on protocol
    let riskScore = 0;
    const details = [];

    if (url.protocol === 'http:') {
      riskScore += 40;
      details.push('Website does not use HTTPS encryption');
    }

    // Check for mixed content concerns
    if (url.protocol === 'https:' && url.hostname.includes('insecure')) {
      riskScore += 20;
      details.push('Potential mixed content concerns');
    }

    return {
      type: 'sslStatus',
      risk: riskScore,
      details: details.length > 0 ? details.join('; ') : null
    };
  }

  async checkUrlStructure(url) {
    let riskScore = 0;
    const details = [];

    // Check for suspicious URL encoding
    if (url.href.includes('%') && url.href.match(/%[0-9a-f]{2}/gi)) {
      const encodedCount = (url.href.match(/%[0-9a-f]{2}/gi) || []).length;
      if (encodedCount > 5) {
        riskScore += 30;
        details.push('Excessive URL encoding detected');
      }
    }

    // Check for very long URLs
    if (url.href.length > 200) {
      riskScore += 25;
      details.push('Unusually long URL');
    }

    // Check for suspicious query parameters
    const suspiciousParams = ['password', 'pwd', 'pass', 'key', 'token', 'auth'];
    const queryParams = new URLSearchParams(url.search);
    
    for (const [param] of queryParams) {
      if (suspiciousParams.some(suspicious => param.toLowerCase().includes(suspicious))) {
        riskScore += 40;
        details.push('URL contains sensitive parameter names');
        break;
      }
    }

    // Check for data URIs or javascript in URL
    if (url.href.includes('data:') || url.href.includes('javascript:')) {
      riskScore += 90;
      details.push('URL contains potentially malicious scheme');
    }

    return {
      type: 'urlStructure',
      risk: riskScore,
      details: details.length > 0 ? details.join('; ') : null
    };
  }

  async checkTyposquatting(url) {
    const hostname = url.hostname.toLowerCase();
    const legitimateDomains = [
      'google.com', 'facebook.com', 'amazon.com', 'paypal.com',
      'microsoft.com', 'apple.com', 'twitter.com', 'instagram.com',
      'linkedin.com', 'netflix.com', 'ebay.com', 'youtube.com'
    ];

    let riskScore = 0;
    const details = [];

    for (const legit of legitimateDomains) {
      const similarity = this.calculateStringSimilarity(hostname, legit);
      
      // High similarity but not exact match suggests typosquatting
      if (similarity > 0.7 && similarity < 1.0) {
        riskScore += 80;
        details.push(`Possible typosquatting of ${legit}`);
        break;
      }
      
      // Check for character substitution attacks
      if (this.isCharacterSubstitution(hostname, legit)) {
        riskScore += 85;
        details.push(`Character substitution attack targeting ${legit}`);
        break;
      }
    }

    return {
      type: 'typosquatting',
      risk: riskScore,
      details: details.length > 0 ? details.join('; ') : null
    };
  }

  calculateRiskScore(checks) {
    let totalRisk = 0;
    let maxRisk = 0;
    let criticalIssues = 0;

    for (const check of checks) {
      totalRisk += check.risk;
      maxRisk = Math.max(maxRisk, check.risk);
      
      if (check.risk >= 80) {
        criticalIssues++;
      }
    }

    // Weight the scoring
    const averageRisk = totalRisk / checks.length;
    const weightedScore = (averageRisk * 0.6) + (maxRisk * 0.4);
    
    // Increase score if multiple critical issues
    if (criticalIssues > 1) {
      return Math.min(100, weightedScore + (criticalIssues * 10));
    }

    return weightedScore;
  }

  determineRiskLevel(score) {
    if (score >= 80) {
      return 'high';
    } else if (score >= 50) {
      return 'medium';
    } else if (score >= 20) {
      return 'low';
    } else {
      return 'safe';
    }
  }

  calculateStringSimilarity(str1, str2) {
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;
    
    if (longer.length === 0) return 1.0;
    
    const editDistance = this.levenshteinDistance(longer, shorter);
    return (longer.length - editDistance) / longer.length;
  }

  levenshteinDistance(str1, str2) {
    const matrix = [];
    
    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }
    
    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }
    
    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }
    
    return matrix[str2.length][str1.length];
  }

  isCharacterSubstitution(suspicious, legitimate) {
    // Check for common character substitutions
    const substitutions = {
      'o': '0',
      'i': '1',
      'l': '1',
      'e': '3',
      'a': '@',
      's': '$',
      'g': '9'
    };

    let substitutedLegit = legitimate;
    for (const [original, substitute] of Object.entries(substitutions)) {
      substitutedLegit = substitutedLegit.replace(new RegExp(original, 'g'), substitute);
    }

    return suspicious.includes(substitutedLegit) || 
           this.calculateStringSimilarity(suspicious, substitutedLegit) > 0.8;
  }

  containsSuspiciousCharacters(hostname) {
    // Check for homograph attack characters
    const suspiciousRanges = [
      /[\u0400-\u04FF]/, // Cyrillic
      /[\u0100-\u017F]/, // Latin Extended-A
      /[\u1E00-\u1EFF]/, // Latin Extended Additional
    ];

    return suspiciousRanges.some(range => range.test(hostname));
  }

  isCommonWord(word) {
    const commonWords = [
      'about', 'other', 'which', 'their', 'would', 'there', 'could', 'first',
      'after', 'these', 'where', 'being', 'every', 'great', 'might', 'shall',
      'still', 'those', 'while', 'should', 'never', 'before', 'another', 'through'
    ];
    
    return commonWords.includes(word.toLowerCase());
  }
}

// Make PhishingDetector available globally for other scripts
if (typeof window !== 'undefined') {
  window.PhishingDetector = PhishingDetector;
}

// Export for use in background script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = PhishingDetector;
}
