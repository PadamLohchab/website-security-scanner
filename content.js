// Content script for vulnerability scanning
(function() {
  'use strict';

  // Store scan results
  const scanResults = {
    url: window.location.href,
    timestamp: new Date().toISOString(),
    vulnerabilities: [],
    warnings: [],
    info: [],
    vulnerabilityChecks: {},
    websiteInfo: {}
  };

  // Check for missing security headers
  function checkSecurityHeaders() {
    // Note: Content scripts can't access response headers directly
    scanResults.vulnerabilityChecks.securityHeaders = {
      label: 'Security headers (CSP, HSTS, etc.)',
      checked: true,
      passed: false
    };
    scanResults.info.push({
      type: 'headers',
      message: 'Security headers check requires background script access to response headers',
      severity: 'info'
    });
  }

  // Check for insecure cookies
  function checkCookies() {
    const cookies = document.cookie.split(';');
    const insecureCookies = [];

    cookies.forEach(cookie => {
      const trimmed = cookie.trim();
      if (trimmed && !trimmed.toLowerCase().includes('secure')) {
        insecureCookies.push(trimmed.split('=')[0]);
      }
    });

    const hasIssue = insecureCookies.length > 0 && window.location.protocol === 'https:';
    scanResults.vulnerabilityChecks.insecureCookies = {
      label: 'Insecure cookies (Secure flag)',
      checked: true,
      passed: !hasIssue
    };
    if (hasIssue) {
      scanResults.warnings.push({
        type: 'cookies',
        message: `Found ${insecureCookies.length} cookie(s) without Secure flag on HTTPS page`,
        details: insecureCookies,
        severity: 'medium'
      });
    }
  }

  // Check for mixed content (HTTP resources on HTTPS pages)
  function checkMixedContent() {
    if (window.location.protocol !== 'https:') {
      scanResults.vulnerabilityChecks.mixedContent = {
        label: 'Mixed content (HTTP on HTTPS)',
        checked: true,
        passed: true
      };
      return;
    }

    const httpResources = [];
    
    // Check images
    document.querySelectorAll('img[src^="http://"]').forEach(img => {
      httpResources.push({ type: 'image', url: img.src });
    });

    // Check scripts
    document.querySelectorAll('script[src^="http://"]').forEach(script => {
      httpResources.push({ type: 'script', url: script.src });
    });

    // Check links
    document.querySelectorAll('link[href^="http://"]').forEach(link => {
      httpResources.push({ type: 'link', url: link.href });
    });

    // Check iframes
    document.querySelectorAll('iframe[src^="http://"]').forEach(iframe => {
      httpResources.push({ type: 'iframe', url: iframe.src });
    });

    scanResults.vulnerabilityChecks.mixedContent = {
      label: 'Mixed content (HTTP on HTTPS)',
      checked: true,
      passed: httpResources.length === 0
    };
    if (httpResources.length > 0) {
      scanResults.vulnerabilities.push({
        type: 'mixed-content',
        message: `Found ${httpResources.length} HTTP resource(s) on HTTPS page`,
        details: httpResources,
        severity: 'high'
      });
    }
  }

  // Check for XSS vulnerabilities in forms
  function checkXSSVulnerabilities() {
    let xssFound = false;
    const forms = document.querySelectorAll('form');
    const xssPatterns = [
      /<script/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /eval\(/i,
      /expression\(/i
    ];

    forms.forEach((form, index) => {
      try {
        const inputs = form.querySelectorAll('input, textarea, select');
        inputs.forEach((input) => {
          try {
            // Check if input value contains potential XSS patterns
            if (input.value) {
              xssPatterns.forEach(pattern => {
                if (pattern.test(input.value)) {
                  xssFound = true;
                  scanResults.warnings.push({
                    type: 'xss-pattern',
                    message: 'Potential XSS pattern detected in form input',
                    details: {
                      formIndex: index,
                      inputName: (typeof input.name === 'string' ? input.name : input.id) || 'unnamed',
                      pattern: pattern.toString()
                    },
                    severity: 'low'
                  });
                }
              });
            }

            const inputType = typeof input.type === 'string' ? input.type : '';
            const inputName = (typeof input.name === 'string' ? input.name : input.id) || 'unnamed';
            // Check for missing input validation attributes
            if (!input.hasAttribute('maxlength') && inputType !== 'password') {
              scanResults.info.push({
                type: 'input-validation',
                message: `Input field "${inputName}" lacks maxlength attribute`,
                severity: 'info'
              });
            }
          } catch (inputErr) {
            // Skip malformed input
          }
        });
      } catch (e) {
        // Skip malformed or unusual form elements
      }
    });
    scanResults.vulnerabilityChecks.xssPatterns = {
      label: 'XSS patterns in forms',
      checked: true,
      passed: !xssFound
    };
  }

  // Check for exposed sensitive information
  function checkExposedInformation() {
    const pageText = document.body ? document.body.innerText.toLowerCase() : '';
    const sensitivePatterns = [
      { pattern: /password\s*[:=]\s*[\w@#$%^&*!]+/i, type: 'password-exposure' },
      { pattern: /api[_-]?key\s*[:=]\s*[\w-]+/i, type: 'api-key-exposure' },
      { pattern: /secret\s*[:=]\s*[\w-]+/i, type: 'secret-exposure' },
      { pattern: /token\s*[:=]\s*[\w-]+/i, type: 'token-exposure' },
      { pattern: /aws[_-]?access[_-]?key/i, type: 'aws-key-exposure' }
    ];

    let secretsFound = false;
    sensitivePatterns.forEach(({ pattern, type }) => {
      if (pattern.test(pageText)) {
        secretsFound = true;
        scanResults.vulnerabilities.push({
          type: type,
          message: `Potential sensitive information exposure detected: ${type}`,
          severity: 'high'
        });
      }
    });
    scanResults.vulnerabilityChecks.exposedSecrets = {
      label: 'Exposed secrets / API keys',
      checked: true,
      passed: !secretsFound
    };

    // Check for email addresses (could be sensitive)
    const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    const emails = pageText.match(emailPattern);
    if (emails && emails.length > 5) {
      scanResults.info.push({
        type: 'email-exposure',
        message: `Found ${emails.length} email address(es) on page`,
        severity: 'info'
      });
    }
  }

  // Check for outdated libraries
  function checkOutdatedLibraries() {
    const scripts = Array.from(document.querySelectorAll('script[src]'));
    const knownVulnerableLibs = [
      { name: 'jquery', versions: ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '1.8', '1.9', '1.10', '1.11'] },
      { name: 'angular', versions: ['1.0', '1.1', '1.2'] }
    ];

    scripts.forEach(script => {
      const src = script.src.toLowerCase();
      knownVulnerableLibs.forEach(lib => {
        if (src.includes(lib.name)) {
          lib.versions.forEach(version => {
            if (src.includes(version)) {
              scanResults.warnings.push({
                type: 'outdated-library',
                message: `Potentially outdated library detected: ${lib.name} ${version}`,
                details: { library: lib.name, version: version, src: script.src },
                severity: 'medium'
              });
            }
          });
        }
      });
    });
  }

  // Check for SQL injection patterns in forms
  function checkSQLInjection() {
    const forms = document.querySelectorAll('form');
    const sqlPatterns = [
      /(\bunion\b.*\bselect\b)/i,
      /(\bor\b.*=.*)/i,
      /(\band\b.*=.*)/i,
      /('.*or.*'.*=.*')/i,
      /(\bexec\b|\bexecute\b)/i,
      /(\bdrop\b.*\btable\b)/i
    ];

    forms.forEach((form, index) => {
      try {
        const inputs = form.querySelectorAll('input[type="text"], input[type="search"], textarea');
        inputs.forEach((input) => {
          try {
            if (input.value) {
              sqlPatterns.forEach(pattern => {
                if (pattern.test(input.value)) {
                  scanResults.warnings.push({
                    type: 'sql-injection-pattern',
                    message: 'Potential SQL injection pattern detected in form input',
                    details: {
                      formIndex: index,
                      inputName: (typeof input.name === 'string' ? input.name : input.id) || 'unnamed'
                    },
                    severity: 'medium'
                  });
                }
              });
            }
          } catch (inputErr) {
            // Skip malformed input
          }
        });
      } catch (e) {
        // Skip malformed or unusual form elements
      }
    });
  }

  // Check for CSRF vulnerabilities (missing tokens)
  function checkCSRF() {
    const forms = document.querySelectorAll('form');
    let formsWithoutToken = 0;

    forms.forEach((form) => {
      try {
        const hasToken = form.querySelector('input[name*="token"], input[name*="csrf"], input[name*="_token"]');
        const rawMethod = form.method;
        const methodStr = (rawMethod && typeof rawMethod === 'string' && !rawMethod.includes('[object')) ? rawMethod : (form.getAttribute ? (form.getAttribute('method') || 'get') : 'get');
        const method = methodStr.toLowerCase();

        if (method === 'post' && !hasToken) {
          formsWithoutToken++;
        }
      } catch (e) {
        // Skip malformed or unusual form elements (e.g. SPA frameworks)
      }
    });

    const hasIssue = formsWithoutToken > 0;
    scanResults.vulnerabilityChecks.formValidationCsrf = {
      label: 'Form validation & CSRF',
      checked: true,
      passed: !hasIssue
    };
    if (hasIssue) {
      scanResults.warnings.push({
        type: 'csrf',
        message: `Found ${formsWithoutToken} POST form(s) without CSRF token`,
        severity: 'medium'
      });
    }
  }

  // Check for autocomplete on sensitive fields
  function checkAutocomplete() {
    const sensitiveInputs = document.querySelectorAll('input[type="password"], input[name*="password"], input[name*="credit"], input[name*="card"]');
    sensitiveInputs.forEach(input => {
      if (input.getAttribute('autocomplete') === 'on' || !input.hasAttribute('autocomplete')) {
        scanResults.warnings.push({
          type: 'autocomplete',
          message: 'Sensitive input field has autocomplete enabled',
          details: { inputName: input.name || input.id || 'unnamed' },
          severity: 'low'
        });
      }
    });
  }

  // ========== COMPREHENSIVE WEBSITE INFORMATION GATHERING ==========

  // Gather basic website information
  function gatherBasicInfo() {
    const info = {
      title: document.title || 'No title',
      description: '',
      keywords: '',
      author: '',
      language: document.documentElement.lang || 'Not specified',
      charset: document.characterSet || 'Not specified',
      viewport: '',
      robots: '',
      canonical: '',
      ogTags: {},
      twitterTags: {}
    };

    // Meta tags
    const metaTags = document.querySelectorAll('meta');
    metaTags.forEach(meta => {
      const name = meta.getAttribute('name') || meta.getAttribute('property') || '';
      const content = meta.getAttribute('content') || '';

      if (name.toLowerCase() === 'description') {
        info.description = content;
      } else if (name.toLowerCase() === 'keywords') {
        info.keywords = content;
      } else if (name.toLowerCase() === 'author') {
        info.author = content;
      } else if (name.toLowerCase() === 'viewport') {
        info.viewport = content;
      } else if (name.toLowerCase() === 'robots') {
        info.robots = content;
      } else if (name.startsWith('og:')) {
        info.ogTags[name] = content;
      } else if (name.startsWith('twitter:')) {
        info.twitterTags[name] = content;
      }
    });

    // Canonical URL
    const canonical = document.querySelector('link[rel="canonical"]');
    if (canonical) {
      info.canonical = canonical.href;
    }

    scanResults.websiteInfo.basic = info;
  }

  // Detect technology stack
  function detectTechnologyStack() {
    const tech = {
      frameworks: [],
      cms: [],
      libraries: [],
      cdn: [],
      analytics: [],
      advertising: [],
      fonts: [],
      server: ''
    };

    // Detect frameworks and libraries from scripts
    const scripts = Array.from(document.querySelectorAll('script[src]'));
    const scriptSources = scripts.map(s => s.src.toLowerCase());

    // Framework detection
    const frameworkPatterns = {
      'React': /react|react-dom|react\.js/i,
      'Vue.js': /vue\.js|vue\.min/i,
      'Angular': /angular|ng\.js/i,
      'jQuery': /jquery/i,
      'Bootstrap': /bootstrap/i,
      'Foundation': /foundation/i,
      'Material-UI': /material-ui|mui/i,
      'Tailwind CSS': /tailwind/i,
      'Svelte': /svelte/i,
      'Ember.js': /ember/i,
      'Backbone.js': /backbone/i
    };

    Object.keys(frameworkPatterns).forEach(framework => {
      if (scriptSources.some(src => frameworkPatterns[framework].test(src)) ||
          document.documentElement.innerHTML.match(frameworkPatterns[framework])) {
        tech.frameworks.push(framework);
      }
    });

    // CMS detection
    const cmsPatterns = {
      'WordPress': /wp-content|wp-includes|wordpress/i,
      'Drupal': /drupal|sites\/all/i,
      'Joomla': /joomla|components\/com_/i,
      'Shopify': /shopify|cdn\.shopify/i,
      'Magento': /magento|skin\/frontend/i,
      'Wix': /wix\.com|wixstatic/i,
      'Squarespace': /squarespace/i,
      'Ghost': /ghost\.org/i,
      'Django': /django|csrfmiddlewaretoken/i
    };

    Object.keys(cmsPatterns).forEach(cms => {
      if (scriptSources.some(src => cmsPatterns[cms].test(src)) ||
          document.documentElement.innerHTML.match(cmsPatterns[cms])) {
        tech.cms.push(cms);
      }
    });

    // CDN detection
    const cdnPatterns = {
      'Cloudflare': /cdnjs\.cloudflare|cloudflare/i,
      'jsDelivr': /cdn\.jsdelivr/i,
      'unpkg': /unpkg\.com/i,
      'Google CDN': /ajax\.googleapis|gstatic/i,
      'Microsoft CDN': /ajax\.aspnetcdn/i,
      'Amazon CloudFront': /cloudfront\.net/i,
      'Bootstrap CDN': /bootstrapcdn/i
    };

    scriptSources.forEach(src => {
      Object.keys(cdnPatterns).forEach(cdn => {
        if (cdnPatterns[cdn].test(src) && !tech.cdn.includes(cdn)) {
          tech.cdn.push(cdn);
        }
      });
    });

    // Analytics detection
    const analyticsPatterns = {
      'Google Analytics': /google-analytics|ga\.js|gtag|analytics\.js/i,
      'Google Tag Manager': /googletagmanager/i,
      'Facebook Pixel': /facebook\.net|fbq/i,
      'Adobe Analytics': /omniture|adobe\.com\/analytics/i,
      'Mixpanel': /mixpanel/i,
      'Segment': /segment\.com|analytics\.js/i,
      'Hotjar': /hotjar/i,
      'Piwik/Matomo': /piwik|matomo/i
    };

    scriptSources.forEach(src => {
      Object.keys(analyticsPatterns).forEach(analytics => {
        if (analyticsPatterns[analytics].test(src) && !tech.analytics.includes(analytics)) {
          tech.analytics.push(analytics);
        }
      });
    });

    // Font detection
    const fontLinks = document.querySelectorAll('link[href*="fonts"], link[href*="font"]');
    fontLinks.forEach(link => {
      const href = link.href.toLowerCase();
      if (href.includes('googleapis.com/fonts') || href.includes('fonts.googleapis')) {
        if (!tech.fonts.includes('Google Fonts')) tech.fonts.push('Google Fonts');
      } else if (href.includes('fonts.com')) {
        if (!tech.fonts.includes('Fonts.com')) tech.fonts.push('Fonts.com');
      } else if (href.includes('typekit')) {
        if (!tech.fonts.includes('Adobe Fonts')) tech.fonts.push('Adobe Fonts');
      }
    });

    // Server detection (from headers if available, or meta tags)
    const generator = document.querySelector('meta[name="generator"]');
    if (generator) {
      tech.server = generator.content;
    }

    scanResults.websiteInfo.technology = tech;
  }

  // Count all links (used for stats); call after possible SPA DOM update
  function countLinks() {
    return document.querySelectorAll('a[href]').length;
  }

  // Gather links and external resources
  function gatherLinksAndResources() {
    const resources = {
      internalLinks: [],
      externalLinks: [],
      socialMedia: {},
      emailLinks: [],
      phoneLinks: [],
      images: {
        total: 0,
        external: 0,
        missingAlt: 0
      },
      scripts: {
        total: 0,
        external: 0,
        inline: 0
      },
      stylesheets: {
        total: 0,
        external: 0,
        inline: 0
      }
    };

    const currentDomain = window.location.hostname;

    // Links
    const links = document.querySelectorAll('a[href]');
    links.forEach(link => {
      const href = link.href;
      try {
        const url = new URL(href);
        if (url.hostname === currentDomain || !url.hostname) {
          resources.internalLinks.push({
            text: link.textContent.trim().substring(0, 50),
            href: href
          });
        } else {
          resources.externalLinks.push({
            text: link.textContent.trim().substring(0, 50),
            href: href,
            domain: url.hostname
          });

          // Social media detection
          const domain = url.hostname.toLowerCase();
          if (domain.includes('facebook.com')) resources.socialMedia.facebook = href;
          if (domain.includes('twitter.com') || domain.includes('x.com')) resources.socialMedia.twitter = href;
          if (domain.includes('linkedin.com')) resources.socialMedia.linkedin = href;
          if (domain.includes('instagram.com')) resources.socialMedia.instagram = href;
          if (domain.includes('youtube.com')) resources.socialMedia.youtube = href;
          if (domain.includes('github.com')) resources.socialMedia.github = href;
        }

        // Email links
        if (href.startsWith('mailto:')) {
          resources.emailLinks.push(href.replace('mailto:', ''));
        }

        // Phone links
        if (href.startsWith('tel:')) {
          resources.phoneLinks.push(href.replace('tel:', ''));
        }
      } catch (e) {
        // Invalid URL, skip
      }
    });

    // Images
    const images = document.querySelectorAll('img');
    resources.images.total = images.length;
    images.forEach(img => {
      if (img.src && !img.src.startsWith('data:')) {
        try {
          const url = new URL(img.src);
          if (url.hostname !== currentDomain) {
            resources.images.external++;
          }
        } catch (e) {}
      }
      if (!img.alt || img.alt.trim() === '') {
        resources.images.missingAlt++;
      }
    });

    // Scripts
    const scripts = document.querySelectorAll('script');
    resources.scripts.total = scripts.length;
    scripts.forEach(script => {
      if (script.src) {
        resources.scripts.external++;
      } else {
        resources.scripts.inline++;
      }
    });

    // Stylesheets
    const stylesheets = document.querySelectorAll('link[rel="stylesheet"], style');
    stylesheets.forEach(style => {
      if (style.href) {
        resources.stylesheets.external++;
      } else {
        resources.stylesheets.inline++;
      }
    });
    resources.stylesheets.total = stylesheets.length;
    resources.totalLinks = countLinks();

    scanResults.websiteInfo.resources = resources;
  }

  // Gather form information (with safety guards for malformed/SPA forms)
  function gatherFormInfo() {
    const forms = Array.from(document.querySelectorAll('form'));
    const formInfo = {
      total: forms.length,
      forms: []
    };

    forms.forEach((form, index) => {
      try {
        // Skip form if method is not a string (e.g. null, undefined, or non-string type from DOM)
        const rawMethod = form?.method;
        const methodStr = (rawMethod && typeof rawMethod === 'string' && !rawMethod.includes('[object')) ? rawMethod : (form.getAttribute ? (form.getAttribute('method') || 'get') : 'get');
        const method = methodStr.toUpperCase();
        const action = String(form?.action || 'Current page');
        const formData = {
          index: index,
          method: method,
          action: action,
          inputs: [],
          hasPassword: false,
          hasFileUpload: false,
          hasCSRFToken: false
        };

        const inputs = form.querySelectorAll('input, textarea, select');
        inputs.forEach((input) => {
          try {
            const inputType = typeof input.type === 'string' ? input.type : (input.tagName ? input.tagName.toLowerCase() : 'text');
            const inputName = typeof input.name === 'string' ? input.name : '';
            const inputId = typeof input.id === 'string' ? input.id : '';
            const inputPlaceholder = typeof input.placeholder === 'string' ? input.placeholder : '';
            const inputInfo = {
              type: inputType,
              name: inputName,
              id: inputId,
              required: input.hasAttribute('required'),
              placeholder: inputPlaceholder
            };

            formData.inputs.push(inputInfo);

            if (inputType === 'password') formData.hasPassword = true;
            if (inputType === 'file') formData.hasFileUpload = true;
            if (inputName && (inputName.includes('token') || inputName.includes('csrf') || inputName.includes('_token'))) {
              formData.hasCSRFToken = true;
            }
          } catch (inputErr) {
            // Skip malformed input
          }
        });

        formInfo.forms.push(formData);
      } catch (e) {
        // One bad form (e.g. hackmd.io or other SPA) should not crash the entire scan
      }
    });

    scanResults.websiteInfo.forms = formInfo;
  }

  // Gather performance metrics
  function gatherPerformanceMetrics() {
    const perf = {
      domElements: document.querySelectorAll('*').length,
      images: document.querySelectorAll('img').length,
      scripts: document.querySelectorAll('script').length,
      stylesheets: document.querySelectorAll('link[rel="stylesheet"], style').length,
      iframes: document.querySelectorAll('iframe').length,
      links: document.querySelectorAll('a[href]').length,
      loadTime: null
    };

    // Try to get performance timing - only use when loadEventEnd is valid (page fully loaded)
    if (window.performance && window.performance.timing) {
      const timing = window.performance.timing;
      const navStart = timing.navigationStart;
      const loadEnd = timing.loadEventEnd;
      if (loadEnd > 0 && navStart > 0 && loadEnd >= navStart) {
        perf.loadTime = loadEnd - navStart;
      }
      const domEnd = timing.domContentLoadedEventEnd;
      if (domEnd > 0 && navStart > 0) {
        perf.domContentLoaded = domEnd - navStart;
      }
      perf.firstPaint = null;

      if (window.performance.getEntriesByType) {
        const paintEntries = window.performance.getEntriesByType('paint');
        paintEntries.forEach(entry => {
          if (entry.name === 'first-paint') {
            perf.firstPaint = entry.startTime;
          }
        });
      }
    }

    scanResults.websiteInfo.performance = perf;
  }

  // Gather domain and security information
  function gatherDomainInfo() {
    const domainInfo = {
      protocol: window.location.protocol,
      hostname: window.location.hostname,
      port: window.location.port || (window.location.protocol === 'https:' ? '443' : '80'),
      path: window.location.pathname,
      hash: window.location.hash,
      search: window.location.search,
      isHTTPS: window.location.protocol === 'https:',
      cookies: document.cookie.split(';').length,
      localStorage: Object.keys(localStorage).length,
      sessionStorage: Object.keys(sessionStorage).length
    };

    scanResults.websiteInfo.domain = domainInfo;
  }

  // Gather all website information
  function gatherWebsiteInfo() {
    gatherBasicInfo();
    detectTechnologyStack();
    gatherLinksAndResources();
    gatherFormInfo();
    gatherPerformanceMetrics();
    gatherDomainInfo();
  }

  // Run all checks
  function runScan() {
    try {
      // Reset website info
      scanResults.websiteInfo = {};
      
      // Run vulnerability checks
      checkSecurityHeaders();
      checkCookies();
      checkMixedContent();
      checkXSSVulnerabilities();
      checkExposedInformation();
      checkOutdatedLibraries();
      checkSQLInjection();
      checkCSRF();
      checkAutocomplete();

      // Gather comprehensive website information
      gatherWebsiteInfo();

      // Send results to background script
      chrome.runtime.sendMessage({
        type: 'scan-results',
        data: scanResults
      });
    } catch (error) {
      console.error('Error during vulnerability scan:', error);
    }
  }

  // Run scan when page is loaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', runScan);
  } else {
    runScan();
  }

  // Listen for scan requests from popup (delay for SPA/React so DOM has links)
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'run-scan') {
      scanResults.vulnerabilities = [];
      scanResults.warnings = [];
      scanResults.info = [];
      scanResults.vulnerabilityChecks = {};
      scanResults.websiteInfo = {};
      scanResults.url = window.location.href;
      scanResults.timestamp = new Date().toISOString();
      const runAfterDelay = () => {
        runScan();
        sendResponse({ success: true });
      };
      setTimeout(runAfterDelay, 1500);
    }
    return true;
  });
})();

