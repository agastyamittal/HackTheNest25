// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
  console.log('DOM loaded, initializing popup...');

  // Dark mode toggle functionality
  const themeToggle = document.getElementById('themeToggle');
  const body = document.body;
  
  // Load saved theme preference or default to light
  const savedTheme = localStorage.getItem('theme') || 'light';
  body.setAttribute('data-theme', savedTheme);
  
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const currentTheme = body.getAttribute('data-theme');
      const newTheme = currentTheme === 'light' ? 'dark' : 'light';
      
      body.setAttribute('data-theme', newTheme);
      localStorage.setItem('theme', newTheme);
      
      // Add a nice transition effect
      themeToggle.style.transform = 'rotate(360deg)';
      setTimeout(() => {
        themeToggle.style.transform = '';
      }, 300);
    });
  }

const urlInput = document.getElementById('urlInput');
const scanBtn = document.getElementById('scanBtn');
const status = document.getElementById('status');
const resultDiv = document.getElementById('result');

// Email breach checker elements
const emailInput = document.getElementById('emailInput');
const emailScanBtn = document.getElementById('emailScanBtn');
const emailStatus = document.getElementById('emailStatus');
const emailResultDiv = document.getElementById('emailResult');

// Check if all elements exist before adding event listeners
if (!emailInput || !emailScanBtn || !emailStatus || !emailResultDiv) {
  console.error('Email elements not found in DOM');
}

scanBtn.addEventListener('click', async () => {
  const url = urlInput.value.trim();
  if (!url) {
    showStatus('Please enter a URL to scan', 'error');
    urlInput.focus();
    return;
  }
  
  showStatus('Analyzing URL...', 'loading');
  resultDiv.textContent = '';
  scanBtn.disabled = true;
  scanBtn.textContent = 'Scanning...';

  try {
    // send a scan request to service worker
    const response = await chrome.runtime.sendMessage({ type: 'startScan', url });
    if (response && response.status === 'ok') {
      showStatus('Scan complete', 'success');
      showResult(response.result);
    } else {
      showStatus('Scan failed', 'error');
      resultDiv.innerHTML = `<div style="color: #e53e3e;">❌ Unable to scan this URL. Please try again.</div>`;
    }
  } catch (err) {
    showStatus('Connection error', 'error');
    resultDiv.innerHTML = `<div style="color: #e53e3e;">❌ ${err.message || 'Unable to connect to scanner service'}</div>`;
  } finally {
    scanBtn.disabled = false;
    scanBtn.innerHTML = `
      <svg class="btn-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <polygon points="13,2 3,14 12,14 11,22 21,10 12,10 13,2" stroke="currentColor" stroke-width="2" fill="currentColor"/>
      </svg>
      Scan
    `;
  }
});

function showStatus(message, type = 'info') {
  status.textContent = message;
  status.className = `status ${type}`;
}

function showResult(res) {
  const { score, verdict, reasons } = res;
  const scoreClass = score >= 70 ? 'score-high' : score >= 40 ? 'score-medium' : 'score-low';
  const statusIcon = score >= 70 ? '⚠️' : score >= 40 ? '⚠️' : '✅';
  const statusColor = score >= 70 ? '#e53e3e' : score >= 40 ? '#d69e2e' : '#38a169';
  
  resultDiv.innerHTML = `
    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
      <div style="width: 24px; height: 24px; border-radius: 50%; background: ${statusColor}; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 12px;">
        ${score >= 70 ? '!' : score >= 40 ? '?' : '✓'}
      </div>
      <div>
        <strong>Security Assessment:</strong> <span class="${scoreClass}">${verdict}</span>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">Risk Score: ${score}/100</div>
      </div>
    </div>
    <div style="margin-bottom: 8px;"><strong>Detection Details:</strong></div>
    <ul style="margin: 0; padding-left: 20px;">
      ${reasons.map(r => `<li style="margin-bottom: 4px;">${r}</li>`).join('')}
    </ul>
  `;
}

// Handle "Scan Current Page" button
document.getElementById('gotoScan').addEventListener('click', async () => {
  const gotoBtn = document.getElementById('gotoScan');
  const originalText = gotoBtn.innerHTML;
  
  try {
    gotoBtn.disabled = true;
    gotoBtn.innerHTML = `
      <svg class="btn-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/>
        <path d="M8 12l2 2 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      Scanning...
    `;
    showStatus('Getting current page URL...', 'loading');
    resultDiv.textContent = '';
    
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab) {
      throw new Error('No active tab found');
    }
    
    if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
      throw new Error('Cannot scan browser internal pages');
    }
    
    // Set the URL in the input field
    urlInput.value = tab.url;
    
    // Show scanning status
    showStatus('Analyzing current page...', 'loading');
    
    // Automatically perform the scan
    const response = await chrome.runtime.sendMessage({ type: 'startScan', url: tab.url });
    if (response && response.status === 'ok') {
      showStatus('Scan complete', 'success');
      showResult(response.result);
    } else {
      showStatus('Scan failed', 'error');
      resultDiv.innerHTML = `<div style="color: #e53e3e;">❌ Unable to scan this URL. Please try again.</div>`;
    }
    
  } catch (err) {
    console.error('Error scanning current page:', err);
    showStatus(`Cannot scan current page: ${err.message}`, 'error');
    if (err.message.includes('Unable to connect')) {
      resultDiv.innerHTML = `<div style="color: #e53e3e;">❌ ${err.message || 'Unable to connect to scanner service'}</div>`;
    }
  } finally {
    gotoBtn.disabled = false;
    gotoBtn.innerHTML = originalText;
  }
});

// Email breach checking functionality
console.log('Setting up email breach checker...');
console.log('Elements found:', {
  emailScanBtn: !!emailScanBtn,
  emailInput: !!emailInput, 
  emailStatus: !!emailStatus,
  emailResultDiv: !!emailResultDiv
});

if (emailScanBtn && emailInput && emailStatus && emailResultDiv) {
  console.log('All email elements found, setting up event listener');
  emailScanBtn.addEventListener('click', async () => {
    console.log('Email check button clicked');
    const email = emailInput.value.trim();
    if (!email) {
      showEmailStatus('Please enter an email address to check', 'error');
      emailInput.focus();
      return;
    }
    
    if (!isValidEmail(email)) {
      showEmailStatus('Please enter a valid email address', 'error');
      emailInput.focus();
      return;
    }
    
    showEmailStatus('Checking email breaches...', 'loading');
    emailResultDiv.textContent = '';
    emailScanBtn.disabled = true;
    emailScanBtn.innerHTML = `
      <svg class="btn-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/>
        <path d="M8 12l2 2 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      Checking...
    `;

    try {
      console.log('Sending message to service worker for email:', email);
      const response = await chrome.runtime.sendMessage({ type: 'checkEmailBreaches', email });
      console.log('Service worker response:', response);
      
      if (response && response.status === 'ok') {
        showEmailStatus('Check complete', 'success');
        showEmailResult(response.result);
      } else {
        showEmailStatus('Check failed', 'error');
        emailResultDiv.innerHTML = `<div style="color: #e53e3e;">❌ Unable to check this email. Please try again.</div>`;
      }
    } catch (err) {
      console.error('Email check error:', err);
      showEmailStatus('Connection error', 'error');
      emailResultDiv.innerHTML = `<div style="color: #e53e3e;">❌ ${err.message || 'Unable to connect to breach checking service'}</div>`;
  } finally {
    emailScanBtn.disabled = false;
    emailScanBtn.innerHTML = `
      <svg class="btn-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke="currentColor" stroke-width="2"/>
        <circle cx="12" cy="16" r="1" fill="currentColor"/>
        <path d="M7 11V7A5 5 0 0 1 17 7V11" stroke="currentColor" stroke-width="2"/>
      </svg>
      Check
    `;
  }
  });
} else {
  console.error('Email breach checker elements not found, skipping event listener setup');
  console.error('Missing elements:', {
    emailScanBtn: !emailScanBtn ? 'missing' : 'found',
    emailInput: !emailInput ? 'missing' : 'found',
    emailStatus: !emailStatus ? 'missing' : 'found',
    emailResultDiv: !emailResultDiv ? 'missing' : 'found'
  });
}

function showEmailStatus(message, type = 'info') {
  if (emailStatus) {
    emailStatus.textContent = message;
    emailStatus.className = `status ${type}`;
  }
}

function showEmailResult(result) {
  if (!emailResultDiv) return;
  
  const { breachCount, breaches, message, suggestion, source } = result;
  
  if (breachCount === 0) {
    emailResultDiv.innerHTML = `
      <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
        <div style="width: 24px; height: 24px; border-radius: 50%; background: #38a169; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 12px;">
          ✓
        </div>
        <div>
          <strong style="color: #38a169;">Good news!</strong>
          <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">No breaches found</div>
        </div>
      </div>
      <div>${message}</div>
      ${suggestion ? `<div style="margin-top: 8px; font-size: 12px; color: var(--text-muted);">${suggestion}</div>` : ''}
      ${source ? `<div style="margin-top: 8px; font-size: 11px; color: var(--text-muted);">Source: ${source}</div>` : ''}
    `;
  } else if (breachCount === -1) {
    // Special case for manual check required
    emailResultDiv.innerHTML = `
      <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
        <div style="width: 24px; height: 24px; border-radius: 50%; background: #d69e2e; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 12px;">
          ?
        </div>
        <div>
          <strong style="color: #d69e2e;">Manual Check Required</strong>
          <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">API limitations</div>
        </div>
      </div>
      <div style="margin-bottom: 12px;">${message}</div>
      <div style="margin-top: 12px; padding: 12px; background: #fef5e7; border-radius: 8px; border-left: 3px solid #d69e2e;">
        <div style="font-weight: 500; margin-bottom: 4px;">Manual Check Instructions:</div>
        <div style="font-size: 13px; line-height: 1.4;">
          1. Visit <a href="https://haveibeenpwned.com/" target="_blank" style="color: #d69e2e; text-decoration: underline;">haveibeenpwned.com</a><br>
          2. Enter your email address<br>
          3. Review any breaches found<br>
          4. Take appropriate security measures if needed
        </div>
      </div>
    `;
  } else if (breachCount === -2) {
    // Special case for likely breached service
    emailResultDiv.innerHTML = `
      <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
        <div style="width: 24px; height: 24px; border-radius: 50%; background: #d69e2e; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 12px;">
          !
        </div>
        <div>
          <strong style="color: #d69e2e;">Service Has Known Breaches</strong>
          <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">Historical security incidents</div>
        </div>
      </div>
      <div style="margin-bottom: 12px;">${message}</div>
      ${suggestion ? `<div style="margin-top: 8px; padding: 8px; background: #fef5e7; border-radius: 6px; font-size: 13px;">${suggestion}</div>` : ''}
      ${source ? `<div style="margin-top: 8px; font-size: 11px; color: var(--text-muted);">Source: ${source}</div>` : ''}
    `;
  } else {
    const breachText = breachCount === 1 ? 'breach' : 'breaches';
    emailResultDiv.innerHTML = `
      <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
        <div style="width: 24px; height: 24px; border-radius: 50%; background: #e53e3e; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 12px;">
          !
        </div>
        <div>
          <strong style="color: #e53e3e;">Security Alert!</strong>
          <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">${breachCount} ${breachText} found</div>
        </div>
      </div>
      <div style="margin-bottom: 12px;">
        <strong>This email was found in ${breachCount} data ${breachText}:</strong>
      </div>
      <ul style="margin: 0; padding-left: 20px; max-height: 200px; overflow-y: auto;">
        ${breaches.map(breach => `
          <li style="margin-bottom: 8px;">
            <strong>${breach.Name}</strong> (${new Date(breach.BreachDate).getFullYear()})
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">
              ${breach.Description || 'Data breach occurred at this service.'}
            </div>
          </li>
        `).join('')}
      </ul>
      <div style="margin-top: 12px; padding: 8px; background: #fed7d7; border-radius: 6px; font-size: 12px;">
        <strong>Recommended actions:</strong> Change your password if you haven't already, enable 2FA, and monitor your accounts.
      </div>
      ${source ? `<div style="margin-top: 8px; font-size: 11px; color: var(--text-muted);">Source: ${source}</div>` : ''}
    `;
  }
}

function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Allow Enter key to trigger email scan
if (emailInput && emailScanBtn) {
  emailInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !emailScanBtn.disabled) {
      emailScanBtn.click();
    }
  });
}

// Popup blocker settings
const popupBlockerToggle = document.getElementById('popupBlockerToggle');
const popupSettingsBtn = document.getElementById('popupSettingsBtn');

// Load popup blocker settings
chrome.storage.local.get(['popupBlockerSettings'], (result) => {
  if (result.popupBlockerSettings && popupBlockerToggle) {
    popupBlockerToggle.checked = result.popupBlockerSettings.enabled !== false;
  }
});

// Handle popup blocker toggle
if (popupBlockerToggle) {
  popupBlockerToggle.addEventListener('change', () => {
    chrome.storage.local.get(['popupBlockerSettings'], (result) => {
      const settings = result.popupBlockerSettings || { enabled: true, allowedDomains: [], blockedDomains: [] };
      settings.enabled = popupBlockerToggle.checked;
      chrome.storage.local.set({ popupBlockerSettings: settings });
    });
  });
}

// Handle popup settings button
if (popupSettingsBtn) {
  popupSettingsBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('popup_blocker.html?settings=true') });
  });
}

}); // Close DOMContentLoaded event listener
