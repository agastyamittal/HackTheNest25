// Parse query params
function getParams() {
  const params = {};
  location.search.substring(1).split('&').forEach(pair => {
    const [k, v] = pair.split('=');
    params[decodeURIComponent(k)] = decodeURIComponent(v || '');
  });
  return params;
}

const params = getParams();
const warningDetails = document.getElementById('warningDetails');
const continueBtn = document.getElementById('continueBtn');
const goBackBtn = document.getElementById('goBackBtn');

// Populate warning details with better formatting
function populateWarningDetails() {
  const score = parseInt(params.score) || 0;
  const reasons = (params.reasons || '').split('|').filter(r => r.trim());
  
  // Determine score class and emoji
  let scoreClass = 'low';
  let scoreEmoji = '😊';
  let scoreText = 'Low Risk';
  
  if (score >= 60) {
    scoreClass = 'high';
    scoreEmoji = '😡';
    scoreText = 'High Risk';
  } else if (score >= 30) {
    scoreClass = 'medium';
    scoreEmoji = '😐';
    scoreText = 'Medium Risk';
  }
  
  warningDetails.innerHTML = `
    <div class="threat-score-section">
      <div class="threat-score-label">� Threat Assessment</div>
      <div class="warning-score-prominent ${scoreClass}">
        <span class="score-emoji">${scoreEmoji}</span>
        <div class="score-details">
          <div class="score-number">${score}/100</div>
          <div class="score-text">${scoreText}</div>
        </div>
      </div>
    </div>
    
    <div>
      <strong>� Website URL:</strong>
      <div class="warning-url">${params.url}</div>
    </div>
    
    <div>
      <strong>⚡ Security Verdict:</strong>
      <div class="warning-verdict">${params.verdict}</div>
    </div>
    
    ${reasons.length > 0 ? `
    <div class="warning-reasons">
      <strong>🔍 Security Concerns Detected:</strong>
      <ul>
        ${reasons.map(reason => `<li>${reason}</li>`).join('')}
      </ul>
    </div>
    ` : ''}
  `;
}

// Populate the warning details
populateWarningDetails();

// Go back button - go to previous page or safe location
goBackBtn.addEventListener('click', (e) => {
  e.preventDefault();
  e.stopPropagation();
  
  // Get the previous URL from the parameters
  const previousUrl = params.previousUrl || 'chrome://newtab/';
  
  // Since this is a Chrome extension warning page, we need to handle navigation carefully
  try {
    // First, try to use the browser's history to go back if possible
    if (window.history.length > 1) {
      // Send a message to the service worker to handle the navigation
      chrome.runtime.sendMessage({
        type: 'goBackSafely',
        previousUrl: previousUrl,
        useHistory: true
      }, (response) => {
        // If the service worker handled it, great
        if (response && response.success) {
          return;
        }
        
        // Fallback: navigate to the previous URL directly
        window.location.href = previousUrl;
      });
    } else {
      // No history to go back to, use the previous URL
      chrome.runtime.sendMessage({
        type: 'goBackSafely',
        previousUrl: previousUrl,
        useHistory: false
      }, (response) => {
        // If the service worker handled it, great
        if (response && response.success) {
          return;
        }
        
        // Fallback: navigate to the previous URL directly
        window.location.href = previousUrl;
      });
    }
    
    // Also set a timeout fallback in case the message doesn't work
    setTimeout(() => {
      if (window.history.length > 1 && previousUrl !== 'chrome://newtab/') {
        window.history.back();
      } else {
        window.location.href = previousUrl;
      }
    }, 1000);
    
  } catch (error) {
    console.log('Extension API not available, using direct navigation');
    // Try to go back in history first if there's a valid previous URL
    if (window.history.length > 1 && previousUrl !== 'chrome://newtab/' && previousUrl.startsWith('http')) {
      window.history.back();
    } else {
      // Direct fallback to previous URL or new tab
      window.location.href = previousUrl;
    }
  }
});

// Continue button - mark domain as scanned and proceed
continueBtn.addEventListener('click', () => {
  // Tell the service worker to mark this base domain as scanned for this tab
  chrome.runtime.sendMessage({
    type: 'markBaseDomainScanned',
    url: params.url
  }, () => {
    // Now redirect to the original URL
    window.location.href = params.url;
  });
});

AIzaSyCfb0j_bfZkLZVcMcOpy36SkL--q5w9zSk