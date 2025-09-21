// content.js for Article Fact Check and Popup Detection coordination

function getArticleData() {
  const title = document.title || "";
  let mainText = "";
  const h1 = document.querySelector("h1");
  if (h1) mainText = h1.innerText;
  const article = document.querySelector("article");
  if (article && article.innerText.length > mainText.length) mainText = article.innerText;
  // Fallback: meta description
  if (!mainText || mainText.trim().length < 20) {
    const metaDesc = document.querySelector('meta[name="description"]');
    if (metaDesc) mainText = metaDesc.getAttribute('content') || mainText;
  }
  // Fallback: body text
  if (!mainText || mainText.trim().length < 20) {
    mainText = document.body.innerText.slice(0, 1000);
  }
  return { title, mainText };
}

// Enhanced popup detection coordination
if (typeof window !== 'undefined') {
  console.log('🔗 Security Scanner: Content script coordinator loaded');
  
  let popupSettings = {};

  // Get popup settings from storage
  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.get(['popupSettings'], (result) => {
      popupSettings = result.popupSettings || {};
      console.log('🔗 Security Scanner: Loaded popup settings:', popupSettings);
    });

    // Listen for storage changes
    chrome.storage.onChanged.addListener((changes, namespace) => {
      if (namespace === 'local' && changes.popupSettings) {
        popupSettings = changes.popupSettings.newValue || {};
        console.log('🔗 Security Scanner: Updated popup settings:', popupSettings);
      }
    });
  }

  // Listen for popup blocked events from the main world script
  document.addEventListener('securityScannerPopupBlocked', function(event) {
    const details = event.detail;
    console.log('🔗 Security Scanner: Received popup blocked event:', details);
    
    const currentDomain = details.domain;
    
    // Check saved preferences
    if (popupSettings[currentDomain] === 'allow') {
      console.log('🔗 Security Scanner: User preference is to allow popups for this domain');
      // Dispatch event to main world to execute popup
      const executeEvent = new CustomEvent('securityScannerExecutePopup', {
        detail: {
          url: details.url,
          name: details.name,
          features: details.features
        }
      });
      document.dispatchEvent(executeEvent);
      return;
    }
    
    if (popupSettings[currentDomain] === 'block') {
      console.log('🔗 Security Scanner: User preference is to block popups for this domain');
      return;
    }
    
    // No preference saved, show confirmation dialog
    const popupId = 'popup_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    
    // Send to service worker to show confirmation dialog
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'popupAttempt',
        url: details.url,
        source: details.source,
        domain: details.domain,
        name: details.name,
        features: details.features,
        popupId: popupId,
        blockedCount: details.blockedCount
      }).catch(error => {
        console.error('🔗 Security Scanner: Error sending popup message:', error);
      });
    }
  });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "scrapeArticle") {
    sendResponse(getArticleData());
  } else if (request.type === 'executePopup' && request.popupId) {
    console.log('🔗 Security Scanner: User chose to allow popup');
    
    // Create a notification that the popup was allowed
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #28a745;
      color: white;
      padding: 15px 20px;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      z-index: 999999;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 14px;
      font-weight: 600;
      max-width: 300px;
    `;
    
    notification.innerHTML = `
      <div style="display: flex; align-items: center; gap: 8px;">
        <span>✅</span>
        <div>
          <div>Popup Allowed</div>
          <div style="font-size: 12px; opacity: 0.9; margin-top: 4px;">
            Opening ${request.url ? new URL(request.url).hostname : 'popup'}...
          </div>
        </div>
      </div>
    `;
    
    document.body.appendChild(notification);
    
    // Dispatch event to main world to execute the popup
    setTimeout(() => {
      const executeEvent = new CustomEvent('securityScannerExecutePopup', {
        detail: {
          url: request.url,
          name: request.name,
          features: request.features,
          popupId: request.popupId
        }
      });
      document.dispatchEvent(executeEvent);
      
      sendResponse({ success: true });
    }, 500);
    
    // Remove notification after 3 seconds
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, 3000);
    
    return true; // Will respond asynchronously
  } else if (request.type === 'blockPopup' && request.popupId) {
    console.log('🔗 Security Scanner: User chose to block popup');
    sendResponse({ success: true });
  }
});