// Popup blocker confirmation dialog handler
(function() {
    'use strict';
    
    // Parse URL parameters
    function getUrlParams() {
        const params = new URLSearchParams(window.location.search);
        return {
            url: params.get('url'),
            domain: params.get('domain'),
            source: params.get('source'),
            popupId: params.get('popupId'),
            tabId: params.get('tabId')
        };
    }
    
    const params = getUrlParams();
    
    // Populate dialog with details
    document.addEventListener('DOMContentLoaded', function() {
        console.log('Popup blocker dialog loaded with params:', params);
        
        // Update UI elements with popup details
        const urlElement = document.getElementById('popupUrl');
        const domainElement = document.getElementById('popupDomain');
        const sourceElement = document.getElementById('popupSource');
        
        if (urlElement) urlElement.textContent = params.url || 'Unknown URL';
        if (domainElement) domainElement.textContent = params.domain || 'Unknown Domain';
        if (sourceElement) sourceElement.textContent = params.source || 'Unknown Source';
        
        // Handle allow button
        const allowBtn = document.getElementById('allowBtn');
        if (allowBtn) {
            allowBtn.addEventListener('click', function() {
                const remember = document.getElementById('rememberChoice')?.checked || false;
                sendDecision('allow', remember);
            });
        }
        
        // Handle block button
        const blockBtn = document.getElementById('blockBtn');
        if (blockBtn) {
            blockBtn.addEventListener('click', function() {
                const remember = document.getElementById('rememberChoice')?.checked || false;
                sendDecision('block', remember);
            });
        }
        
        // Handle escape key
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                sendDecision('block', false);
            }
        });
        
        // Auto-focus on block button for safety
        if (blockBtn) {
            blockBtn.focus();
        }
    });
    
    function sendDecision(decision, remember) {
        console.log(`Sending decision: ${decision}, remember: ${remember}`);
        
        // Disable buttons to prevent double-clicks
        const allowBtn = document.getElementById('allowBtn');
        const blockBtn = document.getElementById('blockBtn');
        if (allowBtn) allowBtn.disabled = true;
        if (blockBtn) blockBtn.disabled = true;
        
        // Show loading state
        showLoading();
        
        // Send decision to service worker
        chrome.runtime.sendMessage({
            type: 'popupDecision',
            action: decision,
            remember: remember,
            domain: params.domain,
            popupUrl: params.url,
            popupId: params.popupId,
            tabId: params.tabId
        }).then(() => {
            console.log(`Popup decision sent: ${decision}`);
            // Close this tab
            window.close();
        }).catch(error => {
            console.error('Error sending popup decision:', error);
            // Still try to close
            window.close();
        });
    }
    
    // Show loading state while processing
    function showLoading() {
        const loadingDiv = document.createElement('div');
        loadingDiv.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(255, 255, 255, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        `;
        loadingDiv.innerHTML = '<div style="font-size: 16px; font-weight: 600;">Processing...</div>';
        document.body.appendChild(loadingDiv);
    }
    
})();
