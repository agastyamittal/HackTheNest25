// MAXIMUM AGGRESSION POPUP BLOCKER - Injected in MAIN world at document_start
(function() {
    'use strict';
    
    console.log('🚫 Security Scanner: Maximum popup blocker initializing...');
    
    let blockedCount = 0;
    
    // Store original functions before overriding
    const originalWindowOpen = window.open;
    const originalAlert = window.alert;
    const originalConfirm = window.confirm;
    const originalPrompt = window.prompt;
    
    // Override window.open with maximum aggression
    function blockedWindowOpen(url, name, features) {
        blockedCount++;
        console.log('🚫 POPUP BLOCKED by Security Scanner:', {
            url: url || 'about:blank',
            name: name || '_blank',
            features: features || 'none',
            blockedCount: blockedCount
        });
        
        // Show visual notification
        showBlockedNotification('Popup blocked', url);
        
        // Dispatch custom event for test detection
        const event = new CustomEvent('securityScannerPopupBlocked', {
            detail: {
                url: url || 'about:blank',
                name: name || '_blank',
                features: features || 'none',
                source: 'window.open',
                domain: window.location.hostname,
                blockedCount: blockedCount
            }
        });
        document.dispatchEvent(event);
        
        // Always return null to indicate blocking
        return null;
    }
    
    // Override JavaScript dialogs
    function blockedAlert(message) {
        blockedCount++;
        console.log('🚫 ALERT BLOCKED by Security Scanner:', message);
        showBlockedNotification('Alert blocked', 'JavaScript alert attempt');
        
        // Dispatch event
        const event = new CustomEvent('securityScannerPopupBlocked', {
            detail: {
                type: 'alert',
                message: message,
                source: 'alert',
                domain: window.location.hostname,
                blockedCount: blockedCount
            }
        });
        document.dispatchEvent(event);
        
        // Don't show the alert, just return undefined
        return undefined;
    }
    
    function blockedConfirm(message) {
        blockedCount++;
        console.log('🚫 CONFIRM BLOCKED by Security Scanner:', message);
        showBlockedNotification('Confirm blocked', 'JavaScript confirm attempt');
        
        // Dispatch event
        const event = new CustomEvent('securityScannerPopupBlocked', {
            detail: {
                type: 'confirm',
                message: message,
                source: 'confirm',
                domain: window.location.hostname,
                blockedCount: blockedCount
            }
        });
        document.dispatchEvent(event);
        
        // Return false as safer default
        return false;
    }
    
    function blockedPrompt(message, defaultText) {
        blockedCount++;
        console.log('🚫 PROMPT BLOCKED by Security Scanner:', message);
        showBlockedNotification('Prompt blocked', 'JavaScript prompt attempt');
        
        // Dispatch event
        const event = new CustomEvent('securityScannerPopupBlocked', {
            detail: {
                type: 'prompt',
                message: message,
                source: 'prompt',
                domain: window.location.hostname,
                blockedCount: blockedCount
            }
        });
        document.dispatchEvent(event);
        
        // Return null to indicate cancellation
        return null;
    }
    
    // Visual notification function
    function showBlockedNotification(title, details) {
        // Remove any existing notifications
        const existing = document.getElementById('securityScannerNotification');
        if (existing) {
            existing.remove();
        }
        
        const notification = document.createElement('div');
        notification.id = 'securityScannerNotification';
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #dc3545;
            color: white;
            padding: 12px 16px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            z-index: 999999;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            font-size: 14px;
            font-weight: 600;
            max-width: 300px;
            animation: slideInRight 0.3s ease-out;
        `;
        
        // Add CSS animation
        if (!document.getElementById('securityScannerStyles')) {
            const style = document.createElement('style');
            style.id = 'securityScannerStyles';
            style.textContent = `
                @keyframes slideInRight {
                    from {
                        transform: translateX(100%);
                        opacity: 0;
                    }
                    to {
                        transform: translateX(0);
                        opacity: 1;
                    }
                }
            `;
            document.head.appendChild(style);
        }
        
        notification.innerHTML = `
            <div style="display: flex; align-items: center; gap: 8px;">
                <span>🚫</span>
                <div>
                    <div>${title}</div>
                    <div style="font-size: 12px; opacity: 0.9; margin-top: 4px;">
                        ${details || 'Blocked by Security Scanner'}
                    </div>
                </div>
            </div>
        `;
        
        // Add to page
        document.body.appendChild(notification);
        
        // Auto-remove after 3 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.style.animation = 'slideInRight 0.3s ease-out reverse';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.parentNode.removeChild(notification);
                    }
                }, 300);
            }
        }, 3000);
    }
    
    // Apply overrides with maximum security
    try {
        // Override window.open
        Object.defineProperty(window, 'open', {
            value: blockedWindowOpen,
            writable: false,
            configurable: false
        });
        
        // Override alert
        Object.defineProperty(window, 'alert', {
            value: blockedAlert,
            writable: false,
            configurable: false
        });
        
        // Override confirm
        Object.defineProperty(window, 'confirm', {
            value: blockedConfirm,
            writable: false,
            configurable: false
        });
        
        // Override prompt
        Object.defineProperty(window, 'prompt', {
            value: blockedPrompt,
            writable: false,
            configurable: false
        });
        
        console.log('✅ Security Scanner: All popup functions successfully overridden');
        
    } catch (error) {
        console.error('❌ Security Scanner: Error overriding popup functions:', error);
    }
    
    // Block target="_blank" links
    document.addEventListener('click', function(event) {
        const target = event.target.closest('a');
        if (target && target.target === '_blank') {
            const href = target.href;
            if (href && !href.startsWith(window.location.origin)) {
                event.preventDefault();
                event.stopImmediatePropagation();
                
                blockedCount++;
                console.log('🚫 TARGET="_blank" LINK BLOCKED:', href);
                showBlockedNotification('Link blocked', 'Suspicious external link');
                
                // Dispatch event
                const blockEvent = new CustomEvent('securityScannerPopupBlocked', {
                    detail: {
                        type: 'link',
                        url: href,
                        source: 'target_blank',
                        domain: window.location.hostname,
                        blockedCount: blockedCount
                    }
                });
                document.dispatchEvent(blockEvent);
            }
        }
    }, true);
    
    // Listen for our own events to handle popup decisions
    document.addEventListener('securityScannerExecutePopup', function(event) {
        const { url, name, features } = event.detail;
        console.log('🔗 Security Scanner: Executing allowed popup:', { url, name, features });
        
        // Use the original window.open function
        try {
            const popup = originalWindowOpen.call(window, url, name, features);
            console.log('✅ Popup opened with user permission');
            return popup;
        } catch (error) {
            console.error('Error opening allowed popup:', error);
        }
    });
    
    console.log('🛡️ Security Scanner: Maximum popup blocker active!');
    
})();