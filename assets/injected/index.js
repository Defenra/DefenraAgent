(function() {
    // Avoid running on the challenge page itself if it somehow gets injected
    if (document.getElementById('challenge-form') || window.location.pathname.includes('/challenge')) {
        return;
    }

    console.log("[Defenra] Protection Module Loaded");

    const originalFetch = window.fetch;
    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;

    let protectionTriggered = false;
    let reloadScheduled = false;

    function stopTraffic() {
        protectionTriggered = true;
    }

    function triggerReload(status) {
        if (reloadScheduled) return;
        reloadScheduled = true;
        stopTraffic(); // Stop any further requests immediately

        console.warn(`[Defenra] Security challenge required (${status}). Aborting pending requests and reloading...`);
        
        // Short delay to allow the "stop" flag to take effect and console logs to flush
        setTimeout(() => {
            window.location.reload();
        }, 300);
    }

    // --- Intercept Fetch API ---
    window.fetch = async function(...args) {
        if (protectionTriggered) {
            // Circuit breaker: silently fail requests to save the user from ban
            return new Promise(() => {}); // Never resolve (pending) or reject based on app needs
        }

        try {
            const response = await originalFetch.apply(this, args);
            
            if (response.status === 403 || response.status === 429) {
                triggerReload(response.status);
                // Return a dummy promise to keep the app from crashing before reload
                return new Promise(() => {}); 
            }
            
            return response;
        } catch (e) {
            if (protectionTriggered) return new Promise(() => {});
            throw e;
        }
    };

    // --- Intercept XMLHttpRequest ---
    XMLHttpRequest.prototype.open = function(method, url) {
        this._url = url;
        return originalXHROpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function() {
        if (protectionTriggered) {
            // Circuit breaker: abort immediately
            return; 
        }

        this.addEventListener('load', function() {
            if (this.status === 403 || this.status === 429) {
                triggerReload(this.status);
            }
        });

        // Optional: Intercept state changes to catch early errors if needed
        
        try {
            return originalXHRSend.apply(this, arguments);
        } catch (e) {
            if (protectionTriggered) return;
            throw e;
        }
    };
})();