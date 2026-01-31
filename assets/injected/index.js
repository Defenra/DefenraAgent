(function() {
    console.log("[Defenra] Protection Module Loaded");

    const originalFetch = window.fetch;
    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;

    // --- Intercept Fetch API ---
    window.fetch = async function(...args) {
        // console.log("[Defenra] Intercepted fetch:", args);
        try {
            const response = await originalFetch.apply(this, args);
            checkChallenge(response);
            return response;
        } catch (e) {
            throw e;
        }
    };

    // --- Intercept XMLHttpRequest ---
    XMLHttpRequest.prototype.open = function(method, url) {
        this._url = url;
        return originalXHROpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function() {
        // console.log("[Defenra] Intercepted XHR:", this._url);
        this.addEventListener('load', function() {
            checkChallenge({
                status: this.status,
                url: this._url
            });
        });
        return originalXHRSend.apply(this, arguments);
    };

    // --- Challenge Detection Logic ---
    function checkChallenge(response) {
        // If the server returns a status code indicating a block or challenge requirement,
        // we reload the main page to allow the user to solve the challenge (CAPTCHA, PoW, etc.)
        // 403: Forbidden (Blocked/Challenge)
        // 429: Too Many Requests (Rate Limit/Challenge)
        if (response.status === 403 || response.status === 429) {
            console.warn("[Defenra] Security challenge required. Reloading page...", response.status);
            
            // Prevent infinite reload loops if the main page itself is 403/429
            // (The browser usually handles main page errors, but this adds safety for SPA)
            // We use a small delay to ensure logs are visible if debugging
            setTimeout(() => {
                window.location.reload();
            }, 500);
        }
    }
})();
