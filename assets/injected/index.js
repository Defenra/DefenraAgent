(function() {
    if (document.getElementById('challenge-form') || window.location.pathname.includes('/challenge')) return;

    /* Powered by Defenra Project: https://github.com/Defenra */
    console.log("[Defenra] System Initialized");

    let protectionTriggered = false;
    const IMAGE_CONCURRENCY = 3; 
    const queue = [];
    let activeRequests = 0;

    function triggerReload(status) {
        if (protectionTriggered) return;
        protectionTriggered = true;
        window.stop();
        
        const overlay = document.getElementById('defenra-status');
        if (overlay) {
            overlay.style.background = "#d9534f";
            overlay.innerHTML = "⚠️ Security Challenge Required. Reloading...";
        }

        setTimeout(() => window.location.reload(), 200);
    }

    function processQueue() {
        if (protectionTriggered || activeRequests >= IMAGE_CONCURRENCY || queue.length === 0) return;

        const item = queue.shift();
        activeRequests++;

        const img = new Image();
        img.onload = () => {
            item.target.src = item.src;
            item.target.style.opacity = "1";
            activeRequests--;
            processQueue();
        };
        img.onerror = () => {
            activeRequests--;
            fetch(item.src, { method: 'HEAD', cache: 'no-store' }).then(res => {
                if (res.status === 403 || res.status === 429) triggerReload(res.status);
                else processQueue();
            }).catch(() => processQueue());
        };
        img.src = item.src;
    }

    const domObserver = new MutationObserver((mutations) => {
        if (protectionTriggered) return;
        mutations.forEach(mutation => {
            mutation.addedNodes.forEach(node => {
                if (node.tagName === 'IMG' && node.src && !node.dataset.controlled) {
                    const originalSrc = node.src;
                    node.dataset.controlled = "true";
                    node.style.opacity = "0.3"; 
                    node.style.transition = "opacity 0.3s";
                    node.src = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
                    queue.push({ target: node, src: originalSrc });
                    processQueue();
                }
            });
        });
    });

    domObserver.observe(document.documentElement, { childList: true, subtree: true });

    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        if (protectionTriggered) return new Promise(() => {});
        try {
            const response = await originalFetch.apply(this, args);
            if (response.status === 403 || response.status === 429) {
                triggerReload(response.status);
                return new Promise(() => {});
            }
            return response;
        } catch (e) {
            if (protectionTriggered) return new Promise(() => {});
            throw e;
        }
    };

    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(m, url) { this._url = url; return originalXHROpen.apply(this, arguments); };
    XMLHttpRequest.prototype.send = function() {
        if (protectionTriggered) return;
        this.addEventListener('load', () => {
            if (this.status === 403 || this.status === 429) triggerReload(this.status);
        });
        return originalXHRSend.apply(this, arguments);
    };

    function injectOverlay() {
        const div = document.createElement('div');
        div.id = "defenra-status";
        div.style = "position:fixed;bottom:20px;left:20px;padding:12px 20px;background:rgba(28,28,28,0.9);color:#fff;z-index:999999;border-radius:8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:13px;box-shadow:0 4px 15px rgba(0,0,0,0.3);display:flex;align-items:center;gap:10px;border:1px solid rgba(255,255,255,0.1);";
        div.innerHTML = `<span style="color:#4caf50">●</span> <b>Defenra</b> Protection Active`;
        document.body.appendChild(div);
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', injectOverlay);
    else injectOverlay();
})();