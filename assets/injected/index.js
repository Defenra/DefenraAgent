(function() {
    if (document.getElementById('challenge-form') || window.location.pathname.includes('/challenge')) return;

    /* Powered by Defenra Project: https://github.com/Defenra */
    
    let protectionTriggered = false;
    const IMAGE_CONCURRENCY = 3;
    const queue = [];
    let activeRequests = 0;
    
    const stats = {
        agents: new Set(),
        totalRequests: 0,
        blockedRequests: 0,
        startTime: new Date().toLocaleTimeString()
    };

    function triggerReload(status) {
        if (protectionTriggered) return;
        protectionTriggered = true;
        window.stop();
        setTimeout(() => window.location.reload(), 200);
    }

    function captureAgent(headers) {
        if (!headers) return;
        const agent = typeof headers.get === 'function' ? headers.get('d-agent-id') : headers['d-agent-id'];
        if (agent) stats.agents.add(agent);
    }

    function processQueue() {
        if (protectionTriggered || activeRequests >= IMAGE_CONCURRENCY || queue.length === 0) return;

        const item = queue.shift();
        activeRequests++;
        stats.totalRequests++;

        const img = new Image();
        img.onload = () => {
            item.target.src = item.src;
            activeRequests--;
            processQueue();
        };
        img.onerror = () => {
            activeRequests--;
            fetch(item.src, { method: 'HEAD', cache: 'no-store' }).then(res => {
                captureAgent(res.headers);
                if (res.status === 418) {
                    stats.blockedRequests++;
                    triggerReload(res.status);
                } else processQueue();
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
            captureAgent(response.headers);
            if (response.status === 418) {
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
            const agent = this.getResponseHeader('d-agent-id');
            if (agent) stats.agents.add(agent);
            if (this.status === 418) triggerReload(this.status);
        });
        return originalXHRSend.apply(this, arguments);
    };

    function toggleDebugMenu() {
        let menu = document.getElementById('defenra-debug');
        if (menu) {
            menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
        } else {
            menu = document.createElement('div');
            menu.id = 'defenra-debug';
            menu.style = "position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:350px;background:#1e1e1e;color:#00ff00;padding:20px;border-radius:10px;font-family:monospace;z-index:1000000;box-shadow:0 0 20px rgba(0,0,0,0.5);border:1px solid #333;font-size:12px;line-height:1.5;";
            updateMenuContent(menu);
            document.body.appendChild(menu);
        }
    }

    function updateMenuContent(menu) {
        const agentList = stats.agents.size > 0 ? Array.from(stats.agents).join('<br>→ ') : 'None detected';
        menu.innerHTML = `
            <div style="border-bottom:1px solid #333;padding-bottom:10px;margin-bottom:10px;display:flex;justify-content:space-between;">
                <b>Defenra Debug Menu</b>
                <span onclick="this.parentElement.parentElement.style.display='none'" style="cursor:pointer;color:#ff0000;">[x]</span>
            </div>
            <div><b>Session Start:</b> ${stats.startTime}</div>
            <div><b>Total Requests:</b> ${stats.totalRequests}</div>
            <div style="margin-top:10px;color:#00e5ff;"><b>Detected Agents:</b></div>
            <div style="padding:5px;background:#121212;border-radius:4px;margin-top:5px;max-height:100px;overflow-y:auto;">
                → ${agentList}
            </div>
            <div style="margin-top:10px;font-size:10px;color:#666;text-align:right;">github.com/Defenra</div>
        `;
    }

    window.addEventListener('keydown', (e) => {
        if (e.key === 'F8') {
            toggleDebugMenu();
            const menu = document.getElementById('defenra-debug');
            if (menu && menu.style.display !== 'none') updateMenuContent(menu);
        }
    });
})();