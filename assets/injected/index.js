(function() {
    // 1. Проверка нахождения на странице самой проверки (Challenge)
    if (document.getElementById('challenge-form') || 
        window.location.pathname.includes('/challenge') || 
        window.location.hostname.includes('challenges.cloudflare.com')) {
        return;
    }

    // Проверяем, был ли релоад вызван защитой, и выводим отчет
    const lastIncident = localStorage.getItem('_defenra_last_incident');
    if (lastIncident) {
        try {
            const data = JSON.parse(lastIncident);
            console.log(`%c[Defenra] Previous session was challenged! Reason: ${data.status} on ${data.url}`, "color: orange; font-weight: bold;");
            localStorage.removeItem('_defenra_last_incident');
        } catch (e) {}
    }

    console.log("[Defenra] Protection Module Active");

    let protectionTriggered = false;
    let reloadScheduled = false;

    const originalFetch = window.fetch;
    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;

    /**
     * Останавливает сетевую активность и инициирует перезагрузку
     */
    function triggerReload(status, url = 'unknown') {
        if (reloadScheduled) return;
        reloadScheduled = true;
        protectionTriggered = true;

        // Сохраняем инцидент для отладки после релоада
        try {
            localStorage.setItem('_defenra_last_incident', JSON.stringify({
                status: status,
                url: url,
                ts: Date.now()
            }));
        } catch (e) {}

        console.warn(`[Defenra] Security challenge detected! Status: ${status} | Resource: ${url}`);
        
        // Прерываем текущий поток выполнения и релоадим
        setTimeout(() => {
            window.location.reload();
        }, 150);
    }

    // --- БЛОК 1: Мониторинг статики (Картинки, Стили, Шрифты) ---
    // Работает для ресурсов с того же домена
    if (window.PerformanceObserver) {
        const observer = new PerformanceObserver((list) => {
            list.getEntries().forEach((entry) => {
                if (entry.entryType === 'resource') {
                    const s = entry.responseStatus;
                    // responseStatus доступен не во всех браузерах (требует Timing-Allow-Origin для CORS)
                    if (s === 403 || s === 429) {
                        triggerReload(s, entry.name);
                    }
                }
            });
        });
        observer.observe({ type: 'resource', buffered: true });
    }

    // Резервный метод для старых браузеров (ловит ошибки загрузки <img>)
    window.addEventListener('error', function(e) {
        if (protectionTriggered) return;
        const target = e.target;
        if (target && (target.tagName === 'IMG' || target.tagName === 'SCRIPT' || target.tagName === 'LINK')) {
            const resourceUrl = target.src || target.href;
            if (!resourceUrl) return;

            // Проверяем доступность через быстрый HEAD запрос
            originalFetch(resourceUrl, { method: 'HEAD' }).then(res => {
                if (res.status === 403 || res.status === 429) triggerReload(res.status, resourceUrl);
            }).catch(() => {});
        }
    }, true);

    // --- БЛОК 2: Перехват Fetch API ---
    window.fetch = async function(...args) {
        if (protectionTriggered) return new Promise(() => {}); // Блокировка

        try {
            const response = await originalFetch.apply(this, args);
            if (response.status === 403 || response.status === 429) {
                triggerReload(response.status, args[0]);
                return new Promise(() => {}); 
            }
            return response;
        } catch (e) {
            if (protectionTriggered) return new Promise(() => {});
            throw e;
        }
    };

    // --- БЛОК 3: Перехват XMLHttpRequest (AJAX) ---
    XMLHttpRequest.prototype.open = function(method, url) {
        this._url = url;
        return originalXHROpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function() {
        if (protectionTriggered) return; 

        this.addEventListener('readystatechange', () => {
            if (this.readyState === 4 && (this.status === 403 || this.status === 429)) {
                triggerReload(this.status, this._url);
            }
        });

        try {
            return originalXHRSend.apply(this, arguments);
        } catch (e) {
            if (protectionTriggered) return;
            throw e;
        }
    };

})();
