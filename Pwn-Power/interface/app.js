let scanData = [];
let accumulatedNetworks = new Map();
let selectedAP = null;
let selectedClients = {};
let scanInterval = null;
let agoTicker = null;
let privacyMode = false;
let wifiStatusCache = { data: null, timestamp: 0, pending: null };
let scanReportCache = { data: null, timestamp: 0, pending: null };
let manualScanBusy = false;
let bgScanBusy = false;
let authToken = null;
let appInitialized = false;
let authPasswordEnabled = true;

let refreshNetworkIntelligence = async () => {
    await Promise.all([loadDeviceIntelligence(), loadBottleneckAnalysis()]);
};

const scheduleIdle = (fn) => {
    if (typeof requestIdleCallback === 'function') {
        requestIdleCallback(fn);
    } else {
        setTimeout(fn, 0);
    }
};

async function fetchAuthed(url, opts = {}) {
    const headers = Object.assign({}, opts.headers || {});
    if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
    return fetch(url, { ...opts, headers });
}

async function loadAuthStatus() {
    const res = await fetchJSON('/auth/status');
    const textEl = document.getElementById('auth-status-text');
    if (!res) {
        if (textEl) textEl.textContent = 'Auth status unavailable';
        return;
    }
    authPasswordEnabled = !!res.has_password;
    if (textEl) textEl.textContent = res.authorized ? 'Login required (authorized)' : 'Login required (not authorized)';
    if (!authPasswordEnabled) {
        if (textEl) textEl.textContent = 'Login disabled (no password set)';
    }
}

async function updateAuthPassword(newPassword, currentPassword = '') {
    const res = await fetchJSON('/auth/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword })
    });
    return res;
}

async function disableLogin() {
    const current = document.getElementById('auth-current')?.value || '';
    const msg = document.getElementById('auth-message');
    const res = await updateAuthPassword('', current);
    if (res && res.status === 'updated') {
        if (msg) msg.textContent = 'Login disabled. Interface is open until a new password is set.';
        authToken = null;
        localStorage.removeItem('authToken');
        await loadAuthStatus();
    } else {
        if (msg) msg.textContent = 'Failed to disable login (check current password)';
    }
}

function setBusyState(manualBusy, backgroundBusy) {
    manualScanBusy = typeof manualBusy === 'boolean' ? manualBusy : manualScanBusy;
    bgScanBusy = typeof backgroundBusy === 'boolean' ? backgroundBusy : bgScanBusy;

    const banner = document.getElementById('scan-busy-banner');
    if (banner) {
        if (manualScanBusy) {
            banner.textContent = 'Manual scan in progress – actions are temporarily blocked.';
            banner.style.display = 'block';
        } else if (bgScanBusy) {
            banner.textContent = 'Background scan running – some actions are temporarily blocked.';
            banner.style.display = 'block';
        } else {
            banner.style.display = 'none';
        }
    }
}

async function fetchJSON(url, opts = {}) {
    try {
        const headers = Object.assign({}, opts.headers || {});
        if (authToken) headers['Authorization'] = `Bearer ${authToken}`;

        const res = await fetch(url, { ...opts, headers });
        if (!res.ok) {
            console.error(`HTTP error for ${url}: ${res.status} ${res.statusText}`);
            if (res.status === 401) {
                await loadAuthStatus();
                if (authPasswordEnabled) showLogin();
            }
            return null;
        }
        const text = await res.text();
        if (!text || text.length === 0) {
            console.error(`Empty response from ${url}`);
            return null;
        }
        try {
            return JSON.parse(text);
        } catch (parseErr) {
            console.error(`JSON parse error for ${url}:`, parseErr);
            console.error(`Response length: ${text.length}, First 200 chars:`, text.substring(0, 200));
            console.error(`Last 200 chars:`, text.substring(Math.max(0, text.length - 200)));
            return null;
        }
    } catch (e) {
        console.error(`Fetch error for ${url}:`, e);
        return null;
    }
}

function initApp() {
    initPrivacyMode();

    // Fire initial data loads in parallel to reduce blocking
    Promise.all([
        loadScanData(true),
        loadApConfig(),
        loadNetworkStatus(),
        loadGpioStatus(),
        updateBgScanStatus(),
        loadScanSettings(),
        refreshNetworkIntelligence(),
        loadHistoryCharts(7),
        loadWebhookConfig(),
        loadBottleneckAnalysis(),
        loadAuthStatus()
    ]).catch(() => {
        // errors already logged per fetchJSON; keep page load resilient
    });

    // Non-urgent fetches after paint
    scheduleIdle(() => loadHandshakes());
    scheduleIdle(() => loadHomeSSIDs());

    // Sync device sort dropdown with currentSort state
    const deviceSort = $('#device-sort');
    if (deviceSort) {
        deviceSort.value = deviceIntelligenceData.currentSort;
    }

    addTrackedInterval(loadNetworkStatus, 10000);
    addTrackedInterval(updateBgScanStatus, 5000);
    addTrackedInterval(refreshNetworkIntelligence, 15000); // Reduced from 60s to 15s for better responsiveness
    addTrackedInterval(loadBottleneckAnalysis, 30000); // Update bottleneck analysis every 30 seconds
    if (!agoTicker) agoTicker = addTrackedInterval(updateAgoTick, 1000);

    const apForm = $('#ap-config-form');
    if (apForm) apForm.onsubmit = saveApConfig;

    const netForm = $('#network-form');
    if (netForm) netForm.onsubmit = connectToNetwork;

    const webhookForm = $('#webhook-form');
    if (webhookForm) webhookForm.onsubmit = saveWebhookConfig;

    const authForm = $('#auth-form');
    if (authForm) authForm.onsubmit = async (e) => {
        e.preventDefault();
        const newPassword = document.getElementById('auth-new')?.value || '';
        const currentPassword = document.getElementById('auth-current')?.value || '';
        const res = await updateAuthPassword(newPassword, currentPassword);
        const msg = document.getElementById('auth-message');
        if (res && res.status === 'updated') {
            if (msg) msg.textContent = res.disabled ? 'Login disabled. Interface is open until a new password is set.' : 'Password updated.';
            document.getElementById('auth-new').value = '';
            document.getElementById('auth-current').value = '';
            await loadAuthStatus();
        } else {
            if (msg) msg.textContent = 'Failed to update password (check current password)';
        }
    };
}

function showLogin(error = false) {
    if (!authPasswordEnabled) return; // do not show overlay when login disabled
    const login = document.getElementById('login-screen');
    const app = document.getElementById('app-shell');
    if (login) login.style.display = 'flex';
    if (app) app.style.display = 'none';
    const err = document.getElementById('login-error');
    if (err) err.style.display = error ? 'block' : 'none';

    authToken = null;
    localStorage.removeItem('authToken');
}

function showAppShell() {
    const login = document.getElementById('login-screen');
    const app = document.getElementById('app-shell');
    if (login) login.style.display = 'none';
    if (app) app.style.display = 'block';
}

async function attemptLogin(password) {
    const res = await fetchJSON('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
    });
    if (res && res.token) {
        authToken = res.token;
        localStorage.setItem('authToken', authToken);
        showLogin(false);
        showAppShell();
        if (!appInitialized) {
            initApp();
            appInitialized = true;
        }
        return true;
    }
    showLogin(true);
    return false;
}

async function checkAuthAndStart() {
    authToken = localStorage.getItem('authToken') || null;
    const status = await fetchJSON('/auth/status');
    if (status && status.authorized) {
        showAppShell();
        if (!appInitialized) {
            initApp();
            appInitialized = true;
        }
    } else if (status && status.has_password === false) {
        authPasswordEnabled = false;
        showAppShell();
        if (!appInitialized) {
            initApp();
            appInitialized = true;
        }
    } else if (!status) {
        // if status unavailable (e.g., transient TLS error), keep current view
        if (appInitialized) {
            showAppShell();
        }
    } else {
        showLogin(false);
    }
}

function initLoginUI() {
    const btn = document.getElementById('login-submit');
    const input = document.getElementById('login-password');
    if (btn) {
        btn.onclick = async () => {
            const pass = input?.value || '';
            if (!pass) return showLogin(true);
            await attemptLogin(pass);
        };
    }
    if (input) {
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                btn?.click();
            }
        });
    }
}

function anyScanBusy() {
    return manualScanBusy || bgScanBusy;
}

function isBlockedAction(actionLabel = 'This action') {
    if (manualScanBusy) {
        showToast(`${actionLabel} is blocked while a manual scan is running.`);
        return true;
    }
    if (bgScanBusy) {
        showToast(`${actionLabel} is blocked while a background scan is running.`);
        return true;
    }
    return false;
}

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function togglePrivacyMode() {
    privacyMode = !privacyMode;
    localStorage.setItem('privacyMode', privacyMode);
    applyPrivacyMode();
}

async function getScanReport(force = false) {
    const now = Date.now();
    if (!force && scanReportCache.data && now - scanReportCache.timestamp < 5000) {
        return scanReportCache.data;
    }
    if (scanReportCache.pending) return scanReportCache.pending;

    scanReportCache.pending = fetchJSON('/scan/report').then((res) => {
        scanReportCache.data = res;
        scanReportCache.timestamp = Date.now();
        scanReportCache.pending = null;
        return res;
    }).catch((e) => {
        scanReportCache.pending = null;
        throw e;
    });
    return scanReportCache.pending;
}

async function getWifiStatus(force = false) {
    const now = Date.now();
    if (!force && wifiStatusCache.data && now - wifiStatusCache.timestamp < 5000) {
        return wifiStatusCache.data;
    }
    if (wifiStatusCache.pending) return wifiStatusCache.pending;

    wifiStatusCache.pending = fetchJSON('/wifi/status').then((res) => {
        wifiStatusCache.data = res;
        wifiStatusCache.timestamp = Date.now();
        wifiStatusCache.pending = null;
        return res;
    }).catch((e) => {
        wifiStatusCache.pending = null;
        throw e;
    });
    return wifiStatusCache.pending;
}

function applyPrivacyMode() {
    const btn = $('#privacy-toggle');
    if (privacyMode) {
        document.body.classList.add('privacy-mode');
        if (btn) btn.classList.add('active');
        $('#privacy-icon').textContent = '⊘';
    } else {
        document.body.classList.remove('privacy-mode');
        if (btn) btn.classList.remove('active');
        $('#privacy-icon').textContent = '◉';
    }
    // Re-render charts to update SSID labels
    if (chartCache.size > 0) {
        chartCache.forEach((cached) => {
            if (cached.canvasId === '#ssid-clients-chart') {
                drawSSIDClientsChart(cached.canvasId, cached.samples, cached.config);
            }
        });
    }
}

function initPrivacyMode() {
    privacyMode = localStorage.getItem('privacyMode') === 'true';
    applyPrivacyMode();
}

function pii(value, type) {
    if (!value) return value;
    return `<span class="pii-${type}">${value}</span>`;
}

function toggleSection(id) {
    const section = document.getElementById(id);
    section.classList.toggle('expanded');
}

function showToast(msg) {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function showWarningPopup(msg) {
    const overlay = document.createElement('div');
    overlay.className = 'popup-overlay';
    
    const popup = document.createElement('div');
    popup.className = 'popup';
    popup.innerHTML = `
        <div class="popup-header">Warning</div>
        <div class="popup-body">${msg}</div>
        <div class="popup-footer">
            <button class="btn" onclick="this.closest('.popup-overlay').remove()">OK</button>
        </div>
    `;
    
    overlay.appendChild(popup);
    document.body.appendChild(overlay);
}

async function loadScanData(preventNewScan = false) {
    const [data, status] = await Promise.all([
        fetchJSON('/cached-scan'),
        getWifiStatus()
    ]);

    // Check if scan is in progress
    if (data && data.scan_in_progress) {
        showToast('Scan in progress, showing cached data...');
    }

    // Show warning if data was truncated
    if (data && data.truncated) {
        showToast('Warning: Scan results were truncated due to large data size', 'warning');
    }

    // If no cached data and we're allowed to trigger new scan, try /scan
    if ((!data || !data.rows || data.rows.length === 0) && !preventNewScan) {
        // Don't auto-trigger scan on refresh - user should click "Scan Networks"
        showToast('No cached scan data. Click "Scan Networks" to start a scan.');
        return;
    }
    if (data && data.rows) {
        scanData = data.rows;
        
        data.rows.forEach(ap => {
            const existing = accumulatedNetworks.get(ap.MAC);
            if (existing) {
                existing.RSSI = ap.RSSI;
                existing.last_seen = ap.last_seen;
                existing.Channel = ap.Channel;
                existing.Security = ap.Security;
                
                if (!existing.stations) existing.stations = [];
                const clientMap = new Map(existing.stations.map(s => [s.mac, s]));
                if (ap.stations && ap.stations.length > 0) {
                    ap.stations.forEach(sta => {
                        clientMap.set(sta.mac, sta);
                    });
                }
                existing.stations = Array.from(clientMap.values());
            } else {
                accumulatedNetworks.set(ap.MAC, {
                    ...ap,
                    stations: ap.stations ? [...ap.stations] : []
                });
            }
        });
        
        renderNetworkTable('wifi-table', true, status);
        renderChannelChart();
        updateStats(data.timestamp, status);
    }
}

function computeLastSeenTimestamp(status, lastSeenEpoch) {
    const epochNow = status?.timestamp;
    const timeSynced = status?.time_synced;

    if (!lastSeenEpoch || !timeSynced || !epochNow) return '--';
    if (lastSeenEpoch > epochNow) return '--';

    return new Date(lastSeenEpoch * 1000).toISOString();
}

function computeLastSeenRelative(status, lastSeenEpoch) {
    const epochNow = status?.timestamp;
    const timeSynced = status?.time_synced;

    // If no valid timestamp or time not synced, show "Unknown"
    if (!lastSeenEpoch || !timeSynced || !epochNow) return 'Unknown';
    if (lastSeenEpoch > epochNow) return 'Unknown';

    const ageSec = Math.floor(epochNow - lastSeenEpoch);
    
    // If the age is very large (years), likely timestamp issue
    if (ageSec > 31536000) return 'Unknown';
    
    return formatUptime(ageSec);
}

function renderNetworkTable(tableId, selectable, status) {
    const tbody = $(`#${tableId}`);
    if (!tbody) return;
    tbody.innerHTML = '';
    const nowMs = Date.now();
    
    const dataToRender = Array.from(accumulatedNetworks.values());
    
    dataToRender.forEach(ap => {
        const row = document.createElement('tr');
        row.dataset.mac = ap.MAC;
        row.dataset.channel = ap.Channel;
        const lastSeenText = computeLastSeenRelative(status, ap.last_seen);
        const clientCount = (ap.stations && ap.stations.length > 0) ? ap.stations.length : 0;
        const expandIcon = clientCount > 0 ? '<span class="expand-icon" style="vertical-align: middle; margin-right: 4px;"></span>' : '';
        
        row.innerHTML = `
            <td>${expandIcon}<span style="vertical-align: middle; ${expandIcon ? 'margin-left: 4px;' : ''}">${pii(ap.SSID || '(Hidden)', 'ssid')}</span></td>
            <td><code>${pii(ap.MAC, 'mac')}</code></td>
            <td class="muted">${pii(ap.Vendor || 'Unknown', 'vendor')}</td>
            <td>${ap.Security}</td>
            <td>${ap.wps ? 'Yes' : 'No'}</td>
            <td>${ap.Channel}</td>
            <td>${ap.RSSI || '--'}</td>
            <td class="muted">${lastSeenText}</td>
        `;
        
        // Add expand/collapse for APs with clients
        if (clientCount > 0) {
            row.classList.add('has-clients');
            const expandIcon = row.querySelector('.expand-icon');
            const toggleClients = (e) => {
                e.stopPropagation();
                const isExpanded = row.classList.toggle('expanded');
                // Toggle visibility of client rows
                const clientRows = tbody.querySelectorAll(`tr.client-row[data-ap-mac="${ap.MAC}"]`);
                clientRows.forEach(cr => {
                    cr.style.display = isExpanded ? '' : 'none';
                });
            };
            
            if (expandIcon) {
                expandIcon.style.cursor = 'pointer';
                expandIcon.onclick = toggleClients;
            }
        }
        
        if (selectable) {
            row.onclick = () => selectAP(row, ap);
        }
        
        tbody.appendChild(row);
        
        if (ap.stations && ap.stations.length > 0) {
            ap.stations.forEach(sta => {
                const clientRow = document.createElement('tr');
                clientRow.className = 'client-row';
                clientRow.dataset.apMac = ap.MAC;
                clientRow.dataset.staMac = sta.mac;
                clientRow.style.display = 'none'; // Hidden by default
                const staLastSeenText = computeLastSeenRelative(status, sta.last_seen);
                
                // Build grouped MACs display if available
                let macDisplay = pii(sta.mac, 'mac');
                if (sta.grouped_macs && sta.grouped_macs.length > 0) {
                    const groupedList = sta.grouped_macs.map(m => pii(m, 'mac')).join(', ');
                    macDisplay += ` <span class="muted" style="font-size:0.85em">(+${sta.grouped_count - 1} more: ${groupedList})</span>`;
                }
                
                clientRow.innerHTML = `
                    <td>↳ Client</td>
                    <td><code>${macDisplay}</code></td>
                    <td class="muted">${pii(sta.device_vendor || sta.vendor || 'Unknown', 'vendor')}</td>
                    <td></td>
                    <td></td>
                    <td></td>
                    <td>${sta.rssi}</td>
                    <td class="muted">${staLastSeenText}</td>
                `;
                if (selectable) {
                    clientRow.onclick = (e) => {
                        e.stopPropagation();
                        selectClient(clientRow, ap.MAC, sta.mac);
                    };
                }
                tbody.appendChild(clientRow);
            });
        }
    });
}

function selectAP(row, ap) {
    const wasSelected = row.classList.contains('selected');
    $$('#wifi-table tr.selected').forEach(r => r.classList.remove('selected'));
    
    if (wasSelected) {
        selectedAP = null;
        selectedClients = {};
        $('#attack-options').style.display = 'none';
    } else {
        selectedClients = {};
        row.classList.add('selected');
        selectedAP = ap;
        $('#attack-options').style.display = 'block';
        $('#selected-target').textContent = ap.SSID || ap.MAC;
    }
}

function selectClient(row, apMac, staMac) {
    row.classList.toggle('selected');
    if (!selectedClients[apMac]) selectedClients[apMac] = [];
    const idx = selectedClients[apMac].indexOf(staMac);
    if (idx > -1) {
        selectedClients[apMac].splice(idx, 1);
    } else {
        selectedClients[apMac].push(staMac);
    }
    
    const hasSelectedClients = Object.values(selectedClients).some(arr => arr.length > 0);
    if (hasSelectedClients && !selectedAP) {
        $('#attack-options').style.display = 'block';
        $('#selected-target').textContent = `${Object.values(selectedClients).flat().length} client(s)`;
    } else if (!hasSelectedClients && !selectedAP) {
        $('#attack-options').style.display = 'none';
    }
}

function renderChannelChart() {
    const container = $('#channel-chart');
    if (!container) return;
    
    const channels = {};
    const dataSource = Array.from(accumulatedNetworks.values());
    dataSource.forEach(ap => {
        const ch = ap.Channel;
        channels[ch] = (channels[ch] || 0) + 1;
    });
    
    const maxCount = Math.max(...Object.values(channels), 1);
    container.innerHTML = '';
    
    for (let ch = 1; ch <= 13; ch++) {
        const count = channels[ch] || 0;
        const height = (count / maxCount) * 100;
        const bar = document.createElement('div');
        bar.className = 'chart-bar';
        bar.style.height = `${Math.max(height, 5)}%`;
        bar.innerHTML = `<span class="chart-bar-label">${ch}</span>`;
        bar.title = `Channel ${ch}: ${count} APs`;
        container.appendChild(bar);
    }
}

function updateStats(scanTimestamp, wifiStatus) {
    const apCount = accumulatedNetworks.size;
    let clientCount = 0;
    const dataSource = Array.from(accumulatedNetworks.values());
    dataSource.forEach(ap => {
        if (ap.stations) clientCount += ap.stations.length;
    });

    const statEl = $('#scan-stats');
    if (statEl) {
        let statsText = `${apCount} APs, ${clientCount} clients`;

        // Add age of data if we have timestamp and wifi status
        if (scanTimestamp && wifiStatus && wifiStatus.timestamp) {
            const age = wifiStatus.timestamp - scanTimestamp;
            if (age > 0 && age < 86400) { // Less than 24 hours
                const minutes = Math.floor(age / 60);
                const seconds = Math.floor(age % 60);
                if (minutes > 0) {
                    statsText += ` (${minutes}m ago)`;
                } else if (seconds > 5) {
                    statsText += ` (${seconds}s ago)`;
                } else {
                    statsText += ` (just now)`;
                }
            }
        }

        statEl.textContent = statsText;
    }
}

let scanInProgress = false;

// Check if scan was in progress when page loaded (e.g., after reconnection)
try {
    const lastScanTime = parseInt(sessionStorage.getItem('lastScanTime') || '0');
    const now = Date.now();
    // If scan started less than 30 seconds ago, assume still in progress
    if (now - lastScanTime < 30000) {
        scanInProgress = true;
        console.log('Detected recent scan, setting lock');
    }
} catch (e) {
    // sessionStorage not available
}

async function checkScanStatus() {
    const status = await fetchJSON('/wifi/scan-status');
    const inProgress = status?.scan_in_progress || false;
    if (inProgress) {
        setBusyState(true, bgScanBusy);
    }
    return inProgress;
}

// Track the active scan abort controller to prevent retries
let activeScanController = null;

async function triggerScan() {
    if (isBlockedAction('Manual scan')) return;

    console.log('=== triggerScan() called at', new Date().toISOString(), '===');
    console.log('Current state: scanInProgress=', scanInProgress);
    console.trace('Call stack:'); // Show where this was called from

    // Check actual backend scan status
    const backendScanning = await checkScanStatus();
    console.log('Backend scanning status:', backendScanning);

    if (scanInProgress || backendScanning) {
        console.warn('Scan already in progress, aborting');
        setBusyState(true, bgScanBusy);
        showToast('Scan already in progress');
        return;
    }

    // Abort any previous scan request that might be stuck
    if (activeScanController) {
        console.log('Aborting previous scan controller');
        activeScanController.abort();
        activeScanController = null;
    }

    console.log('Starting new scan, creating AbortController...');
    scanInProgress = true;
    setBusyState(true, bgScanBusy);
    // Store scan start time in sessionStorage to survive page reloads
    try {
        sessionStorage.setItem('lastScanTime', Date.now().toString());
    } catch (e) {
        // sessionStorage not available
    }
    showWarningPopup('Scanning will temporarily interrupt your connection. You will need to reconnect or refresh this page after the scan completes.');

    // Create abort controller for this scan
    activeScanController = new AbortController();

    try {
        // The /scan endpoint is blocking and completes the scan before returning
        const result = await fetchAuthed('/scan', { signal: activeScanController.signal });

        // Check if request was successful
        if (result && result.ok) {
            await loadScanData(true);
            showToast('Scan complete');
        } else {
            // Connection dropped during scan (expected)
            console.log('Scan connection interrupted (expected), waiting for reconnection...');
            await new Promise(resolve => setTimeout(resolve, 3000)); // Wait 3 seconds
            await loadScanData(true);
            showToast('Scan complete');
        }
    } catch (error) {
        if (error.name === 'AbortError') {
            console.log('Scan request was aborted');
        } else {
            console.error('Scan error:', error);
            // Connection dropped, wait and load cached results
            await new Promise(resolve => setTimeout(resolve, 3000));
            await loadScanData(true);
            showToast('Scan completed but connection was interrupted');
        }
    } finally {
        activeScanController = null;
        scanInProgress = false;
        setBusyState(false, bgScanBusy);
        // Clear the scan lock
        try {
            sessionStorage.removeItem('lastScanTime');
        } catch (e) {
            // sessionStorage not available
        }
    }
}

async function startDeauth() {
    if (isBlockedAction('Deauth attack')) return;
    if (!selectedAP) return showToast('Select a target first');
    
    const targets = selectedClients[selectedAP.MAC] || [];
    const body = {
        mac: selectedAP.MAC,
        channel: String(selectedAP.Channel),
        state: 'started',
        sta: targets
    };
    
    showToast('Deauth started...');
    await fetchJSON('/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
}

async function startHandshake() {
    if (isBlockedAction('Handshake capture')) return;
    if (!selectedAP) return showToast('Select a target first');
    
    const targets = selectedClients[selectedAP.MAC] || [];
    const body = {
        mac: selectedAP.MAC,
        channel: selectedAP.Channel,
        duration: 30,
        sta: targets
    };
    
    showToast('Capturing handshake...');
    await fetchJSON('/handshake', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
}

async function updateBgScanStatus() {
    const data = await fetchJSON('/scan/status');
    if (!data) return;
    
    const dot = $('#bg-scan-dot');
    const text = $('#bg-scan-text');
    const count = $('#bg-scan-count');
    
    if (dot && text) {
        if (data.state === 'running') {
            dot.className = 'status-dot warning';
            text.textContent = 'Scanning...';
        } else if (data.state === 'waiting') {
            dot.className = 'status-dot online';
            text.textContent = 'Active';
        } else {
            dot.className = 'status-dot';
            text.textContent = data.state;
        }
    }
    if (count) count.textContent = data.record_count || 0;

    setBusyState(manualScanBusy, data.state === 'running');
}

async function triggerBgScan() {
    if (isBlockedAction('Background scan')) return;
    showWarningPopup('Scanning will temporarily interrupt your connection. You may need to reconnect or refresh this page after the scan completes.');
    setBusyState(manualScanBusy, true);
    await fetchJSON('/scan/trigger', { method: 'POST' });
    setTimeout(updateBgScanStatus, 1000);
}

async function loadScanSettings() {
    const data = await fetchJSON('/scan/settings');
    if (!data) return;
    
    const bgEnabled = $('#bg-enabled');
    const bgInterval = $('#bg-interval');
    const autoHs = $('#auto-handshake');
    const idleThresh = $('#idle-threshold');
    const hsDur = $('#hs-duration');
    
    if (bgEnabled) bgEnabled.checked = data.bg_enabled;
    if (bgInterval) bgInterval.value = Math.round(data.bg_interval / 60);
    if (autoHs) autoHs.checked = data.auto_handshake;
    if (idleThresh) idleThresh.value = data.idle_threshold;
    if (hsDur) hsDur.value = data.handshake_duration;
    
    // Store scan interval globally for gap detection
    window.currentScanInterval = Math.round(data.bg_interval / 60);
}

async function saveScanSettings() {
    const bgEnabled = $('#bg-enabled')?.checked ?? true;
    const bgInterval = parseInt($('#bg-interval')?.value || 5) * 60;
    const autoHs = $('#auto-handshake')?.checked ?? true;
    const idleThresh = parseInt($('#idle-threshold')?.value || 60);
    const hsDur = parseInt($('#hs-duration')?.value || 30);
    
    await fetchJSON('/scan/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            bg_enabled: bgEnabled,
            bg_interval: bgInterval,
            auto_handshake: autoHs,
            idle_threshold: idleThresh,
            handshake_duration: hsDur
        })
    });
    showToast('Settings saved');
    
    // Update global scan interval for gap detection
    window.currentScanInterval = Math.round(bgInterval / 60);
}


async function loadApConfig() {
    const data = await fetchJSON('/ap/config');
    if (!data) return;
    
    const ssidEl = $('#current-ssid');
    if (ssidEl) {
        ssidEl.innerHTML = pii(data.ssid || '--', 'ssid');
    }
    $('#current-security').textContent = data.has_password ? 'WPA2/WPA3' : 'Open';
    $('#ap-ssid').placeholder = data.ssid || 'SSID';
}

async function saveApConfig(e) {
    e.preventDefault();
    const ssid = $('#ap-ssid').value;
    const pass = $('#ap-pass').value;
    
    if (!ssid) return showToast('Enter SSID');
    if (pass && pass.length < 8) return showToast('Password must be 8+ chars');
    
    const res = await fetchJSON('/ap/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ssid, password: pass })
    });
    
    if (res && res.status === 'ok') {
        showToast('Settings saved. Reconnect to new AP.');
        loadApConfig();
    } else {
        showToast('Failed to save settings');
    }
}

async function loadNetworkStatus() {
    const data = await getWifiStatus(true);
    const dot = $('#net-status-dot');
    const text = $('#net-status-text');
    const info = $('#net-info');
    const autoToggle = $('#auto-connect-toggle');
    const apToggle = $('#ap-while-connected-toggle');
    
    if (data && data.status === 'connected') {
        if (dot) dot.className = 'status-dot online';
        if (text) text.textContent = 'Connected';
        if (info) info.innerHTML = pii(data.saved_ssid || '', 'ssid');
    } else {
        if (dot) dot.className = 'status-dot offline';
        if (text) text.textContent = 'Disconnected';
        if (info) {
            if (data && data.has_saved && data.saved_ssid) {
                info.innerHTML = `Saved: ${pii(data.saved_ssid, 'ssid')}`;
            } else {
                info.textContent = 'No network saved';
            }
        }
    }
    
    if (autoToggle) autoToggle.checked = data ? data.auto_connect : true;
    if (apToggle) apToggle.checked = data ? data.ap_while_connected : true;
}

async function toggleAutoConnect() {
    const enabled = $('#auto-connect-toggle').checked;
    await fetchJSON('/wifi/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ auto_connect: enabled })
    });
    showToast(enabled ? 'Auto-connect enabled' : 'Auto-connect disabled');
}

async function toggleApWhileConnected() {
    const enabled = $('#ap-while-connected-toggle').checked;
    await fetchJSON('/wifi/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ap_while_connected: enabled })
    });
    showToast(enabled ? 'AP will stay active when connected' : 'AP will disable when connected');
}

async function forgetNetwork() {
    await fetchJSON('/wifi/disconnect', { method: 'POST' });
    showToast('Saved network cleared');
    loadNetworkStatus();
}

async function connectToNetwork(e) {
    if (isBlockedAction('Connect')) return;
    e.preventDefault();
    const ssid = $('#net-ssid').value;
    const pass = $('#net-pass').value;
    
    if (!ssid) return showToast('Enter SSID');
    
    showToast('Connecting...');
    const res = await fetchJSON('/wifi/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ssid, password: pass })
    });
    
    if (res) {
        if (res.status === 'ok') {
            showToast('Connected! Credentials saved for auto-reconnect on boot.');
        } else {
            showToast(res.message || 'Connection failed');
        }
        setTimeout(loadNetworkStatus, 2000);
    }
}

function formatUptime(sec) {
    sec = Math.max(0, Math.floor(sec || 0));
    // handle overflow (UINT32_MAX or invalid values)
    if (sec > 4000000000 || sec === 4294967295) return 'never';
    if (sec < 60) return sec + 's ago';
    if (sec < 3600) return Math.floor(sec / 60) + 'm ago';
    if (sec < 86400) return Math.floor(sec / 3600) + 'h ago';
    if (sec < 31536000) return Math.floor(sec / 86400) + 'd ago';  // less than 1 year
    return 'long ago';
}

function updateAgoTick() {
    const now = Date.now();
    document.querySelectorAll('.js-ago').forEach(el => {
        const base = parseInt(el.dataset.agoBase || '0', 10);
        const start = parseInt(el.dataset.agoStart || '0', 10);
        if (!start) return;
        const sec = base + Math.floor((now - start) / 1000);
        // prevent overflow display bugs
        if (sec < 0 || sec > 4000000000) {
            el.textContent = 'never';
        } else {
            el.textContent = formatUptime(sec);
        }
    });
}

async function loadHandshakes() {
    const container = $('#handshake-list');
    if (!container) return;
    
    try {
        const [arrRaw, statusRes] = await Promise.all([
            fetchJSON('/captures'),
            getWifiStatus()
        ]);

        const arr = arrRaw || [];
        if (arr.length === 0) {
            container.innerHTML = '<div class="muted">No captures yet</div>';
            return;
        }

        const uptime = statusRes?.uptime || 0;
        
        const nowMs = Date.now();
        container.innerHTML = arr.map(h => {
            const ago = Math.max(0, uptime - h.timestamp);
            const typeLabel = h.auto ? 'Auto Capture' : 'Manual Capture';
            return `
            <div class="card" style="display:flex;justify-content:space-between;align-items:center;">
                <div>
                    <strong>${typeLabel}</strong>
                    <div class="muted"><span class="pii-bssid">${h.bssid}</span> • ch ${h.channel} • ${h.eapol} EAPOL</div>
                    <div class="muted"><span class="js-ago" data-ago-base="${ago}" data-ago-start="${nowMs}">${formatUptime(ago)}</span></div>
                </div>
                <a href="/handshake.pcap" class="btn">Download</a>
            </div>`;
        }).join('');

        updateAgoTick();
    } catch (e) {
        container.innerHTML = '<div class="muted">No captures yet</div>';
    }
}

async function controlGpio(value) {
    const res = await fetchJSON('/gpio', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin: 4, value })
    });
    
    if (res) {
        const dot = $('#gpio-dot');
        const text = $('#gpio-text');
        if (dot) dot.className = value ? 'status-dot online' : 'status-dot offline';
        if (text) text.textContent = value ? 'On' : 'Off';
    }
}

async function loadGpioStatus() {
    const res = await fetchJSON('/gpio/status?pin=4');
    if (res) {
        const dot = $('#gpio-dot');
        const text = $('#gpio-text');
        if (dot) dot.className = res.value ? 'status-dot online' : 'status-dot offline';
        if (text) text.textContent = res.value ? 'On' : 'Off';
    }
}

let deviceIntelligenceData = {
    devices: [],
    intelligence: null,
    report: null,
    currentFilter: 'all',
    currentSort: 'last_seen',
    currentAPFilter: 'all',
    devicesPerPage: 10,
    displayedDevices: 10
};

let lastDeviceDataHash = '';
async function loadDeviceIntelligence() {
    // try new unified endpoint first (more efficient)
    const unified = await fetchJSON('/intelligence/unified');

    if (unified && unified.summary && unified.devices) {
        // Quick hash to detect changes
        const dataHash = `${unified.summary.presence.devices_present}-${unified.summary.presence.devices_away}-${unified.devices.length}`;
        const dataChanged = dataHash !== lastDeviceDataHash;
        lastDeviceDataHash = dataHash;

        // use unified response
        deviceIntelligenceData.intelligence = {
            presence: unified.summary.presence,
            security: unified.summary.security,
            uptime_hours: unified.summary.uptime_hours
        };
        deviceIntelligenceData.report = {
            summary: {
                unique_aps: unified.summary.network.unique_aps,
                unique_stations: unified.summary.network.unique_stations
            },
            channel_analysis: {
                channels: new Array(unified.summary.network.active_channels)
            }
        };
        deviceIntelligenceData.devices = unified.devices;

        // Only update UI if data actually changed
        if (dataChanged) {
            updateIntelligenceSummary();
            populateAPFilter();
            renderDeviceList();
        }
        return;
    } else {
        // fallback to legacy multi-endpoint approach
        const [intelligence, presence, deviceList, report] = await Promise.all([
            fetchJSON('/intelligence'),
            fetchJSON('/devices/presence'),
            fetchJSON('/devices/list'),
            getScanReport()
        ]);
        
        if (!intelligence || !presence || !deviceList) {
            showToast('failed to load device intelligence');
            return;
        }
        
        deviceIntelligenceData.intelligence = intelligence;
        deviceIntelligenceData.report = report;
        
        const deviceMap = new Map();
        
        if (presence.devices) {
            presence.devices.forEach(d => {
                deviceMap.set(d.mac, {
                    mac: d.mac,
                    vendor: d.vendor || 'unknown',
                    rssi: d.rssi,
                    sightings: d.sightings,
                    present: d.present,
                    last_seen_ago: d.last_seen_ago || 0,
                    last_seen_epoch: d.last_seen_epoch || 0,
                    epoch_valid: d.epoch_valid || 0,
                    last_ap: d.last_ap || 'unknown',
                    trust_score: 10,
                    tracked: false
                });
            });
        }
        
        if (deviceList.devices) {
            deviceList.devices.forEach(d => {
                const existing = deviceMap.get(d.mac);
                if (existing) {
                    existing.trust_score = d.trust_score || 10;
                    existing.tracked = d.tracked || false;
                    existing.sightings = d.sightings || existing.sightings;
                    if (d.last_ap) existing.last_ap = d.last_ap;
                } else {
                    deviceMap.set(d.mac, {
                        mac: d.mac,
                        vendor: d.vendor || 'unknown',
                        rssi: d.rssi || 0,
                        sightings: d.sightings || 0,
                        present: d.present || false,
                        last_seen_ago: d.last_seen_ago || 0,
                    last_seen_epoch: d.last_seen_epoch || 0,
                    epoch_valid: d.epoch_valid || 0,
                        last_ap: d.last_ap || 'unknown',
                        trust_score: d.trust_score || 10,
                        tracked: d.tracked || false
                    });
                }
            });
        }
        
        deviceIntelligenceData.devices = Array.from(deviceMap.values());

        updateIntelligenceSummary();
        populateAPFilter();
        renderDeviceList();
    }
}

function populateAPFilter() {
    const apFilter = $('#ap-filter');
    if (!apFilter) return;

    const aps = new Set();
    deviceIntelligenceData.devices.forEach(d => {
        if (d.last_ap && d.last_ap !== 'unknown') {
            aps.add(d.last_ap);
        }
    });

    const sortedAPs = Array.from(aps).sort();
    apFilter.innerHTML = '<option value="all">All APs</option>' +
        sortedAPs.map(ap => `<option value="${ap}" class="pii-ssid">${ap}</option>`).join('');
}

function updateIntelligenceSummary() {
    const data = deviceIntelligenceData.intelligence;
    const report = deviceIntelligenceData.report;
    const devices = deviceIntelligenceData.devices;
    
    const el = (id) => document.getElementById(id);
    
    if (data && data.presence) {
        const p = data.presence;
        if (el('intel-present')) el('intel-present').textContent = p.devices_present || 0;
        if (el('intel-away')) el('intel-away').textContent = p.devices_away || 0;
        if (el('intel-new')) el('intel-new').textContent = p.new_today || 0;
        if (el('intel-total')) el('intel-total').textContent = (p.devices_present || 0) + (p.devices_away || 0);
    }
    
    if (data && data.security) {
        const s = data.security;
        if (el('intel-deauth')) el('intel-deauth').textContent = s.deauth_events || 0;
        if (el('intel-rogue')) el('intel-rogue').textContent = s.rogue_aps || 0;
        if (el('intel-open')) el('intel-open').textContent = s.open_networks || 0;
        if (el('intel-hidden')) el('intel-hidden').textContent = s.hidden_networks || 0;
    }
    
    if (data && data.uptime_hours !== undefined) {
        if (el('intel-uptime')) el('intel-uptime').textContent = data.uptime_hours.toFixed(1) + 'h';
    }
    
    if (report) {
        if (report.summary) {
            if (el('intel-aps')) el('intel-aps').textContent = report.summary.unique_aps || 0;
            if (el('intel-clients')) el('intel-clients').textContent = report.summary.unique_stations || 0;
        }
        if (report.channel_analysis && report.channel_analysis.channels) {
            if (el('intel-channels')) el('intel-channels').textContent = report.channel_analysis.channels.length || 0;
        }
    }
}

function getTrustCategory(trustScore) {
    if (trustScore > 70) return 'trusted';
    if (trustScore > 50) return 'known';
    if (trustScore > 30) return 'familiar';
    return 'new';
}

function getTrustLabel(trustScore) {
    if (trustScore > 70) return 'Trusted';
    if (trustScore > 50) return 'Known';
    if (trustScore > 30) return 'Familiar';
    return 'New';
}

function renderPresenceHeatmap(presenceHours) {
    if (!presenceHours || presenceHours.length < 3) {
        return '<div class="heatmap-label">No presence data</div>';
    }

    let html = '<div class="heatmap-label"><span>24-Hour Activity</span><span>Hover for time</span></div>';
    html += '<div class="presence-heatmap">';

    // Get current local time to calculate proper hour labels
    const now = new Date();
    const currentHour = now.getHours();

    for (let hour = 0; hour < 24; hour++) {
        const byteIndex = Math.floor(hour / 8);
        const bitIndex = hour % 8;
        const isPresent = (presenceHours[byteIndex] >> bitIndex) & 1;
        
        // Calculate actual hour in local time (24-hour format)
        const localHour = (currentHour - 23 + hour + 24) % 24;
        const timeLabel = `${localHour.toString().padStart(2, '0')}:00`;
        
        html += `<div class="hour ${isPresent ? 'active' : ''}" title="${timeLabel}"></div>`;
    }

    html += '</div>';
    
    // Update hour labels to show actual local time range
    const startHour = (currentHour - 23 + 24) % 24;
    const hourLabels = [startHour, (startHour + 6) % 24, (startHour + 12) % 24, (startHour + 18) % 24, (startHour + 23) % 24];
    html += `<div class="heatmap-hours">${hourLabels.map(h => `<span>${h.toString().padStart(2, '0')}</span>`).join('')}</div>`;
    
    return html;
}

function calculateReliabilityScore(device) {
    // Simple reliability calculation based on sightings vs time tracked
    const sightings = device.sightings || 0;
    const daysTracked = device.days_tracked || 1;

    // Expected sightings: ~720 per day (one every 2 minutes)
    const expectedSightings = daysTracked * 720;
    const reliability = Math.min(100, Math.round((sightings / expectedSightings) * 100));

    return reliability;
}

function getReliabilityClass(score) {
    if (score >= 70) return 'reliability-high';
    if (score >= 30) return 'reliability-medium';
    return 'reliability-low';
}

function renderReliabilityBadge(device) {
    const score = calculateReliabilityScore(device);
    const className = getReliabilityClass(score);
    return `<span class="reliability-badge ${className}">${score}% Reliable</span>`;
}

function renderAPAssociations(associatedAps) {
    if (!associatedAps || associatedAps.length === 0) {
        return '<div class="ap-associations"><div class="muted" style="font-size:11px;color:#666;">No AP association history</div></div>';
    }

    let html = '<div class="ap-associations">';
    html += '<div class="heatmap-label">Associated Access Points</div>';

    associatedAps.slice(0, 5).forEach(ap => {
        const ssid = ap.ssid || 'Unknown';
        const bssid = ap.bssid ? `${ap.bssid.slice(0, 8)}...` : '';
        html += `
            <div class="ap-entry">
                <span class="ap-ssid pii-ssid">${ssid}</span>
                <span class="ap-count pii-bssid" style="font-size:10px;color:#666;" title="${ap.bssid || ''}">${bssid}</span>
            </div>
        `;
    });

    if (associatedAps.length > 5) {
        html += `<div class="muted" style="font-size:11px;margin-top:4px;">+ ${associatedAps.length - 5} more APs</div>`;
    }

    html += '</div>';
    return html;
}

function formatEpoch(sec) {
    const n = Number(sec);
    if (!Number.isFinite(n) || n <= 0) return '--';
    // keep it consistent and explicit
    return new Date(n * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC');
}

let renderDeviceListTimeout = null;
function renderDeviceList(immediate = false) {
    // Debounce rendering to prevent lag from rapid calls
    if (!immediate) {
        if (renderDeviceListTimeout) clearTimeout(renderDeviceListTimeout);
        renderDeviceListTimeout = setTimeout(() => renderDeviceList(true), 50);
        return;
    }

    const container = $('#device-list');
    if (!container) return;

    let devices = [...deviceIntelligenceData.devices];

    // Filter by presence status
    const filter = deviceIntelligenceData.currentFilter;
    if (filter === 'present') {
        devices = devices.filter(d => d.present);
    } else if (filter === 'away') {
        devices = devices.filter(d => !d.present);
    } else if (filter === 'new') {
        devices = devices.filter(d => d.trust_score <= 30);
    }

    // Filter by AP
    const apFilter = deviceIntelligenceData.currentAPFilter;
    if (apFilter !== 'all') {
        devices = devices.filter(d => d.last_ap === apFilter);
    }
    
    const sort = deviceIntelligenceData.currentSort;
    if (sort === 'trust') {
        devices.sort((a, b) => (b.trust_score || 0) - (a.trust_score || 0));
    } else if (sort === 'presence') {
        devices.sort((a, b) => (b.present ? 1 : 0) - (a.present ? 1 : 0));
    } else if (sort === 'last_seen') {
        const norm = (v) => {
            const n = Number(v);
            if (!Number.isFinite(n) || n <= 0 || n >= 4000000000) return Number.MAX_SAFE_INTEGER;
            return n;
        };
        devices.sort((a, b) => norm(a.last_seen_ago) - norm(b.last_seen_ago));
    } else if (sort === 'sightings') {
        devices.sort((a, b) => (b.sightings || 0) - (a.sightings || 0));
    }
    
    if (devices.length === 0) {
        container.innerHTML = '<div class="muted" style="text-align:center;padding:20px;">No devices match the current filter.</div>';
        const showMoreContainer = $('#show-more-container');
        if (showMoreContainer) showMoreContainer.style.display = 'none';
        return;
    }

    // Paginate devices
    const displayCount = deviceIntelligenceData.displayedDevices;
    const hasMore = devices.length > displayCount;
    const displayedDevices = devices.slice(0, displayCount);

    // Update show more/less button visibility
    const showMoreContainer = $('#show-more-container');
    const showMoreBtn = $('#show-more-btn');
    const showLessBtn = $('#show-less-btn');
    
    if (showMoreContainer) {
        showMoreContainer.style.display = (hasMore || displayCount > deviceIntelligenceData.devicesPerPage) ? 'block' : 'none';
    }
    if (showMoreBtn) {
        showMoreBtn.style.display = hasMore ? 'inline-block' : 'none';
    }
    if (showLessBtn) {
        showLessBtn.style.display = displayCount > deviceIntelligenceData.devicesPerPage ? 'inline-block' : 'none';
    }

    container.innerHTML = displayedDevices.map(d => {
        const trustCategory = getTrustCategory(d.trust_score);
        const trustLabel = getTrustLabel(d.trust_score);
        const statusClass = d.present ? 'online' : 'offline';

        // handle unknown last_seen_ago values (e.g. persisted devices after reboot)
        const lastSeenAgoRaw = (d.last_seen_ago === undefined || d.last_seen_ago === null) ? null : Number(d.last_seen_ago);
        const lastSeenUnknown = (lastSeenAgoRaw === null || !Number.isFinite(lastSeenAgoRaw) || lastSeenAgoRaw <= 0 || lastSeenAgoRaw >= 4000000000);
        const sightings = Number(d.sightings) || 0;
        const hasEpoch = (Number(d.epoch_valid) === 1) && Number(d.last_seen_epoch) > 0;
        const unknownLabel = hasEpoch
            ? `Away (Last Seen: ${formatEpoch(d.last_seen_epoch)})`
            : (sightings >= 2 ? 'Away (Seen Previously)' : 'Away (New Device)');
        const statusText = d.present ? 'Here Now' : (lastSeenUnknown ? unknownLabel : `Away ${formatUptime(lastSeenAgoRaw)}`);
        
        return `
            <div class="device-row" data-mac="${d.mac}" onclick="toggleDeviceDetails(this)">
                <div class="device-header">
                    <div class="device-main">
                        <div class="device-mac">${pii(d.mac, 'mac')}</div>
                        <div class="device-vendor">${pii(d.vendor || 'Unknown', 'vendor')}</div>
                    </div>
                    <div class="device-meta">
                        ${d.home_device ? '<span class="trust-badge" style="background:#10b981;color:#fff;">Home</span>' : ''}
                        <span class="trust-badge ${trustCategory}">${trustLabel}</span>
                        <div class="status-badge">
                            <span class="status-dot ${statusClass}"></span>
                            <span>${statusText}</span>
                        </div>
                    </div>
                </div>
                <div class="device-details">
                    <div class="device-detail-grid">
                        <div class="device-detail-item">
                            <span class="device-detail-label">Trust Score</span>
                            <strong>${d.trust_score}/100</strong>
                        </div>
                        <div class="device-detail-item">
                            <span class="device-detail-label">RSSI</span>
                            <strong>${d.rssi} dBm</strong>
                        </div>
                        <div class="device-detail-item">
                            <span class="device-detail-label">Sightings</span>
                            <strong>${d.sightings}x</strong>
                        </div>
                        <div class="device-detail-item">
                            <span class="device-detail-label">Last AP</span>
                            <strong>${pii(d.last_ap || 'Unknown', 'ssid')}</strong>
                        </div>
                    </div>
                    <div class="device-details-lazy" data-mac="${d.mac}">
                        <!-- Lazy loaded on expand -->
                    </div>
                    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;">
                        <button class="btn btn-sm ${d.tracked ? 'btn-primary' : ''}" onclick="toggleDeviceTrack(event, '${d.mac}', ${!d.tracked})">
                            ${d.tracked ? 'Tracking' : 'Track'}
                        </button>
                        <button class="btn btn-sm ${d.home_device ? 'btn-primary' : ''}" onclick="toggleDeviceHome(event, '${d.mac}', ${!d.home_device}, '${(d.last_ap || '').replace(/'/g, "\\'")}')">Mark Home
                        </button>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function toggleDeviceDetails(element) {
    const wasExpanded = element.classList.contains('expanded');
    element.classList.toggle('expanded');

    // Lazy load heavy content only on first expand
    if (!wasExpanded) {
        const lazyContainer = element.querySelector('.device-details-lazy');
        if (lazyContainer && !lazyContainer.dataset.loaded) {
            const mac = lazyContainer.dataset.mac;
            const device = deviceIntelligenceData.devices.find(d => d.mac === mac);

            if (device) {
                let html = '';
                if (device.presence_hours) {
                    html += renderPresenceHeatmap(device.presence_hours);
                }
                html += '<div style="margin-top:8px;">' + renderReliabilityBadge(device) + '</div>';
                if (device.associated_aps) {
                    html += renderAPAssociations(device.associated_aps);
                }

                lazyContainer.innerHTML = html;
                lazyContainer.dataset.loaded = 'true';
            }
        }
    }
}

function filterDevices(filter) {
    deviceIntelligenceData.currentFilter = filter;
    deviceIntelligenceData.displayedDevices = deviceIntelligenceData.devicesPerPage;

    $$('.btn-filter').forEach(btn => btn.classList.remove('active'));
    const activeBtn = $(`.btn-filter[data-filter="${filter}"]`);
    if (activeBtn) activeBtn.classList.add('active');

    renderDeviceList();
}

function filterByAP(ap) {
    deviceIntelligenceData.currentAPFilter = ap;
    deviceIntelligenceData.displayedDevices = deviceIntelligenceData.devicesPerPage;
    renderDeviceList();
}

function sortDevices(sortField) {
    deviceIntelligenceData.currentSort = sortField;
    deviceIntelligenceData.displayedDevices = deviceIntelligenceData.devicesPerPage;
    renderDeviceList();
}

function showMoreDevices() {
    deviceIntelligenceData.displayedDevices += deviceIntelligenceData.devicesPerPage;
    renderDeviceList();
}

function showLessDevices() {
    deviceIntelligenceData.displayedDevices = Math.max(deviceIntelligenceData.devicesPerPage, deviceIntelligenceData.displayedDevices - deviceIntelligenceData.devicesPerPage);
    renderDeviceList();
}

async function toggleDeviceTrack(e, mac, tracked) {
    e.stopPropagation();
    const res = await fetchJSON('/devices/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mac, tracked })
    });
    if (res && res.status === 'ok') {
        showToast(tracked ? 'Device tracking enabled' : 'Device tracking disabled');
        loadDeviceIntelligence();
    } else {
        showToast('Failed to update device');
    }
}

async function toggleDeviceHome(e, mac, home_device, lastAp) {
    e.stopPropagation();
    
    if (home_device && lastAp) {
        const res = await fetchJSON('/home-ssids/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ssid: lastAp })
        });
        if (res && res.status === 'ok') {
            const res2 = await fetchJSON('/devices/update', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mac, home_device: true })
            });
            if (res2 && res2.status === 'ok') {
                showToast(`Added "${lastAp}" as home network and marked device as Home`);
                loadHomeSSIDs();
                loadDeviceIntelligence();
            } else {
                showToast(`Added "${lastAp}" as home network but failed to mark device`);
                loadHomeSSIDs();
                loadDeviceIntelligence();
            }
        } else {
            showToast('Failed to add home SSID (max 3)');
        }
    } else if (!home_device) {
        const res = await fetchJSON('/devices/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mac, home_device: false })
        });
        if (res && res.status === 'ok') {
            showToast('Device removed from Home');
            loadDeviceIntelligence();
        } else {
            showToast('Failed to update device');
        }
    } else {
        showToast('Device has no associated AP');
    }
}

let chartData = null;
let chartObservers = new Map();
let chartCache = new Map();
let legendMeasurementCache = new Map(); // Cache for legend text measurements
let canvasHandlers = new WeakMap();
let trackedIntervals = [];
const MAX_CACHE_SIZE = 3;

function debounce(fn, ms) {
    let timeout;
    return (...args) => {
        clearTimeout(timeout);
        timeout = setTimeout(() => fn(...args), ms);
    };
}

function clearChartObservers() {
    chartObservers.forEach((observer, canvas) => {
        observer.disconnect();
    });
    chartObservers.clear();
}

function addToChartCache(canvas, data) {
    if (chartCache.size >= MAX_CACHE_SIZE) {
        const firstKey = chartCache.keys().next().value;
        const firstObserver = chartObservers.get(firstKey);
        if (firstObserver) {
            firstObserver.disconnect();
            chartObservers.delete(firstKey);
        }
        chartCache.delete(firstKey);
    }
    chartCache.set(canvas, data);
}

function addTrackedInterval(fn, ms) {
    const id = setInterval(fn, ms);
    trackedIntervals.push(id);
    return id;
}

function cleanupAllResources() {
    trackedIntervals.forEach(id => clearInterval(id));
    trackedIntervals = [];
    clearChartObservers();
    chartCache.clear();
    legendMeasurementCache.clear();
}

function setupChartResize(canvas, redrawFn) {
    if (!canvas || chartObservers.has(canvas)) return;
    
    const debouncedRedraw = debounce(() => {
        const cached = chartCache.get(canvas);
        if (cached) {
            // Handle different callback signatures
            if (cached.config) {
                // Multi-line and interactive charts: (canvasId, samples, config)
                redrawFn(cached.canvasId, cached.samples, cached.config);
            } else {
                // SSID chart: (canvasId, samples)
                redrawFn(cached.canvasId, cached.samples);
            }
        }
    }, 100);
    
    const observer = new ResizeObserver(debouncedRedraw);
    observer.observe(canvas.parentElement);
    chartObservers.set(canvas, observer);
}

function getPointerPos(e, canvas) {
    const rect = canvas.getBoundingClientRect();
    if (e.touches && e.touches.length > 0) {
        return { x: e.touches[0].clientX - rect.left, y: e.touches[0].clientY - rect.top };
    }
    return { x: e.clientX - rect.left, y: e.clientY - rect.top };
}

// Channel colors for WiFi channels 1-13 (common channels highlighted)
const CHANNEL_COLORS = [
    '#ef4444', // Ch 1 - Red
    '#f97316', // Ch 2 - Orange
    '#f59e0b', // Ch 3 - Amber
    '#eab308', // Ch 4 - Yellow
    '#84cc16', // Ch 5 - Lime
    '#22c55e', // Ch 6 - Green (common)
    '#10b981', // Ch 7 - Emerald
    '#14b8a6', // Ch 8 - Teal
    '#06b6d4', // Ch 9 - Cyan
    '#0ea5e9', // Ch 10 - Sky
    '#3b82f6', // Ch 11 - Blue (common)
    '#6366f1', // Ch 12 - Indigo
    '#8b5cf6'  // Ch 13 - Violet
];

function drawMultiLineChart(canvasId, samples, config) {
    const canvas = $(canvasId);
    if (!canvas) return;

    // Cache for resize observer with eviction policy
    addToChartCache(canvas, { canvasId, samples, config });
    setupChartResize(canvas, drawMultiLineChart);

    const ctx = canvas.getContext('2d');
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;

    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    const isMobile = rect.width < 500;
    const padding = isMobile
        ? { top: 50, right: 15, bottom: 40, left: 38 }
        : { top: 60, right: 25, bottom: 60, left: 60 };
    const chartWidth = rect.width - padding.left - padding.right;
    const chartHeight = rect.height - padding.top - padding.bottom;

    // Clear with gradient background
    const bgGrad = ctx.createLinearGradient(0, 0, 0, rect.height);
    bgGrad.addColorStop(0, '#1f1f1f');
    bgGrad.addColorStop(1, '#141414');
    ctx.fillStyle = bgGrad;
    ctx.fillRect(0, 0, rect.width, rect.height);

    // Extract multi-series data
    const seriesData = config.extractSeries(samples);

    if (seriesData.length === 0 || seriesData.every(s => s.data.length === 0)) {
        ctx.fillStyle = '#888';
        ctx.font = '20px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No data available', rect.width / 2, rect.height / 2);
        return;
    }

    // Find max value across all series
    const maxValue = Math.max(...seriesData.flatMap(s => s.data.map(d => d.value)), 1);
    const minValue = 0;

    // Draw grid
    ctx.strokeStyle = '#2a2a2a';
    ctx.lineWidth = 1;
    const gridLines = isMobile ? 4 : 5;
    for (let i = 0; i <= gridLines; i++) {
        const y = padding.top + (chartHeight / gridLines) * i;
        ctx.beginPath();
        ctx.moveTo(padding.left, y);
        ctx.lineTo(padding.left + chartWidth, y);
        ctx.stroke();

        const val = maxValue - (maxValue / gridLines) * i;
        ctx.fillStyle = '#666';
        ctx.font = (isMobile ? '10px' : '12px') + ' system-ui, sans-serif';
        ctx.textAlign = 'right';
        ctx.fillText(Math.round(val), padding.left - 6, y + 4);
    }

    // Draw each series
    const timeRange = config.timeRange;
    const timeRangeMs = timeRange.endTime - timeRange.startTime;
    
    seriesData.forEach(series => {
        if (series.data.length === 0) return;

        // Sort data points by timestamp to ensure proper line connections
        const sortedData = [...series.data]
            .filter(d => Number.isFinite(d.timestamp))
            .sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));

        if (sortedData.length === 0) return;

        const points = sortedData.map((d, idx) => {
            let x;
            if (sortedData.length === 1) {
                // For single data point, position based on its timestamp within the time range
                const timeRatio = timeRangeMs > 0 ? ((d.timestamp || 0) - timeRange.startTime) / timeRangeMs : 0.5;
                x = padding.left + Math.max(0, Math.min(1, timeRatio)) * chartWidth;
            } else {
                // Position based on actual timestamp within the time range
                const timeRatio = timeRangeMs > 0 ? ((d.timestamp || 0) - timeRange.startTime) / timeRangeMs : 0;
                x = padding.left + Math.max(0, Math.min(1, timeRatio)) * chartWidth;
            }
            
            return {
                x: x,
                y: padding.top + chartHeight - ((d.value - minValue) / (maxValue - minValue)) * chartHeight,
                timestamp: d.timestamp || 0,
                value: d.value,
                originalIndex: idx
            };
        });

        // Detect gaps (downtime periods) - gap threshold: 2x expected sample interval
        const gaps = [];
        // Get current scan interval from settings, default to 2 minutes if not available
        const scanIntervalMinutes = window.currentScanInterval || 2;
        const expectedInterval = 2 * scanIntervalMinutes * 60 * 1000; // 2x scan interval in milliseconds
        for (let i = 0; i < points.length - 1; i++) {
            if (points[i].timestamp && points[i + 1].timestamp) {
                const timeDiff = points[i + 1].timestamp - points[i].timestamp;
                if (timeDiff > expectedInterval) {
                    gaps.push({ start: i, end: i + 1, duration: timeDiff });
                }
            }
        }

        // Draw line segments with dashed lines for gaps
        if (points.length > 1) {
            ctx.strokeStyle = series.color;
            ctx.lineWidth = isMobile ? 1.5 : 2;
            ctx.lineJoin = 'round';
            ctx.lineCap = 'round';
            
            for (let i = 0; i < points.length - 1; i++) {
                const isGap = gaps.some(gap => gap.start === i);
                
                if (isGap) {
                    // Draw dashed line for gap
                    ctx.setLineDash([5, 5]);
                    ctx.globalAlpha = 0.5;
                } else {
                    // Draw solid line for normal data
                    ctx.setLineDash([]);
                    ctx.globalAlpha = 1;
                }
                
                ctx.beginPath();
                ctx.moveTo(points[i].x, points[i].y);
                ctx.lineTo(points[i + 1].x, points[i + 1].y);
                ctx.stroke();
            }
            
            // Reset line dash and alpha
            ctx.setLineDash([]);
            ctx.globalAlpha = 1;
        }

        // Draw points (smaller for multi-line)
        const pointSize = isMobile ? 2 : 3;
        points.forEach(p => {
            ctx.fillStyle = series.color;
            ctx.beginPath();
            ctx.arc(p.x, p.y, pointSize, 0, Math.PI * 2);
            ctx.fill();
        });

        // Add gap indicators (subtle text above gaps)
        if (gaps.length > 0 && !isMobile) {
            ctx.fillStyle = '#666';
            ctx.font = '10px system-ui, sans-serif';
            ctx.textAlign = 'center';
            
            gaps.forEach(gap => {
                const midX = (points[gap.start].x + points[gap.end].x) / 2;
                const gapY = padding.top + chartHeight + 15;
                const durationHours = Math.round(gap.duration / (1000 * 60 * 60) * 10) / 10;
                ctx.fillText(`${durationHours}h gap`, midX, gapY);
            });
        }
    });

    // X-axis labels (show time range based on selected time frame)
    if (timeRange && timeRangeMs > 0) {
        ctx.fillStyle = '#666';
        ctx.font = (isMobile ? '10px' : '12px') + ' system-ui, sans-serif';
        ctx.textAlign = 'center';
        const labelCount = isMobile ? 3 : 5;

        for (let i = 0; i < labelCount; i++) {
            const timeRatio = i / (labelCount - 1);
            const timestamp = timeRange.startTime + (timeRatio * timeRangeMs);
            const x = padding.left + timeRatio * chartWidth;
            
            const date = new Date(timestamp);
            const label = date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
            ctx.fillText(label, x, rect.height - (isMobile ? 12 : 20));
        }
    } else {
        // Fallback to original behavior if no time range
        const firstSeries = seriesData.find(s => s.data.length > 0);
        if (firstSeries) {
            ctx.fillStyle = '#666';
            ctx.font = (isMobile ? '10px' : '12px') + ' system-ui, sans-serif';
            ctx.textAlign = 'center';
            const labelCount = Math.min(isMobile ? 3 : 5, firstSeries.data.length);

            if (labelCount === 1) {
                ctx.fillText(firstSeries.data[0].label, padding.left + chartWidth / 2, rect.height - (isMobile ? 12 : 20));
            } else {
                for (let i = 0; i < labelCount; i++) {
                    const idx = Math.floor((i / (labelCount - 1)) * (firstSeries.data.length - 1));
                    const x = padding.left + (idx / (firstSeries.data.length - 1)) * chartWidth;
                    ctx.fillText(firstSeries.data[idx].label, x, rect.height - (isMobile ? 12 : 20));
                }
            }
        }
    }

    // Legend - show active channels only, wrap on mobile
    const activeChannels = seriesData.filter(s => s.data.some(d => d.value > 0));
    if (activeChannels.length > 0) {
        const fontSize = isMobile ? 10 : 12;
        ctx.font = `${fontSize}px system-ui, sans-serif`;
        const boxSize = isMobile ? 8 : 10;
        const maxChannels = isMobile ? 6 : 10;

        let legendX = padding.left;
        const legendY = isMobile ? 35 : 45;
        const itemSpacing = isMobile ? 6 : 10;

        activeChannels.slice(0, maxChannels).forEach((series) => {
            // Optimize: Cache text measurements to avoid repeated canvas operations
            const cacheKey = `${fontSize}:${series.label}`;
            let labelWidth = legendMeasurementCache.get(cacheKey);
            if (labelWidth === undefined) {
                labelWidth = ctx.measureText(series.label).width;
                legendMeasurementCache.set(cacheKey, labelWidth);
            }

            const itemWidth = boxSize + 4 + labelWidth + itemSpacing;

            // Wrap to next line if needed
            if (legendX + itemWidth > rect.width - padding.right && legendX > padding.left) {
                legendX = padding.left;
            }

            ctx.fillStyle = series.color;
            ctx.fillRect(legendX, legendY - boxSize, boxSize, boxSize);
            ctx.fillStyle = '#aaa';
            ctx.textAlign = 'left';
            ctx.fillText(series.label, legendX + boxSize + 4, legendY);
            legendX += itemWidth;
        });

        if (activeChannels.length > maxChannels) {
            ctx.fillStyle = '#666';
            ctx.fillText(`+${activeChannels.length - maxChannels}`, legendX, legendY);
        }
    }
}

function drawInteractiveChart(canvasId, samples, config, highlightIdx = -1) {
    const canvas = $(canvasId);
    if (!canvas) return;

    // Cache for resize observer with eviction policy
    addToChartCache(canvas, { canvasId, samples, config });
    setupChartResize(canvas, drawInteractiveChart);

    const ctx = canvas.getContext('2d');
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;

    // Set canvas size with device pixel ratio
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    // Responsive padding
    const isMobile = rect.width < 500;
    const padding = isMobile
        ? { top: 25, right: 8, bottom: 40, left: 38 }
        : { top: 40, right: 20, bottom: 60, left: 60 };
    const chartWidth = rect.width - padding.left - padding.right;
    const chartHeight = rect.height - padding.top - padding.bottom;

    // Clear with gradient background
    const bgGrad = ctx.createLinearGradient(0, 0, 0, rect.height);
    bgGrad.addColorStop(0, '#1f1f1f');
    bgGrad.addColorStop(1, '#141414');
    ctx.fillStyle = bgGrad;
    ctx.fillRect(0, 0, rect.width, rect.height);
    
    // extract data
    const dataPoints = samples.map(s => config.extractData(s));
    
    // handle empty data
    if (dataPoints.length === 0) {
        ctx.fillStyle = '#888';
        ctx.font = '20px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No data available', rect.width / 2, rect.height / 2);
        return;
    }
    
    const maxValue = Math.max(...dataPoints.map(d => d.value), 1);
    const minValue = 0;
    
    // draw grid
    ctx.strokeStyle = '#2a2a2a';
    ctx.lineWidth = 1;
    const gridLines = isMobile ? 4 : 5;
    for (let i = 0; i <= gridLines; i++) {
        const y = padding.top + (chartHeight / gridLines) * i;
        ctx.beginPath();
        ctx.moveTo(padding.left, y);
        ctx.lineTo(padding.left + chartWidth, y);
        ctx.stroke();
        
        const val = maxValue - (maxValue / gridLines) * i;
        ctx.fillStyle = '#666';
        ctx.font = (isMobile ? '10px' : '12px') + ' system-ui, sans-serif';
        ctx.textAlign = 'right';
        ctx.fillText(Math.round(val), padding.left - 6, y + 4);
    }
    
    // Build path points with timestamps for gap detection
    const points = dataPoints.map((d, i) => ({
        x: dataPoints.length === 1 ? padding.left + chartWidth / 2 : padding.left + (i / (dataPoints.length - 1)) * chartWidth,
        y: padding.top + chartHeight - ((d.value - minValue) / (maxValue - minValue)) * chartHeight,
        value: d.value,
        label: d.label,
        timestamp: d.timestamp || 0
    }));

    // Detect gaps (downtime periods) - gap threshold: 2x expected sample interval
    const gaps = [];
    // Get current scan interval from settings, default to 2 minutes if not available
    const scanIntervalMinutes = window.currentScanInterval || 2;
    const expectedInterval = 2 * scanIntervalMinutes * 60 * 1000; // 2x scan interval in milliseconds
    for (let i = 0; i < points.length - 1; i++) {
        if (points[i].timestamp && points[i + 1].timestamp) {
            const timeDiff = points[i + 1].timestamp - points[i].timestamp;
            if (timeDiff > expectedInterval) {
                gaps.push({ start: i, end: i + 1, duration: timeDiff });
            }
        }
    }

    // Draw area fill under line (skip gaps)
    if (points.length > 1) {
        const areaGrad = ctx.createLinearGradient(0, padding.top, 0, padding.top + chartHeight);
        areaGrad.addColorStop(0, config.color + '40');
        areaGrad.addColorStop(1, config.color + '05');
        
        ctx.fillStyle = areaGrad;
        
        // Draw area segments, skipping gaps
        for (let i = 0; i < points.length - 1; i++) {
            const isGap = gaps.some(gap => gap.start === i);
            if (isGap) continue;
            
            ctx.beginPath();
            ctx.moveTo(points[i].x, padding.top + chartHeight);
            ctx.lineTo(points[i].x, points[i].y);
            ctx.lineTo(points[i + 1].x, points[i + 1].y);
            ctx.lineTo(points[i + 1].x, padding.top + chartHeight);
            ctx.closePath();
            ctx.fill();
        }
    }

    // Draw line with dashed segments for gaps
    if (points.length > 1) {
        ctx.strokeStyle = config.color;
        ctx.lineWidth = 2.5;
        ctx.lineJoin = 'round';
        ctx.lineCap = 'round';
        
        for (let i = 0; i < points.length - 1; i++) {
            const isGap = gaps.some(gap => gap.start === i);
            
            if (isGap) {
                // Draw dashed line for gap
                ctx.setLineDash([5, 5]);
                ctx.globalAlpha = 0.5;
            } else {
                // Draw solid line for normal data
                ctx.setLineDash([]);
                ctx.globalAlpha = 1;
            }
            
            ctx.beginPath();
            ctx.moveTo(points[i].x, points[i].y);
            ctx.lineTo(points[i + 1].x, points[i + 1].y);
            ctx.stroke();
        }
        
        // Reset line dash and alpha
        ctx.setLineDash([]);
        ctx.globalAlpha = 1;
    }

    // Add gap indicators (subtle text above gaps)
    if (gaps.length > 0 && !isMobile) {
        ctx.fillStyle = '#666';
        ctx.font = '10px system-ui, sans-serif';
        ctx.textAlign = 'center';
        
        gaps.forEach(gap => {
            const midX = (points[gap.start].x + points[gap.end].x) / 2;
            const gapY = padding.top + chartHeight + 15;
            const durationHours = Math.round(gap.duration / (1000 * 60 * 60) * 10) / 10;
            ctx.fillText(`${durationHours}h gap`, midX, gapY);
        });
    }

    // Draw points
    const pointRadius = dataPoints.length <= 2 ? 6 : 3;
    points.forEach((p, i) => {
        const isHighlighted = i === highlightIdx;
        const r = isHighlighted ? pointRadius + 4 : pointRadius;
        
        ctx.fillStyle = isHighlighted ? '#fff' : config.color;
        ctx.beginPath();
        ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
        ctx.fill();
        
        if (isHighlighted) {
            ctx.strokeStyle = config.color;
            ctx.lineWidth = 2;
            ctx.stroke();
        }
    });
    
    // x-axis labels (time)
    ctx.fillStyle = '#666';
    ctx.font = (isMobile ? '10px' : '12px') + ' system-ui, sans-serif';
    ctx.textAlign = 'center';
    const labelCount = Math.min(isMobile ? 3 : 5, dataPoints.length);

    if (labelCount === 1) {
        ctx.fillText(dataPoints[0].label, padding.left + chartWidth / 2, rect.height - (isMobile ? 12 : 20));
    } else {
        for (let i = 0; i < labelCount; i++) {
            const idx = Math.floor((i / (labelCount - 1)) * (dataPoints.length - 1));
            const x = padding.left + (idx / (dataPoints.length - 1)) * chartWidth;
            ctx.fillText(dataPoints[idx].label, x, rect.height - (isMobile ? 12 : 20));
        }
    }
    
    // Draw tooltip for highlighted point
    if (highlightIdx >= 0 && highlightIdx < points.length) {
        const p = points[highlightIdx];
        const tooltipText = `${p.label}: ${p.value} ${config.unit}`;
        ctx.font = (isMobile ? '11px' : '13px') + ' system-ui, sans-serif';
        const textWidth = ctx.measureText(tooltipText).width;
        const tooltipPadding = isMobile ? 8 : 12;
        const tooltipWidth = textWidth + tooltipPadding * 2;
        const tooltipHeight = isMobile ? 26 : 30;

        let tooltipX = p.x - tooltipWidth / 2;
        let tooltipY = p.y - tooltipHeight - 12;

        if (tooltipX < padding.left) tooltipX = padding.left;
        if (tooltipX + tooltipWidth > rect.width - padding.right) {
            tooltipX = rect.width - padding.right - tooltipWidth;
        }
        if (tooltipY < 5) tooltipY = p.y + 15;

        ctx.fillStyle = 'rgba(0,0,0,0.9)';
        ctx.beginPath();
        ctx.roundRect(tooltipX, tooltipY, tooltipWidth, tooltipHeight, 6);
        ctx.fill();
        
        ctx.strokeStyle = config.color + '80';
        ctx.lineWidth = 1;
        ctx.stroke();

        ctx.fillStyle = '#fff';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(tooltipText, tooltipX + tooltipWidth / 2, tooltipY + tooltipHeight / 2);
        ctx.textBaseline = 'alphabetic';
    }

    // Unified pointer handler for mouse and touch
    const handlePointer = (e) => {
        e.preventDefault();
        const pos = getPointerPos(e, canvas);
        const threshold = isMobile ? 40 : 25;
        
        let nearestIdx = -1;
        let nearestDist = Infinity;
        
        points.forEach((p, i) => {
            const dist = Math.sqrt((p.x - pos.x) ** 2 + (p.y - pos.y) ** 2);
            if (dist < nearestDist && dist < threshold) {
                nearestDist = dist;
                nearestIdx = i;
            }
        });
        
        drawInteractiveChart(canvasId, samples, config, nearestIdx);
    };

    const handlePointerLeave = () => {
        drawInteractiveChart(canvasId, samples, config, -1);
    };

    // Remove old listeners before adding new ones
    const oldHandlers = canvasHandlers.get(canvas);
    if (oldHandlers) {
        canvas.removeEventListener('mousemove', oldHandlers.move);
        canvas.removeEventListener('mouseleave', oldHandlers.leave);
        canvas.removeEventListener('touchmove', oldHandlers.touchmove);
        canvas.removeEventListener('touchstart', oldHandlers.touchstart);
        canvas.removeEventListener('touchend', oldHandlers.touchend);
    }

    // Add new listeners using addEventListener
    const handlers = {
        move: handlePointer,
        leave: handlePointerLeave,
        touchmove: handlePointer,
        touchstart: handlePointer,
        touchend: handlePointerLeave
    };
    canvas.addEventListener('mousemove', handlers.move);
    canvas.addEventListener('mouseleave', handlers.leave);
    canvas.addEventListener('touchmove', handlers.touchmove);
    canvas.addEventListener('touchstart', handlers.touchstart);
    canvas.addEventListener('touchend', handlers.touchend);
    canvasHandlers.set(canvas, handlers);
}

const HISTORY_READY_THRESHOLD = 10;
const IDEAL_TREND_SAMPLE_COUNT = 30;
const HISTORY_OVERLAY_TEXT = 'Collecting data... check back soon.';

function formatHistoryLabel(sample) {
    if (!sample) return '--';
    if (!sample.time_valid || !sample.epoch_ts) {
        const hours = Math.floor(sample.uptime_sec / 3600);
        const mins = Math.floor((sample.uptime_sec % 3600) / 60);
        return hours > 0 ? `${hours}h${mins}m` : `${mins}m`;
    }
    // Device epoch_ts is UTC, convert to local time for display
    const date = new Date(sample.epoch_ts * 1000);
    return date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

function updateGraphOverlayState(graphKey, active) {
    const overlay = document.querySelector(`.graph-overlay[data-graph="${graphKey}"]`);
    if (!overlay) return;
    overlay.textContent = active ? HISTORY_OVERLAY_TEXT : '';
    overlay.classList.toggle('active', active);
}

function renderCharts(samples, timeRange = null) {
    const needsMoreData = !samples || samples.length < HISTORY_READY_THRESHOLD;

    // Show/hide overlays based on data availability
    updateGraphOverlayState('activity', needsMoreData);
    updateGraphOverlayState('channel', needsMoreData);
    updateGraphOverlayState('ssid-clients', needsMoreData);

    if (!samples || samples.length === 0) return;

    // If no time range provided, calculate from samples
    if (!timeRange) {
        const endTime = Date.now();
        const startTime = samples.length > 0 ? 
            Math.min(...samples.map(s => s.epoch_ts * 1000)) : 
            endTime - (24 * 60 * 60 * 1000);
        timeRange = { startTime, endTime, days: (endTime - startTime) / (24 * 60 * 60 * 1000) };
    }

    // activity chart - show APs and clients as separate lines with smoothing
    // Ensure samples are sorted chronologically to avoid line jumps
    const sortedSamples = [...samples].sort((a, b) => (a.epoch_ts || 0) - (b.epoch_ts || 0));

    drawMultiLineChart('#activity-chart', sortedSamples, {
        timeRange: timeRange,
        extractSeries: (samples) => {
            const apData = [];
            const clientData = [];

            // Apply moving average for smoothing (window size depends on data density)
            const windowSize = samples.length > 100 ? 5 : (samples.length > 20 ? 3 : 1);

            // Optimize: Use incremental sliding window instead of recalculating from scratch
            // This reduces complexity from O(N*W) to O(N)
            let apSum = 0, clientSum = 0;

            samples.forEach((s, idx) => {
                const label = formatHistoryLabel(s);

                // Add current value to sum
                apSum += s.ap_count || 0;
                clientSum += s.client_count || 0;

                // Remove oldest value if window is full
                if (idx >= windowSize) {
                    apSum -= samples[idx - windowSize].ap_count || 0;
                    clientSum -= samples[idx - windowSize].client_count || 0;
                }

                // Calculate current window size (handles initial fill)
                const currentWindowSize = Math.min(idx + 1, windowSize);

                const apAvg = Math.round(apSum / currentWindowSize);
                const clientAvg = Math.round(clientSum / currentWindowSize);

                apData.push({ label, value: apAvg, timestamp: s.epoch_ts * 1000 });
                clientData.push({ label, value: clientAvg, timestamp: s.epoch_ts * 1000 });
            });

            return [
                { label: 'APs', color: '#4ade80', data: apData },
                { label: 'Clients', color: '#60a5fa', data: clientData }
            ];
        }
    });

    // Channel distribution over time - multi-line chart
    const channelStatus = samples.length < 10
        ? `Collecting data... (${samples.length} samples)`
        : `Showing ${samples.length} samples`;

    drawMultiLineChart('#channel-chart-time', sortedSamples, {
        timeRange: timeRange,
        extractSeries: (samples) => {
            // Optimize: Find active channels first, then build only needed series
            const activeChannels = new Set();

            // Single pass to identify active channels
            samples.forEach(s => {
                if (s.channel_counts) {
                    s.channel_counts.forEach((count, ch) => {
                        if (count > 0) activeChannels.add(ch);
                    });
                }
            });

            // Build series only for active channels
            const series = [];
            const windowSize = samples.length > 150 ? 7 : (samples.length > 60 ? 5 : (samples.length > 20 ? 3 : 1));
            activeChannels.forEach(ch => {
                const channelNum = ch + 1;
                const data = [];
                let sum = 0;

                samples.forEach((s, idx) => {
                    const value = s.channel_counts && s.channel_counts[ch] ? s.channel_counts[ch] : 0;
                    sum += value;
                    if (idx >= windowSize) {
                        const prev = samples[idx - windowSize].channel_counts && samples[idx - windowSize].channel_counts[ch]
                            ? samples[idx - windowSize].channel_counts[ch]
                            : 0;
                        sum -= prev;
                    }

                    const currentWindowSize = Math.min(idx + 1, windowSize);
                    const avg = windowSize === 1 ? value : Math.round(sum / currentWindowSize);

                    data.push({
                        label: formatHistoryLabel(s),
                        value: avg,
                        timestamp: s.epoch_ts * 1000
                    });
                });

                series.push({
                    label: `Ch ${channelNum}`,
                    color: CHANNEL_COLORS[ch],
                    data: data
                });
            });

            return series;
        }
    });

    // Clients per SSID - show top networks by client count from history
    drawSSIDClientsChart('#ssid-clients-chart', samples);
}

async function drawSSIDClientsChart(canvasId, samples) {
    if (!samples || samples.length === 0) return;

    const data = await getScanReport();
    const hashToSsid = new Map();
    if (data && data.networks) {
        data.networks.forEach(net => {
            const hash = hashSsid(net.ssid || '');
            hashToSsid.set(hash, net.ssid || '(Hidden)');
        });
    }

    const ssidAggregates = new Map();
    samples.forEach(sample => {
        if (sample.ssid_clients) {
            sample.ssid_clients.forEach(entry => {
                const current = ssidAggregates.get(entry.hash) || { hash: entry.hash, total: 0, count: 0, max: 0 };
                current.total += entry.count;
                current.count++;
                current.max = Math.max(current.max, entry.count);
                ssidAggregates.set(entry.hash, current);
            });
        }
    });

    const networks = Array.from(ssidAggregates.values())
        .map(agg => ({
            ssid: hashToSsid.get(agg.hash) || `Unknown (${agg.hash})`,
            stations: agg.max
        }))
        .sort((a, b) => b.stations - a.stations)
        .slice(0, 10);

    if (networks.length === 0) return;

    const canvas = $(canvasId);
    if (!canvas) return;

    addToChartCache(canvas, { canvasId, samples });
    setupChartResize(canvas, (id, cachedData) => {
        if (cachedData && cachedData.samples) {
            drawSSIDClientsChart(id, cachedData.samples);
        }
    });

    drawSSIDClientsChartImpl(canvasId, networks);
}

function hashSsid(ssid) {
    let hash = 5381;
    for (let i = 0; i < ssid.length; i++) {
        hash = ((hash << 5) + hash) + ssid.charCodeAt(i);
    }
    return hash >>> 0;
}

function drawSSIDClientsChartImpl(canvasId, networks) {
    const canvas = $(canvasId);
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;

    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    const isMobile = rect.width < 500;
    const padding = isMobile
        ? { top: 40, right: 15, bottom: 80, left: 38 }
        : { top: 50, right: 25, bottom: 80, left: 60 };
    const chartWidth = rect.width - padding.left - padding.right;
    const chartHeight = rect.height - padding.top - padding.bottom;

    // Background
    const bgGrad = ctx.createLinearGradient(0, 0, 0, rect.height);
    bgGrad.addColorStop(0, '#1f1f1f');
    bgGrad.addColorStop(1, '#141414');
    ctx.fillStyle = bgGrad;
    ctx.fillRect(0, 0, rect.width, rect.height);

    const maxClients = Math.max(...networks.map(n => n.stations), 1);

    // Draw bars
    const barWidth = chartWidth / networks.length - 10;
    networks.forEach((net, i) => {
        const x = padding.left + (i * (chartWidth / networks.length)) + 5;
        const barHeight = (net.stations / maxClients) * chartHeight;
        const y = padding.top + chartHeight - barHeight;

        // Draw bar
        const colors = ['#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#3b82f6', '#6366f1', '#ef4444', '#14b8a6', '#f97316', '#84cc16'];
        ctx.fillStyle = colors[i % colors.length];
        ctx.fillRect(x, y, barWidth, barHeight);

        // Draw client count on top of bar
        ctx.fillStyle = '#fff';
        const clientCountFontSize = Math.max(10, Math.min(12, barWidth / 3));
        ctx.font = `${clientCountFontSize}px system-ui, sans-serif`;
        ctx.textAlign = 'center';
        ctx.fillText(net.stations, x + barWidth / 2, y - 5);

        // Draw SSID label (rotated)
        ctx.save();
        ctx.translate(x + barWidth / 2, padding.top + chartHeight + 10);
        ctx.rotate(-Math.PI / 4);
        ctx.fillStyle = '#aaa';
        const ssidFontSize = Math.max(9, Math.min(11, barWidth / 4));
        ctx.font = `${ssidFontSize}px system-ui, sans-serif`;
        ctx.textAlign = 'right';
        const ssid = net.ssid || `Hidden`;
        const maxSsidLength = Math.max(8, Math.floor(barWidth / 6));
        const displaySsid = privacyMode ? '••••••••' : (ssid.length > maxSsidLength ? ssid.slice(0, maxSsidLength) + '...' : ssid);
        ctx.fillText(displaySsid, 0, 0);
        ctx.restore();
    });

    // Draw Y-axis labels
    ctx.fillStyle = '#666';
    const yAxisFontSize = Math.max(10, Math.min(12, chartWidth / 40));
    ctx.font = `${yAxisFontSize}px system-ui, sans-serif`;
    ctx.textAlign = 'right';
    for (let i = 0; i <= 5; i++) {
        const val = Math.round((maxClients / 5) * i);
        const y = padding.top + chartHeight - ((chartHeight / 5) * i);
        ctx.fillText(val, padding.left - 10, y + 4);
    }

    // Title
    ctx.fillStyle = '#fff';
    const titleFontSize = Math.max(12, Math.min(16, chartWidth / 25));
    ctx.font = `bold ${titleFontSize}px system-ui, sans-serif`;
    ctx.textAlign = 'center';
    ctx.fillText('Top Networks by Client Count', rect.width / 2, isMobile ? 15 : 20);
}

async function loadHistoryCharts(days) {
    // For 'from-start', fetch all available data (use large days value)
    const fetchDays = days === 'from-start' ? 365 : days;
    const data = await fetchJSON(`/history/samples?days=${fetchDays}`);
    if (!data || !data.samples || data.samples.length === 0) {
        showToast('No history data available yet');
        return;
    }

    const desc = document.querySelector('.history-description');
    if (desc) {
        if (days === 'from-start') {
            const oldestSample = data.samples[0];
            const oldestTime = oldestSample && oldestSample.epoch_ts ? 
                new Date(oldestSample.epoch_ts * 1000).toLocaleDateString() : 'unknown';
            desc.textContent = `Network activity charts (from ${oldestTime})`;
        } else {
            desc.textContent = days === 1
                ? 'Network activity charts (last 24 hours)'
                : days < 1
                ? `Network activity charts (last ${Math.round(days * 24)} hours)`
                : `Network activity charts (last ${days} days)`;
        }
    }

    // Use samples directly without unnecessary padding
    chartData = data.samples;
    
    let timeRange;
    if (days === 'from-start') {
        // For 'from-start', calculate time range from oldest sample to now
        const endTime = Date.now();
        const oldestTimestamp = data.samples.length > 0 ? 
            Math.min(...data.samples.map(s => s.epoch_ts * 1000)) : endTime - (24 * 60 * 60 * 1000);
        const startTime = oldestTimestamp;
        const actualDays = (endTime - startTime) / (24 * 60 * 60 * 1000);
        timeRange = { startTime, endTime, days: actualDays };
        showToast(`Loaded ${data.samples.length} samples (${Math.round(actualDays * 24)} hour range)`);
    } else {
        // Calculate the time range for proper chart positioning
        const endTime = Date.now();
        const startTime = endTime - (days * 24 * 60 * 60 * 1000);
        timeRange = { startTime, endTime, days };
        showToast(`Loaded ${data.samples.length} samples (${Math.round(days * 24)} hour range)`);
    }
    
    renderCharts(data.samples, timeRange);
}


async function loadHomeSSIDs() {
    const data = await fetchJSON('/home-ssids');
    if (!data) return;
    
    const connectedEl = $('#home-ssid-connected');
    if (connectedEl) {
        connectedEl.innerHTML = pii(data.connected || 'Not connected', 'ssid');
    }
    
    const extraEl = $('#extra-home-ssids');
    if (extraEl && data.extra) {
        if (data.extra.length === 0) {
            extraEl.innerHTML = '<span class="muted">No additional SSIDs configured</span>';
        } else {
            extraEl.innerHTML = data.extra.map(ssid => `
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
                    ${pii(ssid, 'ssid')}
                    <button class="btn btn-sm" onclick="removeHomeSSID('${ssid}')" style="padding:2px 8px;font-size:11px;max-width:80px;">Remove</button>
                </div>
            `).join('');
        }
    }
}

async function addHomeSSID() {
    const input = $('#new-home-ssid');
    const ssid = input?.value?.trim();
    if (!ssid) {
        showToast('Enter an SSID');
        return;
    }
    
    const res = await fetchJSON('/home-ssids/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ssid })
    });
    
    if (res && res.status === 'ok') {
        input.value = '';
        showToast('Home SSID added');
        loadHomeSSIDs();
    } else {
        showToast('Failed to add SSID (max 3)');
    }
}

async function removeHomeSSID(ssid) {
    const res = await fetchJSON('/home-ssids/remove', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ssid })
    });
    
    if (res && res.status === 'ok') {
        showToast('Home SSID removed');
        loadHomeSSIDs();
    } else {
        showToast('Failed to remove SSID');
    }
}

async function loadWebhookConfig() {
    const data = await fetchJSON('/webhook/config');
    if (!data) return;
    
    const enabledCheckbox = $('#webhook-enabled');
    const urlInput = $('#webhook-url');
    const trackedOnlyCheckbox = $('#webhook-tracked-only');
    const homeDepartureCheckbox = $('#webhook-home-departure');
    const homeArrivalCheckbox = $('#webhook-home-arrival');
    const newDeviceCheckbox = $('#webhook-new-device');
    const deauthCheckbox = $('#webhook-deauth');
    const handshakeCheckbox = $('#webhook-handshake');
    const allEventsCheckbox = $('#webhook-all-events');
    const status = $('#webhook-status');
    
    if (enabledCheckbox) enabledCheckbox.checked = data.enabled;
    if (urlInput) urlInput.value = data.url || '';
    if (trackedOnlyCheckbox) trackedOnlyCheckbox.checked = data.tracked_only;
    if (homeDepartureCheckbox) homeDepartureCheckbox.checked = data.home_departure_alert;
    if (homeArrivalCheckbox) homeArrivalCheckbox.checked = data.home_arrival_alert;
    if (newDeviceCheckbox) newDeviceCheckbox.checked = data.new_device_alert;
    if (deauthCheckbox) deauthCheckbox.checked = data.deauth_alert;
    if (handshakeCheckbox) handshakeCheckbox.checked = data.handshake_alert;
    if (allEventsCheckbox) allEventsCheckbox.checked = data.all_events;
    
    if (status) {
        const pendingRaw = data.total_events - data.send_cursor;
        const pending = data.enabled ? Math.max(0, pendingRaw) : 0;
        status.textContent = `Status: ${data.enabled ? 'Enabled' : 'Disabled'} • Sent: ${data.send_cursor} • Pending: ${pending}`;
    }
}

async function saveWebhookConfig(e) {
    e.preventDefault();
    
    const enabled = $('#webhook-enabled')?.checked ?? false;
    const url = $('#webhook-url')?.value || '';
    const tracked_only = $('#webhook-tracked-only')?.checked ?? false;
    const home_departure_alert = $('#webhook-home-departure')?.checked ?? false;
    const home_arrival_alert = $('#webhook-home-arrival')?.checked ?? false;
    const new_device_alert = $('#webhook-new-device')?.checked ?? false;
    const deauth_alert = $('#webhook-deauth')?.checked ?? false;
    const handshake_alert = $('#webhook-handshake')?.checked ?? false;
    const all_events = $('#webhook-all-events')?.checked ?? false;
    
    const res = await fetchJSON('/webhook/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled, url, tracked_only, home_departure_alert, home_arrival_alert, new_device_alert, deauth_alert, handshake_alert, all_events })
    });
    
    if (res && res.status === 'ok') {
        showToast('Webhook settings saved');
        loadWebhookConfig();
    } else {
        showToast('Failed to save settings');
    }
}

async function testWebhook(e) {
    e.preventDefault();
    
    const res = await fetchJSON('/webhook/test', { method: 'POST' });
    
    if (res && res.status === 'ok') {
        showToast('Test webhook sent successfully');
    } else {
        showToast(res?.message || 'Failed to send test webhook');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    initLoginUI();
    checkAuthAndStart();
});

window.addEventListener('beforeunload', cleanupAllResources);

// Network Bottleneck Detector Functions
class NetworkBottleneckDetector {
    calculateChannelBottleneck(channelCounts) {
        const maxCapacity = 25;
        const totalAPs = channelCounts.reduce((a, b) => a + b, 0);
        const maxChannelCount = Math.max(...channelCounts);
        
        // Calculate bottleneck score based on worst channel utilization
        const bottleneckScore = Math.min(100, (maxChannelCount / maxCapacity) * 100);
        
        // Find which channels are congested
        const congestedChannels = channelCounts
            .map((count, idx) => ({ channel: idx + 1, count, congested: count > 15 }))
            .filter(ch => ch.congested);
        
        return {
            score: Math.round(bottleneckScore),
            severity: this.getSeverity(bottleneckScore),
            detail: maxChannelCount > 0 ? 
                `${maxChannelCount} APs on most congested channel (Ch ${channelCounts.indexOf(maxChannelCount) + 1})` : 
                'No channels detected',
            overloadedAPs: channelCounts.filter(c => c > 20).length,
            congestedChannels: congestedChannels.length
        };
    }
    
    calculateCapacityBottleneck(clientCounts, apCount) {
        const totalClients = clientCounts.reduce((a, b) => a + b, 0);
        const avgClientsPerAP = apCount > 0 ? totalClients / apCount : 0;
        const optimalRatio = 30;
        const bottleneckScore = apCount > 0 ? Math.min(100, (avgClientsPerAP / optimalRatio) * 100) : 0;
        
        return {
            score: Math.round(bottleneckScore),
            devicesPerAP: Math.round(avgClientsPerAP),
            severity: this.getSeverity(bottleneckScore),
            detail: apCount > 0 ? `${Math.round(avgClientsPerAP)} devices per AP average` : 'No APs detected'
        };
    }
    
    calculateSignalBottleneck(rssiValues) {
        if (!rssiValues || rssiValues.length === 0) {
            return { score: 0, weakSignalPercentage: 0, severity: 'low', detail: 'No signal data' };
        }
        
        const weakSignals = rssiValues.filter(rssi => rssi < -70).length;
        const totalSignals = rssiValues.length;
        const weakSignalPercentage = (weakSignals / totalSignals) * 100;
        
        return {
            score: Math.round(weakSignalPercentage),
            weakSignalPercentage: Math.round(weakSignalPercentage),
            severity: this.getSeverity(weakSignalPercentage),
            detail: `${weakSignals} devices with weak signal (< -70dBm)`
        };
    }
    
    calculateTimingBottleneck(activityTimeline) {
        if (!activityTimeline || activityTimeline.length < 2) {
            return { score: 0, congestionPeriods: 0, severity: 'low', detail: 'Insufficient data' };
        }
        
        const totalDevices = activityTimeline.map(s => (s.ap_count || 0) + (s.client_count || 0));
        
        // Calculate average and standard deviation to detect significant spikes
        const avgActivity = totalDevices.reduce((a, b) => a + b, 0) / totalDevices.length;
        const variance = totalDevices.reduce((sum, val) => sum + Math.pow(val - avgActivity, 2), 0) / totalDevices.length;
        const stdDev = Math.sqrt(variance);
        
        // Use statistical threshold (2 standard deviations above mean) for congestion
        const peakThreshold = avgActivity + (2 * stdDev);
        
        // If there's very little variation, no timing bottleneck
        if (stdDev < 1) {
            return { score: 0, congestionPeriods: 0, severity: 'low', detail: 'Stable network activity' };
        }
        
        const congestionPeriods = totalDevices.filter(count => count > peakThreshold).length;
        const bottleneckScore = (congestionPeriods / totalDevices.length) * 100;
        
        return {
            score: Math.round(bottleneckScore),
            congestionPeriods: congestionPeriods,
            severity: this.getSeverity(bottleneckScore),
            detail: congestionPeriods > 0 ? 
                `${congestionPeriods} periods of high activity detected` : 
                'Consistent network activity'
        };
    }
    
    getSeverity(score) {
        if (score < 25) return 'low';
        if (score < 50) return 'medium';
        if (score < 75) return 'high';
        return 'critical';
    }
    
    getOverallBottleneckScore(bottlenecks) {
        const weights = { channel: 0.3, capacity: 0.25, signal: 0.25, timing: 0.2 };
        
        const weightedScore = 
            bottlenecks.channel.score * weights.channel +
            bottlenecks.capacity.score * weights.capacity +
            bottlenecks.signal.score * weights.signal +
            bottlenecks.timing.score * weights.timing;
            
        const overallScore = Math.round(weightedScore);
        const primaryBottleneck = Object.entries(bottlenecks).reduce((a, [key, value]) => 
            value.score > a.value.score ? { key, value } : a, { key: 'none', value: { score: 0 } });
        
        return {
            overallScore,
            severity: this.getSeverity(overallScore),
            bottlenecks,
            primaryBottleneck: primaryBottleneck.key,
            recommendations: this.generateRecommendations(bottlenecks, primaryBottleneck)
        };
    }
    
    generateRecommendations(bottlenecks, primaryBottleneck) {
        const recommendations = [];
        
        // Channel recommendations with specific channel info
        if (bottlenecks.channel.score > 70) {
            const worstChannel = bottlenecks.channel.congestedChannels > 0 ? 
                `prioritize moving APs from congested channels` : 
                `redistribute APs across channels`;
            
            recommendations.push({
                priority: 'high',
                title: 'Optimize Channel Usage',
                description: `${bottlenecks.channel.overloadedAPs} APs on overloaded channels - ${worstChannel}`,
                impact: 'Could improve performance by 40-60%'
            });
        }
        
        // Capacity recommendations with SSID-specific insights
        if (bottlenecks.capacity.score > 80) {
            let description = `Current load: ${bottlenecks.capacity.devicesPerAP} devices per AP`;
            
            // Add SSID-specific details if available
            if (bottlenecks.capacity.ssidAnalysis) {
                const worstSSID = bottlenecks.capacity.ssidAnalysis
                    .sort((a, b) => b.avgClientsPerAP - a.avgClientsPerAP)[0];
                
                if (worstSSID && worstSSID.avgClientsPerAP > bottlenecks.capacity.devicesPerAP * 1.5) {
                    description += `. "${worstSSID.ssid}" has ${Math.round(worstSSID.avgClientsPerAP)} devices per AP`;
                }
            }
            
            recommendations.push({
                priority: 'critical',
                title: 'Add Network Capacity',
                description: description,
                impact: 'Network may become unstable'
            });
        }
        
        // Signal recommendations with specific insights
        if (bottlenecks.signal.score > 60) {
            recommendations.push({
                priority: 'medium',
                title: 'Improve Signal Coverage',
                description: `${bottlenecks.signal.weakSignalPercentage}% devices have poor signal (< -70dBm)`,
                impact: 'Could improve reliability by 25%'
            });
        }
        
        // Timing recommendations
        if (bottlenecks.timing.score > 75) {
            recommendations.push({
                priority: 'medium',
                title: 'Optimize Peak Usage',
                description: `Severe congestion during peak periods`,
                impact: 'Could reduce peak congestion by 30%'
            });
        }
        
        // Add general recommendation if no specific issues but overall score is elevated
        if (recommendations.length === 0 && bottlenecks.channel.score > 40) {
            recommendations.push({
                priority: 'low',
                title: 'Monitor Network Performance',
                description: 'Network performance is acceptable but should be monitored',
                impact: 'Preventative maintenance recommended'
            });
        }
        
        return recommendations.sort((a, b) => this.getPriorityWeight(b.priority) - this.getPriorityWeight(a.priority));
    }
    
    getPriorityWeight(priority) {
        const weights = { critical: 4, high: 3, medium: 2, low: 1 };
        return weights[priority] || 0;
    }
}

const bottleneckDetector = new NetworkBottleneckDetector();
const BOTTLENECK_DEBUG = false;

async function loadBottleneckAnalysis() {
    if (BOTTLENECK_DEBUG) console.log('[BOTTLENECK] Starting bottleneck analysis...');
    try {
        // Use scan/report endpoint which has the networks array (not /intelligence/unified)
        const [reportData, historyData] = await Promise.all([
            fetchJSON('/scan/report'),
            fetchJSON('/history/samples?days=3')  // Get 3 days of history for timing analysis
        ]);
        if (BOTTLENECK_DEBUG) {
            console.log('[BOTTLENECK] Raw reportData:', reportData);
            console.log('[BOTTLENECK] Raw historyData:', historyData);
        }

        if (!reportData) {
            console.error('[BOTTLENECK] No reportData received!');
            updateBottleneckPanel(null);
            return;
        }

        if (!reportData.networks) {
            console.error('[BOTTLENECK] reportData.networks is missing! Available keys:', Object.keys(reportData));
            updateBottleneckPanel(null);
            return;
        }

        if (BOTTLENECK_DEBUG) console.log('[BOTTLENECK] Network count:', reportData.networks.length);

        // Extract data for bottleneck analysis from network scan report
        const channelCounts = Array(13).fill(0);
        const clientCounts = [];
        const rssiValues = [];
        const ssidData = new Map(); // Track SSIDs for better analysis

        reportData.networks.forEach((network, idx) => {
            // Handle both formats: clients can be an array of client objects, or stations can be a number
            const clientCount = Array.isArray(network.clients)
                ? network.clients.length
                : (network.stations || 0);

            if (BOTTLENECK_DEBUG) {
                console.log(`[BOTTLENECK] Network ${idx}:`, {
                    ssid: network.ssid,
                    channel: network.channel,
                    clientsRaw: network.clients,
                    stationsRaw: network.stations,
                    clientCount: clientCount,
                    rssi: network.rssi
                });
            }

            if (network.channel >= 1 && network.channel <= 13) {
                channelCounts[network.channel - 1]++;
            }

            clientCounts.push(clientCount);
            rssiValues.push(network.rssi || 0);

            // Track SSID data for capacity analysis
            if (network.ssid) {
                const existing = ssidData.get(network.ssid) || { count: 0, clients: 0, rssi: [] };
                existing.count++;
                existing.clients += clientCount;
                existing.rssi.push(network.rssi || 0);
                ssidData.set(network.ssid, existing);
            }
        });

        if (BOTTLENECK_DEBUG) {
            console.log('[BOTTLENECK] Extracted data:', {
                channelCounts,
                clientCounts,
                rssiValues,
                ssidData: Array.from(ssidData.entries())
            });
        }

        // Calculate bottlenecks with enhanced data
        if (BOTTLENECK_DEBUG) console.log('[BOTTLENECK] Calculating channel bottleneck...');
        const channelBottleneck = bottleneckDetector.calculateChannelBottleneck(channelCounts);
        if (BOTTLENECK_DEBUG) console.log('[BOTTLENECK] Channel result:', channelBottleneck);

        if (BOTTLENECK_DEBUG) console.log('[BOTTLENECK] Calculating capacity bottleneck...');
        const capacityBottleneck = bottleneckDetector.calculateCapacityBottleneck(clientCounts, reportData.networks.length);
        if (BOTTLENECK_DEBUG) console.log('[BOTTLENECK] Capacity result:', capacityBottleneck);

        if (BOTTLENECK_DEBUG) console.log('[BOTTLENECK] Calculating signal bottleneck...');
        const signalBottleneck = bottleneckDetector.calculateSignalBottleneck(rssiValues);
        if (BOTTLENECK_DEBUG) console.log('[BOTTLENECK] Signal result:', signalBottleneck);

        if (BOTTLENECK_DEBUG) console.log('[BOTTLENECK] Calculating timing bottleneck...');
        const timingBottleneck = bottleneckDetector.calculateTimingBottleneck(historyData?.samples || []);
        if (BOTTLENECK_DEBUG) console.log('[BOTTLENECK] Timing result:', timingBottleneck);

        const bottlenecks = {
            channel: channelBottleneck,
            capacity: capacityBottleneck,
            signal: signalBottleneck,
            timing: timingBottleneck
        };

        // Add SSID-specific analysis to capacity bottleneck
        if (ssidData.size > 0) {
            bottlenecks.capacity.ssidAnalysis = Array.from(ssidData.entries()).map(([ssid, data]) => ({
                ssid,
                apCount: data.count,
                totalClients: data.clients,
                avgRssi: data.rssi.reduce((a, b) => a + b, 0) / data.rssi.length,
                avgClientsPerAP: data.clients / data.count
            }));
            if (BOTTLENECK_DEBUG) console.log('[BOTTLENECK] Added SSID analysis:', bottlenecks.capacity.ssidAnalysis);
        }

        if (BOTTLENECK_DEBUG) console.log('[BOTTLENECK] Getting overall score...');
        const analysis = bottleneckDetector.getOverallBottleneckScore(bottlenecks);
        if (BOTTLENECK_DEBUG) console.log('[BOTTLENECK] Final analysis:', analysis);

        updateBottleneckPanel(analysis);

    } catch (error) {
        console.error('[BOTTLENECK] Failed to load bottleneck analysis:', error);
        if (BOTTLENECK_DEBUG) console.error('[BOTTLENECK] Error stack:', error.stack);
        updateBottleneckPanel(null);
    }
}

function updateBottleneckPanel(analysis) {
    console.log('[BOTTLENECK-UI] Updating panel with analysis:', analysis);

    if (!analysis) {
        console.warn('[BOTTLENECK-UI] No analysis data - showing error state');
        // Show error state
        $('#bottleneck-overall-score').querySelector('.score-value').textContent = '--';
        $('#bottleneck-severity').textContent = 'Analysis Failed';
        $('#bottleneck-summary').textContent = 'Unable to analyze network';
        return;
    }

    // Update overall score - handle NaN values properly
    const scoreCircle = $('#bottleneck-overall-score');
    const overallScore = isNaN(analysis.overallScore) ? 0 : analysis.overallScore;

    // If score is NaN/invalid, adjust severity to match the low visual (green circle)
    const displaySeverity = isNaN(analysis.overallScore) ? 'low' : analysis.severity;

    console.log('[BOTTLENECK-UI] Setting overall score:', overallScore, 'original:', analysis.overallScore);
    console.log('[BOTTLENECK-UI] Severity adjusted from', analysis.severity, 'to', displaySeverity);

    scoreCircle.querySelector('.score-value').textContent = overallScore;
    scoreCircle.dataset.score = overallScore;

    // Add severity class to the circle for border color
    scoreCircle.className = `bottleneck-score-circle ${displaySeverity}`;

    // Update severity text to match the circle color
    const severityEl = $('#bottleneck-severity');
    severityEl.textContent = displaySeverity.charAt(0).toUpperCase() + displaySeverity.slice(1) + ' Risk';
    severityEl.className = `bottleneck-severity ${displaySeverity}`;

    // Update summary
    const primaryBottleneck = analysis.bottlenecks[analysis.primaryBottleneck];
    console.log('[BOTTLENECK-UI] Primary bottleneck:', analysis.primaryBottleneck, primaryBottleneck);
    $('#bottleneck-summary').textContent = `Primary issue: ${analysis.primaryBottleneck} (${primaryBottleneck.detail})`;

    // Update individual metrics
    console.log('[BOTTLENECK-UI] Updating individual metrics...');
    updateBottleneckMetric('channel', analysis.bottlenecks.channel);
    updateBottleneckMetric('capacity', analysis.bottlenecks.capacity);
    updateBottleneckMetric('signal', analysis.bottlenecks.signal);
    updateBottleneckMetric('timing', analysis.bottlenecks.timing);

    // Update recommendations
    console.log('[BOTTLENECK-UI] Updating recommendations:', analysis.recommendations);
    updateRecommendations(analysis.recommendations);
}

function updateBottleneckMetric(type, data) {
    console.log(`[BOTTLENECK-METRIC] Updating ${type} metric:`, data);

    const scoreEl = $(`#${type}-score`);
    const fillEl = $(`#${type}-fill`);
    const detailEl = $(`#${type}-detail`);

    console.log(`[BOTTLENECK-METRIC] ${type} elements:`, {
        scoreEl: !!scoreEl,
        fillEl: !!fillEl,
        detailEl: !!detailEl
    });

    if (scoreEl) {
        const score = isNaN(data.score) ? 0 : data.score;
        console.log(`[BOTTLENECK-METRIC] ${type} setting score:`, score);
        scoreEl.textContent = score;
    } else {
        console.warn(`[BOTTLENECK-METRIC] ${type} scoreEl not found!`);
    }

    if (fillEl) {
        const score = isNaN(data.score) ? 0 : data.score;
        console.log(`[BOTTLENECK-METRIC] ${type} setting fill width: ${score}%, severity: ${data.severity}`);
        fillEl.style.width = `${score}%`;
        fillEl.className = `metric-fill ${data.severity}`;
    } else {
        console.warn(`[BOTTLENECK-METRIC] ${type} fillEl not found!`);
    }

    if (detailEl) {
        console.log(`[BOTTLENECK-METRIC] ${type} setting detail:`, data.detail);
        detailEl.textContent = data.detail;
    } else {
        console.warn(`[BOTTLENECK-METRIC] ${type} detailEl not found!`);
    }
}

function updateRecommendations(recommendations) {
    const container = $('#recommendations-list');
    if (!container) return;
    
    if (!recommendations || recommendations.length === 0) {
        container.innerHTML = '<div class="muted" style="font-size:11px;">No recommendations available</div>';
        return;
    }
    
    container.innerHTML = recommendations.map(rec => `
        <div class="recommendation-item ${rec.priority}">
            <div>
                <div class="recommendation-priority ${rec.priority}">${rec.priority}</div>
                <div class="recommendation-title">${rec.title}</div>
                <div class="recommendation-desc">${rec.description}</div>
                <div class="recommendation-impact">Impact: ${rec.impact}</div>
            </div>
        </div>
    `).join('');
}

function toggleBottleneckDetails() {
    const breakdown = $('#bottleneck-breakdown');
    const isVisible = breakdown.style.display !== 'none';
    breakdown.style.display = isVisible ? 'none' : 'block';
    
    // Update button text
    event.target.textContent = isVisible ? 'Details' : 'Hide Details';
}
