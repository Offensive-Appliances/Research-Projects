let scanData = [];
let accumulatedNetworks = new Map();
let selectedAP = null;
let selectedClients = {};
let scanInterval = null;
let agoTicker = null;
let privacyMode = false;

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function togglePrivacyMode() {
    privacyMode = !privacyMode;
    localStorage.setItem('privacyMode', privacyMode);
    applyPrivacyMode();
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

async function fetchJSON(url, opts = {}) {
    try {
        const res = await fetch(url, opts);
        if (!res.ok) {
            console.error(`HTTP error for ${url}: ${res.status} ${res.statusText}`);
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

async function loadScanData() {
    const data = await fetchJSON('/cached-scan');
    const status = await fetchJSON('/wifi/status');
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
        updateStats();
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
    scanData.forEach(ap => {
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

function updateStats() {
    const apCount = accumulatedNetworks.size;
    let clientCount = 0;
    const dataSource = Array.from(accumulatedNetworks.values());
    dataSource.forEach(ap => {
        if (ap.stations) clientCount += ap.stations.length;
    });
    
    const statEl = $('#scan-stats');
    if (statEl) {
        statEl.textContent = `${apCount} APs, ${clientCount} clients`;
    }
}

let scanInProgress = false;

async function triggerScan() {
    if (scanInProgress) {
        showToast('Scan already in progress');
        return;
    }

    scanInProgress = true;
    showWarningPopup('Scanning will temporarily interrupt your connection. You will need to reconnect or refresh this page after the scan completes.');
    await fetchJSON('/scan');
    setTimeout(() => {
        loadScanData();
        scanInProgress = false;
    }, 2000);
}

async function startDeauth() {
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
}

async function triggerBgScan() {
    showWarningPopup('Scanning will temporarily interrupt your connection. You may need to reconnect or refresh this page after the scan completes.');
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
    const data = await fetchJSON('/wifi/status');
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
        const arr = await fetchJSON('/captures') || [];
        
        if (arr.length === 0) {
            container.innerHTML = '<div class="muted">No captures yet</div>';
            return;
        }
        
        const statusRes = await fetchJSON('/wifi/status');
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
            fetchJSON('/scan/report')
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

    for (let hour = 0; hour < 24; hour++) {
        const byteIndex = Math.floor(hour / 8);
        const bitIndex = hour % 8;
        const isPresent = (presenceHours[byteIndex] >> bitIndex) & 1;
        const timeLabel = `${hour.toString().padStart(2, '0')}:00`;
        html += `<div class="hour ${isPresent ? 'active' : ''}" title="${timeLabel}"></div>`;
    }

    html += '</div>';
    html += '<div class="heatmap-hours"><span>00</span><span>06</span><span>12</span><span>18</span><span>23</span></div>';
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
        if (cached) redrawFn(cached.canvasId, cached.samples, cached.config);
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
    seriesData.forEach(series => {
        if (series.data.length === 0) return;

        const points = series.data.map((d, i) => ({
            x: series.data.length === 1 ? padding.left + chartWidth / 2 : padding.left + (i / (series.data.length - 1)) * chartWidth,
            y: padding.top + chartHeight - ((d.value - minValue) / (maxValue - minValue)) * chartHeight
        }));

        // Draw line with smooth joins
        if (points.length > 1) {
            ctx.strokeStyle = series.color;
            ctx.lineWidth = isMobile ? 1.5 : 2;
            ctx.lineJoin = 'round';
            ctx.lineCap = 'round';
            ctx.beginPath();
            points.forEach((p, i) => i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y));
            ctx.stroke();
        }

        // Draw points (smaller for multi-line)
        const pointSize = isMobile ? 2 : 3;
        points.forEach(p => {
            ctx.fillStyle = series.color;
            ctx.beginPath();
            ctx.arc(p.x, p.y, pointSize, 0, Math.PI * 2);
            ctx.fill();
        });
    });

    // X-axis labels (use first series for timestamps)
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
    
    // Build path points
    const points = dataPoints.map((d, i) => ({
        x: dataPoints.length === 1 ? padding.left + chartWidth / 2 : padding.left + (i / (dataPoints.length - 1)) * chartWidth,
        y: padding.top + chartHeight - ((d.value - minValue) / (maxValue - minValue)) * chartHeight,
        value: d.value,
        label: d.label
    }));

    // Draw area fill under line
    if (points.length > 1) {
        const areaGrad = ctx.createLinearGradient(0, padding.top, 0, padding.top + chartHeight);
        areaGrad.addColorStop(0, config.color + '40');
        areaGrad.addColorStop(1, config.color + '05');
        
        ctx.fillStyle = areaGrad;
        ctx.beginPath();
        ctx.moveTo(points[0].x, padding.top + chartHeight);
        points.forEach(p => ctx.lineTo(p.x, p.y));
        ctx.lineTo(points[points.length - 1].x, padding.top + chartHeight);
        ctx.closePath();
        ctx.fill();
    }

    // Draw line
    if (points.length > 1) {
        ctx.strokeStyle = config.color;
        ctx.lineWidth = 2.5;
        ctx.lineJoin = 'round';
        ctx.lineCap = 'round';
        ctx.beginPath();
        points.forEach((p, i) => i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y));
        ctx.stroke();
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
    const date = new Date(sample.epoch_ts * 1000);
    return date.toLocaleTimeString('en', { hour: '2-digit', minute: '2-digit' });
}

function updateGraphOverlayState(graphKey, active) {
    const overlay = document.querySelector(`.graph-overlay[data-graph="${graphKey}"]`);
    if (!overlay) return;
    overlay.textContent = active ? HISTORY_OVERLAY_TEXT : '';
    overlay.classList.toggle('active', active);
}

function renderCharts(samples) {
    const needsMoreData = !samples || samples.length < HISTORY_READY_THRESHOLD;

    // Show/hide overlays based on data availability
    updateGraphOverlayState('activity', needsMoreData);
    updateGraphOverlayState('channel', needsMoreData);
    updateGraphOverlayState('ssid-clients', false); // Always show (uses current data, not history)

    if (!samples || samples.length === 0) return;

    // activity chart - show APs and clients as separate lines with smoothing
    drawMultiLineChart('#activity-chart', samples, {
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

                apData.push({ label, value: apAvg });
                clientData.push({ label, value: clientAvg });
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

    drawMultiLineChart('#channel-chart-time', samples, {
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
                        value: avg
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

    const data = await fetchJSON('/scan/report');
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

    addToChartCache(canvas, { canvasId, networks });
    setupChartResize(canvas, (id, cachedData) => {
        if (cachedData && cachedData.networks) {
            drawSSIDClientsChartImpl(id, cachedData.networks);
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
        ctx.font = '12px system-ui, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(net.stations, x + barWidth / 2, y - 5);

        // Draw SSID label (rotated)
        ctx.save();
        ctx.translate(x + barWidth / 2, padding.top + chartHeight + 10);
        ctx.rotate(-Math.PI / 4);
        ctx.fillStyle = '#aaa';
        ctx.font = '11px system-ui, sans-serif';
        ctx.textAlign = 'right';
        const ssid = net.ssid || `Hidden`;
        const displaySsid = privacyMode ? '••••••••' : (ssid.length > 15 ? ssid.slice(0, 15) + '...' : ssid);
        ctx.fillText(displaySsid, 0, 0);
        ctx.restore();
    });

    // Draw Y-axis labels
    ctx.fillStyle = '#666';
    ctx.font = '12px system-ui, sans-serif';
    ctx.textAlign = 'right';
    for (let i = 0; i <= 5; i++) {
        const val = Math.round((maxClients / 5) * i);
        const y = padding.top + chartHeight - ((chartHeight / 5) * i);
        ctx.fillText(val, padding.left - 10, y + 4);
    }

    // Title
    ctx.fillStyle = '#fff';
    ctx.font = 'bold 14px system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Top Networks by Client Count', rect.width / 2, isMobile ? 15 : 20);
}

async function loadHistoryCharts(days) {
    const data = await fetchJSON(`/history/samples?days=${days}`);
    if (!data || !data.samples || data.samples.length === 0) {
        showToast('No history data available yet');
        return;
    }

    const desc = document.querySelector('.history-description');
    if (desc) {
        desc.textContent = days === 1
            ? 'Network activity charts (last 24 hours)'
            : days < 1
            ? `Network activity charts (last ${Math.round(days * 24)} hours)`
            : `Network activity charts (last ${days} days)`;
    }

    // Use samples directly without unnecessary padding
    chartData = data.samples;
    renderCharts(data.samples);
    showToast(`Loaded ${data.samples.length} samples (${Math.round(days * 24)} hour range)`);
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
    const allEventsCheckbox = $('#webhook-all-events');
    const status = $('#webhook-status');
    
    if (enabledCheckbox) enabledCheckbox.checked = data.enabled;
    if (urlInput) urlInput.value = data.url || '';
    if (trackedOnlyCheckbox) trackedOnlyCheckbox.checked = data.tracked_only;
    if (homeDepartureCheckbox) homeDepartureCheckbox.checked = data.home_departure_alert;
    if (homeArrivalCheckbox) homeArrivalCheckbox.checked = data.home_arrival_alert;
    if (newDeviceCheckbox) newDeviceCheckbox.checked = data.new_device_alert;
    if (allEventsCheckbox) allEventsCheckbox.checked = data.all_events;
    
    if (status) {
        const pending = data.total_events - data.send_cursor;
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
    const all_events = $('#webhook-all-events')?.checked ?? false;
    
    const res = await fetchJSON('/webhook/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled, url, tracked_only, home_departure_alert, home_arrival_alert, new_device_alert, all_events })
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
    initPrivacyMode();
    loadScanData();
    loadApConfig();
    loadNetworkStatus();
    loadHandshakes();
    loadGpioStatus();
    updateBgScanStatus();
    loadScanSettings();
    loadDeviceIntelligence();
    loadHistoryCharts(7);
    loadHomeSSIDs();
    loadWebhookConfig();

    // Sync device sort dropdown with currentSort state
    const deviceSort = $('#device-sort');
    if (deviceSort) {
        deviceSort.value = deviceIntelligenceData.currentSort;
    }

    addTrackedInterval(loadNetworkStatus, 10000);
    addTrackedInterval(updateBgScanStatus, 5000);
    addTrackedInterval(loadDeviceIntelligence, 60000); // Reduced from 30s to 60s
    if (!agoTicker) agoTicker = addTrackedInterval(updateAgoTick, 1000);

    const apForm = $('#ap-config-form');
    if (apForm) apForm.onsubmit = saveApConfig;

    const netForm = $('#network-form');
    if (netForm) netForm.onsubmit = connectToNetwork;

    const webhookForm = $('#webhook-form');
    if (webhookForm) webhookForm.onsubmit = saveWebhookConfig;
});

window.addEventListener('beforeunload', cleanupAllResources);
