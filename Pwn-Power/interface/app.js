let scanData = [];
let selectedAP = null;
let selectedClients = {};
let scanInterval = null;
let agoTicker = null;

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

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
        return await res.json();
    } catch (e) {
        console.error('Fetch error:', e);
        return null;
    }
}

async function loadScanData() {
    const data = await fetchJSON('/cached-scan');
    const status = await fetchJSON('/wifi/status');
    if (data && data.rows) {
        scanData = data.rows;
        renderNetworkTable('recon-table', false, status);
        renderNetworkTable('attack-table', true, status);
        renderChannelChart();
        updateStats();
    }
}

function computeLastSeenTimestamp(status, lastSeenUptimeSec) {
    const uptime = status?.uptime;
    const epochNow = status?.timestamp;
    const timeSynced = status?.time_synced;

    if (!lastSeenUptimeSec || !uptime) return '--';
    if (lastSeenUptimeSec > uptime) return '--';
    if (!timeSynced || !epochNow) return '--';

    const epoch = epochNow - (uptime - lastSeenUptimeSec);
    if (!epoch || epoch <= 0) return '--';
    return new Date(epoch * 1000).toISOString();
}

function computeLastSeenRelative(status, lastSeenUptimeSec) {
    const uptime = status?.uptime;
    if (!lastSeenUptimeSec || !uptime) return '--';
    if (lastSeenUptimeSec > uptime) return '--';
    return formatUptime(uptime - lastSeenUptimeSec);
}

function renderNetworkTable(tableId, selectable, status) {
    const tbody = $(`#${tableId}`);
    if (!tbody) return;
    tbody.innerHTML = '';
    const nowMs = Date.now();
    
    scanData.forEach(ap => {
        const row = document.createElement('tr');
        row.dataset.mac = ap.MAC;
        row.dataset.channel = ap.Channel;
        const uptime = status?.uptime || 0;
        const age = (ap.last_seen && uptime && ap.last_seen <= uptime) ? (uptime - ap.last_seen) : null;
        row.innerHTML = `
            <td>${ap.SSID || '(Hidden)'}</td>
            <td><code>${ap.MAC}</code></td>
            <td class="muted">${ap.Vendor || 'Unknown'}</td>
            <td>${ap.Security}</td>
            <td>${ap.Channel}</td>
            <td>${ap.RSSI || '--'}</td>
            <td class="muted">${age === null ? '--' : `<span class="js-ago" data-ago-base="${age}" data-ago-start="${nowMs}">${formatUptime(age)}</span>`}</td>
        `;
        
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
                const staAge = (sta.last_seen && uptime && sta.last_seen <= uptime) ? (uptime - sta.last_seen) : null;
                clientRow.innerHTML = `
                    <td>↳ Client</td>
                    <td><code>${sta.mac}</code></td>
                    <td class="muted">${sta.vendor || 'Unknown'}</td>
                    <td></td>
                    <td></td>
                    <td>${sta.rssi}</td>
                    <td class="muted">${staAge === null ? '--' : `<span class="js-ago" data-ago-base="${staAge}" data-ago-start="${nowMs}">${formatUptime(staAge)}</span>`}</td>
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

    updateAgoTick();
}

function selectAP(row, ap) {
    const wasSelected = row.classList.contains('selected');
    $$('#attack-table tr.selected').forEach(r => r.classList.remove('selected'));
    
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
    const apCount = scanData.length;
    let clientCount = 0;
    scanData.forEach(ap => {
        if (ap.stations) clientCount += ap.stations.length;
    });
    
    const statEl = $('#scan-stats');
    if (statEl) statEl.textContent = `${apCount} APs, ${clientCount} clients`;
}

async function triggerScan() {
    showWarningPopup('Scanning will temporarily interrupt your connection. You will need to reconnect or refresh this page after the scan completes.');
    await fetchJSON('/scan');
    setTimeout(loadScanData, 2000);
}

async function startDeauth() {
    if (!selectedAP) return showToast('Select a target first');
    
    const targets = selectedClients[selectedAP.MAC] || [];
    const body = {
        mac: selectedAP.MAC,
        channel: String(selectedAP.Channel),
        state: 'start',
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

async function downloadReport() {
    const data = await fetchJSON('/scan/report');
    const secStats = await fetchJSON('/security/stats');
    if (!data) return showToast('Failed to get report');
    
    const now = new Date();
    const hours = data.summary?.monitoring_hours || 0;
    const days = Math.floor(hours / 24);
    const remHours = (hours % 24).toFixed(1);
    const duration = days > 0 ? `${days}d ${remHours}h` : `${hours.toFixed(1)}h`;
    
    let csv = '';
    
    csv += 'PWNPOWER SCAN REPORT\n';
    csv += `Generated,${now.toISOString()}\n`;
    csv += `Uptime,${duration}\n`;
    csv += `Total Scans,${data.summary?.total_scans || 0}\n`;
    csv += `APs Found,${data.summary?.unique_aps || 0}\n`;
    csv += `Clients Found,${data.summary?.unique_stations || 0}\n`;
    csv += `Scans/Hour,${hours > 0 ? ((data.summary?.total_scans || 0) / hours).toFixed(2) : 0}\n\n`;
    
    csv += 'SECURITY EVENTS\n';
    csv += `Deauth Frames Detected,${secStats?.deauth_count || 0}\n`;
    csv += `Last Deauth,${secStats?.deauth_last_seen > 0 ? formatUptime(secStats.deauth_last_seen) : 'None'}\n`;
    csv += `Hidden APs Found,${secStats?.hidden_count || 0}\n`;
    if (secStats?.hidden_aps?.length > 0) {
        csv += 'Hidden Networks\n';
        csv += 'BSSID,Status,SSID\n';
        secStats.hidden_aps.forEach(h => {
            const status = h.revealed ? 'Revealed' : 'Unknown';
            const ssid = h.revealed && h.ssid ? h.ssid : '(not revealed)';
            csv += `${h.bssid},${status},"${ssid}"\n`;
        });
    }
    csv += '\n';
    
    csv += 'SECURITY BREAKDOWN\n';
    csv += 'Type,Count,Percentage\n';
    const sec = data.security_analysis || {};
    const total = (data.summary?.unique_aps || 1);
    csv += `Open,${sec.open || 0},${((sec.open || 0) / total * 100).toFixed(1)}%\n`;
    csv += `WEP,${sec.wep || 0},${((sec.wep || 0) / total * 100).toFixed(1)}%\n`;
    csv += `WPA2,${sec.wpa2 || 0},${((sec.wpa2 || 0) / total * 100).toFixed(1)}%\n`;
    csv += `WPA3,${sec.wpa3 || 0},${((sec.wpa3 || 0) / total * 100).toFixed(1)}%\n`;
    csv += `WPA2/WPA3,${sec.wpa2_wpa3 || 0},${((sec.wpa2_wpa3 || 0) / total * 100).toFixed(1)}%\n\n`;
    
    csv += 'CHANNEL USAGE\n';
    csv += 'Channel,AP Count\n';
    if (data.channel_analysis?.channels) {
        data.channel_analysis.channels.forEach(ch => {
            csv += `${ch.channel},${ch.ap_count}\n`;
        });
    }
    csv += '\n';
    
    const status = await fetchJSON('/wifi/status');
    
    csv += 'ACCESS POINTS\n';
    csv += 'SSID,BSSID,Vendor,Channel,RSSI (dBm),Security,Clients,Hidden,Last Seen\n';
    if (data.networks) {
        data.networks.forEach(net => {
            const hidden = !net.ssid || net.ssid === '' ? 'Yes' : 'No';
            const ssid = net.ssid || "(Hidden)";
            const vendor = net.vendor || "Unknown";
            const lastSeen = computeLastSeenTimestamp(status, net.last_seen);
            csv += '"' + ssid + '",' + net.bssid + ',"' + vendor + '",' + net.channel + ',' + net.rssi + ',' + net.security + ',' + net.stations + ',' + hidden + ',' + lastSeen + '\n';
        });
    }
    csv += '\n';
    
    csv += 'CLIENTS\n';
    csv += 'MAC,Vendor,AP BSSID,AP SSID,RSSI (dBm),Random MAC,Last Seen\n';
    if (data.networks) {
        data.networks.forEach(net => {
            if (net.clients) {
                net.clients.forEach(client => {
                    const randomMac = client.vendor === 'Random MAC' ? 'Yes' : 'No';
                    const cVendor = client.vendor || "Unknown";
                    const cSsid = net.ssid || "(Hidden)";
                    const lastSeen = computeLastSeenTimestamp(status, client.last_seen);
                    csv += client.mac + ',"' + cVendor + '",' + net.bssid + ',"' + cSsid + '",' + client.rssi + ',' + randomMac + ',' + lastSeen + '\n';
                });
            }
        });
    }
    csv += '\n';
    
    csv += 'VULNERABLE NETWORKS (WPA2 with clients)\n';
    csv += 'SSID,BSSID,Vendor,Channel,RSSI,Clients,Score\n';
    if (data.networks) {
        const vulnerable = data.networks
            .filter(net => net.security && net.security.includes('WPA2') && !net.security.includes('WPA3') && net.stations > 0)
            .map(net => {
                const rssiBonus = net.rssi > -50 ? 3 : net.rssi > -65 ? 2 : net.rssi > -75 ? 1 : 0;
                return { ...net, score: (net.stations * 3) + rssiBonus };
            })
            .sort((a, b) => b.score - a.score);
        
        vulnerable.forEach(net => {
            const ssid = net.ssid || "(Hidden)";
            const vendor = net.vendor || "Unknown";
            csv += '"' + ssid + '",' + net.bssid + ',"' + vendor + '",' + net.channel + ',' + net.rssi + ',' + net.stations + ',' + net.score + '\n';
        });
        if (vulnerable.length === 0) csv += 'None found\n';
    }
    csv += '\n';
    
    csv += 'SUMMARY\n';
    const openCount = sec.open || 0;
    const wepCount = sec.wep || 0;
    csv += `Open/WEP Networks,${openCount + wepCount}\n`;
    csv += `Total Clients,${data.summary?.unique_stations || 0}\n`;
    csv += `Total APs,${data.summary?.unique_aps || 0}\n`;
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pwnpower_report_${now.toISOString().slice(0,10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Report downloaded');
}

async function loadApConfig() {
    const data = await fetchJSON('/ap/config');
    if (!data) return;
    
    $('#current-ssid').textContent = data.ssid || '--';
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
        if (info) info.textContent = data.saved_ssid || '';
    } else {
        if (dot) dot.className = 'status-dot offline';
        if (text) text.textContent = 'Disconnected';
        if (info) {
            if (data && data.has_saved && data.saved_ssid) {
                info.textContent = `Saved: ${data.saved_ssid}`;
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
    if (sec < 60) return sec + 's ago';
    if (sec < 3600) return Math.floor(sec / 60) + 'm ago';
    if (sec < 86400) return Math.floor(sec / 3600) + 'h ago';
    return Math.floor(sec / 86400) + 'd ago';
}

function updateAgoTick() {
    const now = Date.now();
    document.querySelectorAll('.js-ago').forEach(el => {
        const base = parseInt(el.dataset.agoBase || '0', 10);
        const start = parseInt(el.dataset.agoStart || '0', 10);
        if (!start) return;
        const sec = base + Math.floor((now - start) / 1000);
        el.textContent = formatUptime(sec);
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
                    <div class="muted">${h.bssid} • ch ${h.channel} • ${h.eapol} EAPOL</div>
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

async function loadIntelligence() {
    const data = await fetchJSON('/intelligence');
    const report = await fetchJSON('/scan/report');
    if (!data) return;
    
    const el = (id) => document.getElementById(id);
    
    if (data.presence) {
        const p = data.presence;
        if (el('intel-present')) el('intel-present').textContent = p.devices_present || 0;
        if (el('intel-away')) el('intel-away').textContent = p.devices_away || 0;
        if (el('intel-new')) el('intel-new').textContent = p.new_today || 0;
        if (el('intel-total')) el('intel-total').textContent = (p.devices_present || 0) + (p.devices_away || 0);
    }
    
    if (data.security) {
        const s = data.security;
        if (el('intel-deauth')) el('intel-deauth').textContent = s.deauth_events || 0;
        if (el('intel-rogue')) el('intel-rogue').textContent = s.rogue_aps || 0;
        if (el('intel-open')) el('intel-open').textContent = s.open_networks || 0;
        if (el('intel-hidden')) el('intel-hidden').textContent = s.hidden_networks || 0;
        
        const threats = (s.deauth_events || 0) + (s.rogue_aps || 0);
        if (el('intel-threats')) el('intel-threats').textContent = threats;
    }
    
    if (data.network) {
        const n = data.network;
        if (el('intel-home')) el('intel-home').textContent = n.home_ssid || '--';
        if (el('intel-strongest')) el('intel-strongest').textContent = n.strongest_ap || '--';
        if (el('intel-rssi')) el('intel-rssi').textContent = n.strongest_rssi || '--';
    }
    
    if (data.uptime_hours !== undefined) {
        if (el('intel-uptime')) el('intel-uptime').textContent = data.uptime_hours.toFixed(1) + 'h';
    }
    
    if (report) {
        if (report.summary) {
            if (el('intel-scans')) el('intel-scans').textContent = report.summary.total_scans || 0;
            if (el('intel-aps')) el('intel-aps').textContent = report.summary.unique_aps || 0;
            if (el('intel-clients')) el('intel-clients').textContent = report.summary.unique_stations || 0;
        }
        if (report.channel_analysis && report.channel_analysis.channels) {
            if (el('intel-channels')) el('intel-channels').textContent = report.channel_analysis.channels.length || 0;
        }
    }
}

let devicesVisible = false;

async function loadDevicePresence() {
    const data = await fetchJSON('/devices/presence');
    const container = document.getElementById('device-list');
    const button = document.querySelector('button[onclick="loadDevicePresence()"]');
    if (!container || !data || !data.devices) return;
    
    if (devicesVisible) {
        // Hide devices
        container.innerHTML = '';
        button.textContent = 'Show All Devices';
        devicesVisible = false;
    } else {
        // Show devices
        if (data.devices.length === 0) {
            container.innerHTML = '<div class="muted">No devices tracked yet</div>';
        } else {
            container.innerHTML = data.devices.map(d => {
                const statusClass = d.present ? 'online' : 'offline';
                const statusText = d.present ? 'Present' : `Away ${formatUptime(d.last_seen_ago)}`;
                return `
                    <div class="card" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                        <div>
                            <strong>${d.mac}</strong>
                            <div class="muted">${d.vendor || 'Unknown'} • RSSI: ${d.rssi} dBm • Seen ${d.sightings}x</div>
                            <div class="muted">Last AP: ${d.last_ap || 'Unknown'}</div>
                        </div>
                        <div class="status-badge">
                            <span class="status-dot ${statusClass}"></span>
                            <span>${statusText}</span>
                        </div>
                    </div>
                `;
            }).join('');
        }
        button.textContent = 'Hide Devices';
        devicesVisible = true;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadScanData();
    loadApConfig();
    loadNetworkStatus();
    loadHandshakes();
    loadGpioStatus();
    updateBgScanStatus();
    loadScanSettings();
    loadIntelligence();
    
    setInterval(loadNetworkStatus, 10000);
    setInterval(updateBgScanStatus, 5000);
    setInterval(loadIntelligence, 30000);
    if (!agoTicker) agoTicker = setInterval(updateAgoTick, 1000);
    
    const apForm = $('#ap-config-form');
    if (apForm) apForm.onsubmit = saveApConfig;
    
    const netForm = $('#network-form');
    if (netForm) netForm.onsubmit = connectToNetwork;
});
