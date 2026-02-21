async function downloadReport() {
    showToast('Generating report, please wait...');
    
    const [data, secStats, scanSettings, apConfig, netStatus, intelUnified] = await Promise.all([
        fetchJSON('/scan/report').catch(e => { console.error('/scan/report failed:', e); return null; }),
        fetchJSON('/security/stats').catch(e => { console.error('/security/stats failed:', e); return null; }),
        fetchJSON('/scan/settings').catch(e => { console.error('/scan/settings failed:', e); return null; }),
        fetchJSON('/ap/config').catch(e => { console.error('/ap/config failed:', e); return null; }),
        fetchJSON('/wifi/status').catch(e => { console.error('/wifi/status failed:', e); return null; }),
        fetchJSON('/intelligence/unified').catch(e => { console.error('/intelligence/unified failed:', e); return null; })
    ]);
    
    if (!data) {
        showToast('Failed to get scan report data - check console for details');
        console.error('Scan report endpoint returned null or invalid data');
        return;
    }
    
    console.log('Report data loaded:', {
        data: !!data,
        secStats: !!secStats,
        scanSettings: !!scanSettings,
        apConfig: !!apConfig,
        netStatus: !!netStatus,
        intelUnified: !!intelUnified
    });

    const now = new Date();
    const hours = data.summary?.monitoring_hours || 0;
    const days = Math.floor(hours / 24);
    const remHours = (hours % 24).toFixed(1);
    const duration = days > 0 ? `${days}d ${remHours}h` : `${hours.toFixed(1)}h`;

    const lines = [];
    const addSection = (title, headers = []) => {
        if (lines.length) lines.push('');
        lines.push(`[${title}]`);
        if (headers.length) lines.push(headers.join(','));
    };

    addSection('Report Summary', ['Metric', 'Value', 'Unit']);
    lines.push(`Report Generated,${now.toISOString()},timestamp`);
    lines.push(`Monitoring Duration,${duration},time`);
    lines.push(`Total Scans,${data.summary?.total_scans || 0},count`);
    lines.push(`Unique APs,${data.summary?.unique_aps || 0},count`);
    lines.push(`Unique Clients,${data.summary?.unique_stations || 0},count`);
    lines.push(`Scan Rate,${hours > 0 ? ((data.summary?.total_scans || 0) / hours).toFixed(2) : 0},scans_per_hour`);

    if (intelUnified && intelUnified.summary && intelUnified.summary.presence) {
        const presence = intelUnified.summary.presence;
        addSection('Device Presence Metrics', ['Metric', 'Value', 'Unit']);
        lines.push(`Devices Present,${presence.devices_present ?? 0},count`);
        lines.push(`Devices Away,${presence.devices_away ?? 0},count`);
        lines.push(`New Today,${presence.new_today ?? 0},count`);
        lines.push(`Total Known Devices,${(presence.devices_present || 0) + (presence.devices_away || 0)},count`);
    } else {
        console.warn('Intelligence unified data not available for presence metrics');
    }

    if (intelUnified && intelUnified.summary && intelUnified.summary.security) {
        const secSummary = intelUnified.summary.security;
        addSection('Security Events Summary', ['Event_Type', 'Count', 'Severity']);
        lines.push(`Deauthentication Frames,${secSummary.deauth_events ?? 0},medium`);
        lines.push(`Rogue Access Points,${secSummary.rogue_aps ?? 0},high`);
        lines.push(`Open Networks,${secSummary.open_networks ?? 0},high`);
        lines.push(`Hidden Networks,${secSummary.hidden_networks ?? 0},low`);
    } else {
        console.warn('Intelligence unified data not available for security metrics');
    }

    if (intelUnified && intelUnified.summary && intelUnified.summary.network) {
        const netSummary = intelUnified.summary.network;
        addSection('Network Statistics', ['Metric', 'Value', 'Unit']);
        lines.push(`Unique Access Points,${netSummary.unique_aps ?? 0},count`);
        lines.push(`Unique Client Devices,${netSummary.unique_stations ?? 0},count`);
        lines.push(`Active WiFi Channels,${netSummary.active_channels ?? 0},count`);
        lines.push(`Total Monitoring Time,${intelUnified.summary.uptime_hours || 0},hours`);
    } else {
        console.warn('Intelligence unified data not available for network stats');
    }

    if (scanSettings) {
        addSection('Scan Settings', ['Setting', 'Value']);
        lines.push(`Background Scanning,${scanSettings.bg_enabled ? 'Enabled' : 'Disabled'}`);
        lines.push(`Scan Interval (min),${(scanSettings.bg_interval || 0) / 60}`);
        lines.push(`Auto Handshake,${scanSettings.auto_handshake ? 'Enabled' : 'Disabled'}`);
        lines.push(`Idle Threshold (s),${scanSettings.idle_threshold ?? 'n/a'}`);
        lines.push(`Handshake Duration (s),${scanSettings.handshake_duration ?? 'n/a'}`);
    }

    if (apConfig) {
        addSection('AP Configuration', ['Field', 'Value']);
        lines.push(`SSID,${apConfig.ssid || '--'}`);
        lines.push(`Security,${apConfig.has_password ? 'WPA2/WPA3' : 'Open'}`);
        lines.push(`Channel,${apConfig.channel ?? 'n/a'}`);
        lines.push(`Clients Allowed,${apConfig.max_clients ?? 'n/a'}`);
    }

    if (netStatus) {
        addSection('Live Network Status', ['Field', 'Value']);
        lines.push(`Status,${netStatus.status || 'unknown'}`);
        lines.push(`SSID,${netStatus.saved_ssid || netStatus.current_ssid || '--'}`);
        lines.push(`Auto-Connect,${netStatus.auto_connect ? 'Enabled' : 'Disabled'}`);
        lines.push(`AP While Connected,${netStatus.ap_while_connected ? 'Enabled' : 'Disabled'}`);
        lines.push(`Uptime (s),${netStatus.uptime ?? 'n/a'}`);
    }

    addSection('Security Events', ['Event', 'Value']);
    lines.push(`Deauth Frames Detected,${secStats?.deauth_count || 0}`);
    lines.push(`Last Deauth,${secStats?.deauth_last_seen > 0 ? formatUptime(secStats.deauth_last_seen) : 'None'}`);
    lines.push(`Hidden APs Found,${secStats?.hidden_count || 0}`);

    if (secStats?.hidden_aps?.length > 0) {
        addSection('Hidden Networks', ['BSSID', 'Status', 'SSID']);
        secStats.hidden_aps.forEach(h => {
            const status = h.revealed ? 'Revealed' : 'Unknown';
            const ssid = h.revealed && h.ssid ? h.ssid : '(not revealed)';
            lines.push(`${h.bssid},${status},"${ssid}"`);
        });
    }

    const sec = data.security_analysis || {};
    const total = (data.summary?.unique_aps || 1);
    addSection('Security Protocol Distribution', ['Protocol', 'Network_Count', 'Percentage', 'Risk_Level']);
    lines.push(`Open,${sec.open || 0},${((sec.open || 0) / total * 100).toFixed(1)}%,Critical`);
    lines.push(`WEP,${sec.wep || 0},${((sec.wep || 0) / total * 100).toFixed(1)}%,Critical`);
    lines.push(`WPA2,${sec.wpa2 || 0},${((sec.wpa2 || 0) / total * 100).toFixed(1)}%,Low`);
    lines.push(`WPA3,${sec.wpa3 || 0},${((sec.wpa3 || 0) / total * 100).toFixed(1)}%,Very Low`);
    lines.push(`WPA2/WPA3,${sec.wpa2_wpa3 || 0},${((sec.wpa2_wpa3 || 0) / total * 100).toFixed(1)}%,Very Low`);

    addSection('Channel Usage', ['Channel', 'AP Count']);
    if (data.channel_analysis?.channels) {
        data.channel_analysis.channels.forEach(ch => {
            lines.push(`${ch.channel},${ch.ap_count}`);
        });
    }

    const status = await fetchJSON('/wifi/status').catch(e => {
        console.warn('Failed to fetch wifi status for timestamp calculations:', e);
        return null;
    });

    addSection('Wireless Access Points Inventory', ['SSID', 'BSSID', 'Vendor', 'Channel', 'RSSI_dBm', 'Security_Protocol', 'Client_Count', 'Hidden_Network', 'Last_Seen_Timestamp']);
    if (data.networks) {
        data.networks.forEach(net => {
            const hidden = !net.ssid || net.ssid === '' ? 'True' : 'False';
            const ssid = net.ssid || "(Hidden)";
            const vendor = net.vendor || "Unknown";
            const lastSeen = computeLastSeenTimestamp(status, net.last_seen);
            lines.push(`"${ssid}",${net.bssid},"${vendor}",${net.channel},${net.rssi},${net.security},${net.stations},${hidden},${lastSeen}`);
        });
    }

    addSection('Wireless Client Inventory', ['Client_MAC', 'Vendor', 'Associated_AP_BSSID', 'Associated_AP_SSID', 'RSSI_dBm', 'Randomized_MAC', 'Last_Seen_Timestamp']);
    if (data.networks) {
        data.networks.forEach(net => {
            if (net.clients) {
                net.clients.forEach(client => {
                    const randomMac = client.vendor === 'Random MAC' ? 'True' : 'False';
                    const cVendor = client.vendor || "Unknown";
                    const cSsid = net.ssid || "(Hidden)";
                    const lastSeen = computeLastSeenTimestamp(status, client.last_seen);
                    lines.push(`${client.mac},"${cVendor}",${net.bssid},"${cSsid}",${client.rssi},${randomMac},${lastSeen}`);
                });
            }
        });
    }

    addSection('Vulnerability Assessment - WPA2 Networks', ['SSID', 'BSSID', 'Vendor', 'Channel', 'RSSI_dBm', 'Client_Count', 'Risk_Score', 'Threat_Level']);
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
            const threatLevel = net.score >= 15 ? 'Critical' : net.score >= 10 ? 'High' : net.score >= 5 ? 'Medium' : 'Low';
            lines.push(`"${ssid}",${net.bssid},"${vendor}",${net.channel},${net.rssi},${net.stations},${net.score},${threatLevel}`);
        });
        if (vulnerable.length === 0) lines.push('No vulnerable networks detected');
    }
    
    // Add historical chart data if available
    if (chartData && chartData.length > 0) {
        // Raw sample data (unique fields not available in other formats)
        addSection('Raw Sample Data', ['Sample_Index', 'Timestamp', 'Uptime_Seconds', 'Time_Valid', 'AP_Count', 'Client_Count', 'Total_Devices']);
        chartData.forEach((sample, index) => {
            const timestamp = sample.epoch_ts ? new Date(sample.epoch_ts * 1000).toISOString() : '';
            const uptime = sample.uptime_sec || 0;
            const timeValid = sample.time_valid || false;
            const totalDevices = (sample.ap_count || 0) + (sample.client_count || 0);
            lines.push(`${index},"${timestamp}",${uptime},${timeValid},${sample.ap_count || 0},${sample.client_count || 0},${totalDevices}`);
        });

        // Time-series sensor data (following IoT/logging standards)
        addSection('Time-Series Network Data', ['Timestamp', 'Device_Type', 'Count', 'Measurement_Unit']);
        chartData.forEach(sample => {
            const timestamp = sample.epoch_ts ? new Date(sample.epoch_ts * 1000).toISOString() : formatHistoryLabel(sample);
            lines.push(`${timestamp},Access Point,${sample.ap_count || 0},devices`);
            lines.push(`${timestamp},Client Device,${sample.client_count || 0},devices`);
        });

        // Channel utilization matrix (following spectrum analysis format)
        addSection('Channel Utilization Matrix', ['Timestamp', 'Channel_Number', 'AP_Count', 'Utilization_Percent']);
        chartData.forEach(sample => {
            const timestamp = sample.epoch_ts ? new Date(sample.epoch_ts * 1000).toISOString() : formatHistoryLabel(sample);
            if (sample.channel_counts) {
                sample.channel_counts.forEach((count, ch) => {
                    const utilization = count > 0 ? ((count / (sample.ap_count || 1)) * 100).toFixed(1) : '0.0';
                    lines.push(`${timestamp},${ch + 1},${count},${utilization}`);
                });
            }
        });

        // SSID activity log (following network monitoring format)
        addSection('SSID Activity Log', ['Timestamp', 'SSID_Hash', 'Client_Count', 'Activity_Level']);
        chartData.forEach(sample => {
            if (sample.ssid_clients && sample.ssid_clients.length > 0) {
                const timestamp = sample.epoch_ts ? new Date(sample.epoch_ts * 1000).toISOString() : formatHistoryLabel(sample);
                sample.ssid_clients.forEach(entry => {
                    const activity = entry.count >= 10 ? 'High' : entry.count >= 5 ? 'Medium' : entry.count >= 1 ? 'Low' : 'None';
                    lines.push(`${timestamp},${entry.hash},${entry.count},${activity}`);
                });
            }
        });

        // Channel analysis summary (following spectrum monitoring format)
        addSection('Channel Analysis Summary', ['Channel', 'Total_Observations', 'Peak_AP_Count', 'Average_AP_Count', 'Busiest_Rank']);
        const channelStats = new Map();
        chartData.forEach(sample => {
            if (sample.channel_counts) {
                sample.channel_counts.forEach((count, ch) => {
                    const stats = channelStats.get(ch) || { total: 0, peak: 0, samples: 0 };
                    stats.total += count;
                    stats.peak = Math.max(stats.peak, count);
                    stats.samples++;
                    channelStats.set(ch, stats);
                });
            }
        });

        const channelRankings = Array.from(channelStats.entries())
            .sort(([,a], [,b]) => b.total - a.total)
            .map(([ch]) => ch);

        for (let ch = 0; ch < 13; ch++) {
            const stats = channelStats.get(ch) || { total: 0, peak: 0, samples: 0 };
            const avg = stats.samples > 0 ? Math.round(stats.total / stats.samples) : 0;
            const rank = channelRankings.indexOf(ch) + 1;
            lines.push(`${ch + 1},${stats.samples},${stats.peak},${avg},${rank > 0 ? `#${rank}` : 'N/A'}`);
        }

        // Performance metrics summary (following monitoring dashboard format)
        addSection('Performance Metrics Summary', ['Metric', 'Value', 'Unit', 'Status']);
        const totalSamples = chartData.length;
        const avgAPs = Math.round(chartData.reduce((sum, s) => sum + (s.ap_count || 0), 0) / totalSamples);
        const avgClients = Math.round(chartData.reduce((sum, s) => sum + (s.client_count || 0), 0) / totalSamples);
        const maxAPs = Math.max(...chartData.map(s => s.ap_count || 0));
        const maxClients = Math.max(...chartData.map(s => s.client_count || 0));
        
        lines.push(`Data Points Collected,${totalSamples},samples,${totalSamples >= 100 ? 'Excellent' : totalSamples >= 50 ? 'Good' : 'Limited'}`);
        lines.push(`Average AP Density,${avgAPs},devices,${avgAPs >= 20 ? 'High' : avgAPs >= 10 ? 'Medium' : 'Low'}`);
        lines.push(`Average Client Density,${avgClients},devices,${avgClients >= 30 ? 'High' : avgClients >= 15 ? 'Medium' : 'Low'}`);
        lines.push(`Peak AP Count,${maxAPs},devices,Peak`);
        lines.push(`Peak Client Count,${maxClients},devices,Peak`);
        lines.push(`Average Network Load,${avgAPs + avgClients},devices,${avgAPs + avgClients >= 40 ? 'Heavy' : 'Moderate'}`);
        lines.push(`Peak Network Load,${maxAPs + maxClients},devices,Peak`);
    }

    addSection('Executive Summary', ['Category', 'Metric', 'Value', 'Assessment']);
    const openCount = sec.open || 0;
    const wepCount = sec.wep || 0;
    const insecureNetworks = openCount + wepCount;
    const totalNetworks = data.summary?.unique_aps || 1;
    const securityPosture = insecureNetworks === 0 ? 'Secure' : insecureNetworks <= 2 ? 'Moderate Risk' : 'High Risk';
    
    lines.push(`Security Posture,Insecure Networks,${insecureNetworks}/${totalNetworks},${securityPosture}`);
    lines.push(`Network Density,Total Networks,${data.summary?.unique_aps || 0},${(data.summary?.unique_aps || 0) >= 25 ? 'Dense' : 'Normal'}`);
    lines.push(`Device Activity,Total Clients,${data.summary?.unique_stations || 0},${(data.summary?.unique_stations || 0) >= 40 ? 'High Activity' : 'Normal'}`);
    lines.push(`Data Collection,Monitoring Samples,${chartData?.length || 0},${chartData?.length >= 100 ? 'Comprehensive' : 'Basic'}`);

    try {
        const csv = lines.join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `legacyhnl_report_${now.toISOString().slice(0,10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        showToast('Report downloaded successfully');
        console.log(`CSV report generated: ${lines.length} lines, ${csv.length} bytes`);
    } catch (err) {
        console.error('Failed to generate CSV download:', err);
        showToast('Failed to download report - ' + err.message);
    }
}
