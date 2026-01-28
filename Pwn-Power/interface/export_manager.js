/**
 * Export Manager
 * Handles data export and visual report generation
 */

window.ExportManager = {
    init: function () {
        console.log('ExportManager initialized');
        this.setupEventListeners();
    },

    setupEventListeners: function () {
        // Visual Report
        document.getElementById('btn-export-visual')?.addEventListener('click', () => this.generateAndDownloadVisualReport());

        // Raw Datasets
        document.getElementById('btn-export-scan')?.addEventListener('click', () => this.downloadJSON('scan_data.json', '/scan/report', 'btn-export-scan'));
        document.getElementById('btn-export-sys')?.addEventListener('click', () => this.downloadJSON('system_info.json', '/system/info', 'btn-export-sys'));
        document.getElementById('btn-export-intel')?.addEventListener('click', () => this.downloadJSON('intelligence.json', '/intelligence/unified', 'btn-export-intel'));
    },

    downloadJSON: async function (filename, endpoint, btnId) {
        const btn = document.getElementById(btnId);
        const originalText = btn ? btn.innerText : '';
        if (btn) btn.innerText = 'Downloading...';

        try {
            const res = await fetch(endpoint);
            if (!res.ok) throw new Error(`Status ${res.status}`);
            const data = await res.json();

            this.triggerDownload(
                filename,
                JSON.stringify(data, null, 2),
                'application/json'
            );

            showToast(`Downloaded ${filename}`);
        } catch (e) {
            console.error('Export failed:', e);
            showToast('Export failed: ' + e.message);
        } finally {
            if (btn) btn.innerText = originalText;
        }
    },

    drawReportLineChart: function (ctx, x, y, width, height, samples, key, color, label, unit) {
        const padding = 50;  // Increased for Y-axis labels
        const chartW = width - padding - 40;  // Leave space on right
        const chartH = height - padding - 30;  // Leave space for X-axis

        // Find max and round up to nice number
        const vals = samples.map(s => s[key] || 0);
        const rawMax = Math.max(...vals, 1);
        const max = this.niceMax(rawMax);

        // Draw Grid and Y-axis labels
        ctx.strokeStyle = 'rgba(255,255,255,0.05)';
        ctx.lineWidth = 1;
        ctx.fillStyle = '#666';
        ctx.font = '12px monospace';
        ctx.textAlign = 'right';

        for (let i = 0; i <= 4; i++) {
            const gy = y + padding + (chartH / 4) * i;
            // Grid line
            ctx.beginPath();
            ctx.moveTo(x + padding, gy);
            ctx.lineTo(x + padding + chartW, gy);
            ctx.stroke();
            // Y-axis label (value at this grid line)
            const value = Math.round(max * (4 - i) / 4);
            ctx.fillText(value.toString(), x + padding - 8, gy + 4);
        }

        // Draw Time Labels (X-Axis)
        ctx.fillStyle = '#666';
        ctx.font = '12px monospace';
        ctx.textAlign = 'center';

        if (samples.length > 1) {
            for (let i = 0; i <= 4; i++) {
                const idx = Math.floor(i * (samples.length - 1) / 4);
                const s = samples[idx];
                if (s && s.epoch_ts) {
                    const date = new Date(s.epoch_ts * 1000);
                    const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    const tx = x + padding + (idx / (samples.length - 1)) * chartW;
                    ctx.fillText(timeStr, tx, y + padding + chartH + 20);
                }
            }
        }
        ctx.textAlign = 'left';

        // Draw Line
        ctx.strokeStyle = color;
        ctx.lineWidth = 3;
        ctx.lineJoin = 'round';
        ctx.beginPath();
        samples.forEach((s, i) => {
            const px = x + padding + (i / (samples.length - 1)) * chartW;
            const val = s[key] || 0;
            const py = y + padding + chartH - (val / max) * chartH;
            if (i === 0) ctx.moveTo(px, py);
            else ctx.lineTo(px, py);
        });
        ctx.stroke();

        // Area under
        ctx.fillStyle = color + '22';
        ctx.lineTo(x + padding + chartW, y + padding + chartH);
        ctx.lineTo(x + padding, y + padding + chartH);
        ctx.closePath();
        ctx.fill();

        // Unit label at top
        ctx.fillStyle = '#888';
        ctx.font = '12px monospace';
        ctx.textAlign = 'left';
        ctx.fillText(unit, x + padding + 5, y + padding - 8);
    },

    // Helper to round up to a nice number for chart max
    niceMax: function (value) {
        if (value <= 0) return 1;
        if (value <= 5) return 5;
        if (value <= 10) return 10;
        const magnitude = Math.pow(10, Math.floor(Math.log10(value)));
        const normalized = value / magnitude;
        let nice;
        if (normalized <= 1) nice = 1;
        else if (normalized <= 2) nice = 2;
        else if (normalized <= 5) nice = 5;
        else nice = 10;
        return nice * magnitude;
    },

    drawReportChannelHistory: function (ctx, x, y, width, height, samples) {
        const padding = 50;  // Increased for Y-axis labels
        const chartW = width - padding - 40;
        const chartH = height - padding - 30;

        // Channel colors
        const colors = ['#ef4444', '#f97316', '#f59e0b', '#eab308', '#84cc16', '#22c55e', '#10b981', '#14b8a6', '#06b6d4', '#0ea5e9', '#3b82f6', '#6366f1', '#8b5cf6'];

        // Identify all active channels and find global max
        const activeChannels = new Set();
        let globalMax = 0;
        samples.forEach(s => {
            if (s.channel_counts) {
                if (s.channel_counts instanceof Map) {
                    for (const [ch, val] of s.channel_counts.entries()) {
                        activeChannels.add(parseInt(ch));
                        if (val > globalMax) globalMax = val;
                    }
                } else if (typeof s.channel_counts === 'object') {
                    for (const ch of Object.keys(s.channel_counts)) {
                        activeChannels.add(parseInt(ch));
                        if (s.channel_counts[ch] > globalMax) globalMax = s.channel_counts[ch];
                    }
                }
            }
        });

        // Round up max to nice number
        const max = this.niceMax(globalMax || 1);

        // Filter out 0 or invalid, sort numerically
        const sortedChannels = Array.from(activeChannels)
            .filter(c => c > 0 && c < 200)
            .sort((a, b) => a - b);

        const channelsToShow = sortedChannels.length > 0 ? sortedChannels : [1, 6, 11];

        // Draw Grid and Y-axis labels
        ctx.strokeStyle = 'rgba(255,255,255,0.05)';
        ctx.lineWidth = 1;
        ctx.fillStyle = '#666';
        ctx.font = '12px monospace';
        ctx.textAlign = 'right';

        for (let i = 0; i <= 4; i++) {
            const gy = y + padding + (chartH / 4) * i;
            // Grid line
            ctx.beginPath();
            ctx.moveTo(x + padding, gy);
            ctx.lineTo(x + padding + chartW, gy);
            ctx.stroke();
            // Y-axis label
            const value = Math.round(max * (4 - i) / 4);
            ctx.fillText(value.toString(), x + padding - 8, gy + 4);
        }

        // Draw Legend (Top of chart area)
        if (channelsToShow.length > 0) {
            ctx.textAlign = 'center';
            ctx.font = 'bold 10px monospace';
            const legendY = y + 10;
            const legendW = chartW;
            const itemW = Math.min(Math.max(legendW / channelsToShow.length, 15), 50);
            const totalLegendW = itemW * channelsToShow.length;
            const startX = x + padding + (chartW - totalLegendW) / 2 + itemW / 2;

            channelsToShow.forEach((ch, i) => {
                const cx = startX + i * itemW;
                const color = colors[ch % colors.length];
                ctx.fillStyle = color;
                ctx.fillRect(cx - 6, legendY, 12, 12);
                ctx.fillStyle = '#fff';
                ctx.fillText(ch, cx, legendY + 24);
            });
            ctx.textAlign = 'left';
        }

        // Draw Time Labels (X-Axis)
        ctx.fillStyle = '#666';
        ctx.font = '12px monospace';
        ctx.textAlign = 'center';

        if (samples.length > 1) {
            for (let i = 0; i <= 4; i++) {
                const idx = Math.floor(i * (samples.length - 1) / 4);
                const s = samples[idx];
                if (s && s.epoch_ts) {
                    const date = new Date(s.epoch_ts * 1000);
                    const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    const tx = x + padding + (idx / (samples.length - 1)) * chartW;
                    ctx.fillText(timeStr, tx, y + padding + chartH + 20);
                }
            }
        }
        ctx.textAlign = 'left';

        // Unit label
        ctx.fillStyle = '#888';
        ctx.font = '12px monospace';
        ctx.fillText('APs', x + padding + 5, y + padding - 8);

        // Draw lines for active channels
        channelsToShow.forEach(ch => {
            const color = colors[ch % colors.length];
            ctx.strokeStyle = color || '#fff';
            ctx.lineWidth = 2;
            ctx.beginPath();
            samples.forEach((s, i) => {
                const px = x + padding + (i / (samples.length - 1)) * chartW;
                const val = (s.channel_counts?.get ? s.channel_counts.get(ch) : s.channel_counts?.[ch]) || 0;
                const py = y + padding + chartH - (val / max) * chartH;
                if (i === 0) ctx.moveTo(px, py);
                else ctx.lineTo(px, py);
            });
            ctx.stroke();
        });
    },

    generateAndDownloadVisualReport: async function () {
        const btn = document.getElementById('btn-export-visual');
        const originalText = btn ? btn.innerText : 'Download Image';
        if (btn) btn.innerText = 'Generating...';
        showToast('Generating report...');

        try {
            // Fetch latest system info
            let sysInfo = { version: 'Unknown', uptime_sec: 0 };
            try {
                const res = await fetch('/system/info');
                if (res.ok) {
                    const data = await res.json();
                    sysInfo = data;
                }
            } catch (e) {
                console.warn('System info fetch failed for report');
            }

            // Use history samples from app.js if available, or fetch if empty
            // We want MAX history for report, so we might prefer fetching fresh if cache is small
            let samples = [];
            // Try fetching full history first
            console.log('Fetching full history samples for report...');
            showToast('Fetching historical data...');
            try {
                // Fetch 30 days to get everything
                const hRes = await fetch('/history/samples?days=30');
                if (hRes.ok) {
                    const hData = await hRes.json();
                    if (typeof parseCompactHistorySamples === 'function') {
                        const parsed = parseCompactHistorySamples(hData);
                        if (parsed && parsed.length > 0) {
                            // Update cache if needed, but primarily use for report
                            // Don't overwrite main cache if it might disturb main UI, actually it's fine to update it
                            if (window.historySamplesCache) {
                                window.historySamplesCache.samples = parsed;
                                window.historySamplesCache.lastTimestamp = parsed[parsed.length - 1].epoch_ts || 0;
                            }
                            samples = parsed; // Use ALL samples
                            console.log('Fetched and parsed full history samples:', samples.length);
                        }
                    }
                }
            } catch (e) {
                console.warn('History fetch failed for report, falling back to cache', e);
                if (historySamplesCache && historySamplesCache.samples && historySamplesCache.samples.length > 0) {
                    samples = historySamplesCache.samples; // Use all cached
                    console.log('Using cached history samples:', samples.length);
                }
            }

            // Force sort just in case
            samples.sort((a, b) => a.epoch_ts - b.epoch_ts);

            // Debug: log sample data quality
            if (samples.length > 0) {
                const first = samples[0];
                const last = samples[samples.length - 1];
                console.log('Report samples range:', {
                    count: samples.length,
                    firstTs: first.epoch_ts,
                    lastTs: last.epoch_ts,
                    firstAp: first.ap_count,
                    lastAp: last.ap_count,
                    hasChannelData: first.channel_counts && (first.channel_counts.size > 0 || Object.keys(first.channel_counts).length > 0)
                });
            } else {
                console.warn('No samples available for report charts');
            }

            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = 1600;
            canvas.height = 1200;

            // --- Background ---
            const grad = ctx.createLinearGradient(0, 0, 0, canvas.height);
            grad.addColorStop(0, '#0d1117');
            grad.addColorStop(1, '#161b22');
            ctx.fillStyle = grad;
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            // Subtle Grid
            ctx.strokeStyle = 'rgba(255,255,255,0.02)';
            ctx.lineWidth = 1;
            for (let i = 0; i < canvas.width; i += 80) {
                ctx.beginPath(); ctx.moveTo(i, 0); ctx.lineTo(i, canvas.height); ctx.stroke();
                ctx.beginPath(); ctx.moveTo(0, i); ctx.lineTo(canvas.width, i); ctx.stroke();
            }

            // --- Header ---
            ctx.fillStyle = '#b31717';
            ctx.fillRect(0, 0, canvas.width, 10);
            ctx.fillStyle = '#ff3e3e';
            ctx.font = 'bold 80px "Inter", sans-serif';
            ctx.fillText('PWNPOWER', 60, 110);
            ctx.fillStyle = '#ffffff';
            ctx.font = '28px "Inter", sans-serif';
            ctx.fillText('OFFENSIVE APPLIANCE RESEARCH REPORT', 60, 155);

            // Version/Time Metadata
            ctx.textAlign = 'right';
            ctx.fillStyle = '#888';
            ctx.font = '18px monospace';
            ctx.fillText(`REPORT ID   : ${Math.random().toString(36).substr(2, 9).toUpperCase()}`, 1540, 70);
            ctx.fillText(`FIRMWARE    : ${sysInfo.version}`, 1540, 100);
            ctx.fillText(`GENERATED   : ${new Date().toLocaleString().toUpperCase()}`, 1540, 130);
            ctx.textAlign = 'left';

            const margin = 60;
            const cardW = 710;
            const cardH = 450;
            const startY = 220;

            const drawCard = (x, y, title, subtitle) => {
                ctx.fillStyle = 'rgba(255,255,255,0.03)';
                if (ctx.roundRect) ctx.roundRect(x, y, cardW, cardH, 15); else ctx.fillRect(x, y, cardW, cardH);
                ctx.fill();
                ctx.strokeStyle = 'rgba(255,255,255,0.08)';
                ctx.stroke();

                // Titles swapped: Title is big, Subtitle is small (or empty)
                // User asked: "remove the titles and replace them with their subtitles like infrastructre trends should be Access points detected"
                // So the MAIN title should be what was the subtitle.

                ctx.fillStyle = '#fff';
                ctx.font = 'bold 32px "Inter", sans-serif';
                ctx.fillText(title, x + 30, y + 50);

                if (subtitle) {
                    ctx.fillStyle = '#666';
                    ctx.font = '18px "Inter", sans-serif';
                    ctx.fillText(subtitle, x + 30, y + 85);
                }
            };

            // Helper to draw "no data" message in chart area
            const drawNoData = (x, y, width, height) => {
                ctx.fillStyle = 'rgba(255,255,255,0.3)';
                ctx.font = '24px "Inter", sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('NO HISTORICAL DATA', x + width / 2, y + height / 2);
                ctx.font = '16px "Inter", sans-serif';
                ctx.fillStyle = 'rgba(255,255,255,0.2)';
                ctx.fillText('Data collection in progress...', x + width / 2, y + height / 2 + 35);
                ctx.textAlign = 'left';
            };

            // 1. AP Activity (Line)
            // Was: drawCard(..., 'INFRASTRUCTURE TRENDS', 'ACCESS POINTS DETECTED')
            // Now: drawCard(..., 'ACCESS POINTS DETECTED', '')
            drawCard(margin, startY, 'ACCESS POINTS DETECTED', '');
            if (samples.length > 1) {
                this.drawReportLineChart(ctx, margin, startY + 80, cardW, cardH - 80, samples, 'ap_count', '#ff3e3e', 'APs', 'APS');
            } else {
                drawNoData(margin, startY + 80, cardW, cardH - 80);
            }

            // 2. Client Activity (Line)
            // Was: drawCard(..., 'CLIENT POPULATION', 'DEVICES DISCOVERED')
            drawCard(margin + cardW + margin / 2, startY, 'DEVICES DISCOVERED', '');
            if (samples.length > 1) {
                this.drawReportLineChart(ctx, margin + cardW + margin / 2, startY + 80, cardW, cardH - 80, samples, 'client_count', '#3fb950', 'Clients', 'STA');
            } else {
                drawNoData(margin + cardW + margin / 2, startY + 80, cardW, cardH - 80);
            }

            // 3. Channel Distribution (History)
            // Was: drawCard(..., 'SPECTRUM ANALYSIS', 'CHANNEL CONGESTION HISTORY')
            drawCard(margin, startY + cardH + 40, 'CHANNEL CONGESTION HISTORY', '');
            if (samples.length > 1) {
                this.drawReportChannelHistory(ctx, margin, startY + cardH + 40 + 80, cardW, cardH - 80, samples);
            } else {
                drawNoData(margin, startY + cardH + 40 + 80, cardW, cardH - 80);
            }

            // 4. Summary Stats (Big Metrics)
            // Was: drawCard(..., 'SESSION ENUMERATION', 'AGGREGATED METRICS')
            drawCard(margin + cardW + margin / 2, startY + cardH + 40, 'AGGREGATED METRICS', '');

            // Calculate extra stats
            const maxAps = samples.length ? Math.max(...samples.map(s => s.ap_count || 0)) : 0;
            const maxClients = samples.length ? Math.max(...samples.map(s => s.client_count || 0)) : 0;

            const formatUptime = (sec) => {
                if (!sec) return '0h 0m';
                const h = Math.floor(sec / 3600);
                const m = Math.floor((sec % 3600) / 60);
                return `${h}h ${m}m`;
            };

            // Find busiest channel (simple sum of activity)
            let busiestCh = '-';
            if (samples.length) {
                const chActivity = {};
                samples.forEach(s => {
                    if (s.channel_counts) {
                        // Handle Map or Object
                        if (s.channel_counts.forEach) {
                            s.channel_counts.forEach((v, k) => { chActivity[k] = (chActivity[k] || 0) + v; });
                        } else {
                            for (const k in s.channel_counts) { chActivity[k] = (chActivity[k] || 0) + s.channel_counts[k]; }
                        }
                    }
                });
                let maxAct = -1;
                for (const ch in chActivity) {
                    if (chActivity[ch] > maxAct) {
                        maxAct = chActivity[ch];
                        busiestCh = ch;
                    }
                }
            }

            const stats = [
                { l: 'TOTAL TARGETS', v: document.getElementById('intel-aps')?.innerText || '0', c: '#ff3e3e' },
                { l: 'PEAK APs DETECTED', v: maxAps.toString(), c: '#ff3e3e' },

                { l: 'UNIQUE CLIENTS', v: document.getElementById('intel-clients')?.innerText || '0', c: '#3fb950' },
                { l: 'PEAK CLIENTS', v: maxClients.toString(), c: '#3fb950' },

                { l: 'DEAUTH ATTEMPTS', v: document.getElementById('intel-deauth')?.innerText || '0', c: '#f39c12' },
                { l: 'BUSIEST CHANNEL', v: busiestCh.toString(), c: '#f39c12' },

                { l: 'HANDSHAKES', v: (document.querySelectorAll('#handshake-list .handshake-item')?.length || '0').toString(), c: '#3b82f6' },
                { l: 'SYSTEM UPTIME', v: formatUptime(sysInfo.uptime_sec), c: '#3b82f6' }
            ];

            // 2-Column Layout
            const statsStartX = margin + cardW + margin / 2 + 40;
            const statsStartY = startY + cardH + 40 + 130;
            const colWidth = (cardW - 80) / 2;

            stats.forEach((s, i) => {
                const col = i % 2;
                const row = Math.floor(i / 2);

                const colX = statsStartX + (col * colWidth);
                const rowY = statsStartY + (row * 80); // 80px row height

                // Label
                ctx.fillStyle = '#888';
                ctx.font = '16px "Inter", sans-serif';
                // Align label to left of column
                ctx.textAlign = 'left';
                ctx.fillText(s.l, colX, rowY);

                // Value
                ctx.fillStyle = s.c;
                ctx.font = 'bold 32px monospace';
                ctx.fillText(s.v, colX, rowY + 35);
            });

            // Reset align
            ctx.textAlign = 'left';



            // Export
            canvas.toBlob(blob => {
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `pwnpower_research_report_${new Date().toISOString().split('T')[0]}.png`;
                a.click();
                URL.revokeObjectURL(url);
                showToast('Report exported');
            }, 'image/png');

        } catch (e) {
            console.error('Report generation failed:', e);
            showToast('Generation failed');
        } finally {
            if (btn) btn.innerText = originalText;
        }
    },

    triggerDownload: function (filename, content, type) {
        const blob = new Blob([content], { type: type });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
};
