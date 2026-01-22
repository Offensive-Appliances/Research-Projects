// Chart state management
let chartData = null;
let chartObservers = new Map();
let chartCache = new Map();
let legendMeasurementCache = new Map();
let canvasHandlers = new WeakMap();
let trackedIntervals = [];
const MAX_CACHE_SIZE = 3;

const HISTORY_READY_THRESHOLD = 10;
const IDEAL_TREND_SAMPLE_COUNT = 30;
const HISTORY_OVERLAY_TEXT = 'Collecting data... check back soon.';

const chartLogState = new Map();
const sampleLogState = new Map();

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

// Utility functions
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

// Logging functions
function logChartTimeRange(canvasId, timeRange, sampleCount) {
    if (!timeRange) return;
    const key = `${timeRange.startTime}-${timeRange.endTime}-${sampleCount}`;
    if (chartLogState.get(canvasId) === key) return;
    chartLogState.set(canvasId, key);

    const spanHours = Math.round(((timeRange.endTime - timeRange.startTime) / (1000 * 60 * 60)) * 10) / 10;
    console.debug(
        `[charts] ${canvasId} range: ${new Date(timeRange.startTime).toISOString()} -> ${new Date(timeRange.endTime).toISOString()} (${spanHours}h, ${sampleCount} samples)`
    );
}

function logSampleExtremes(label, samples) {
    if (!samples || samples.length === 0) return;
    const timestamps = samples
        .map(s => (Number.isFinite(s?.epoch_ts) ? s.epoch_ts * 1000 : null))
        .filter(ts => ts !== null);
    if (timestamps.length === 0) return;

    const minTs = Math.min(...timestamps);
    const maxTs = Math.max(...timestamps);
    const spanHours = Math.round(((maxTs - minTs) / (1000 * 60 * 60)) * 10) / 10;
    // Sort timestamps chronologically for logging first/last
    const sortedTimestamps = [...timestamps].sort((a, b) => a - b);
    const firstFew = sortedTimestamps.slice(0, 3).map(ts => new Date(ts).toISOString());
    const lastFew = sortedTimestamps.slice(-3).map(ts => new Date(ts).toISOString());
    const key = `${minTs}-${maxTs}-${samples.length}`;
    if (sampleLogState.get(label) === key) return;
    sampleLogState.set(label, key);

    console.debug(
        `[charts] ${label} samples=${samples.length} min=${new Date(minTs).toISOString()} max=${new Date(maxTs).toISOString()} span=${spanHours}h first=${firstFew.join(', ')} last=${lastFew.join(', ')}`
    );
}

// Check if a sample has a valid real-world timestamp (not just uptime)
function hasValidTimestamp(sample) {
    return sample && sample.time_valid && sample.epoch_ts > 0;
}

function formatHistoryLabel(sample) {
    if (!sample) return '--';
    if (!hasValidTimestamp(sample)) {
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

// Chart drawing functions
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
        // Filter out invalid timestamps (0 or non-finite) that would break the timeline
        const sortedData = [...series.data]
            .filter(d => Number.isFinite(d.timestamp) && d.timestamp > 0)
            .sort((a, b) => a.timestamp - b.timestamp);

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

function hashSsid(ssid) {
    let hash = 5381;
    for (let i = 0; i < ssid.length; i++) {
        hash = ((hash << 5) + hash) + ssid.charCodeAt(i);
    }
    return hash >>> 0;
}

async function drawSSIDClientsChart(canvasId, samples) {
    if (!samples || samples.length === 0) {
        console.log('[ssid-chart] no samples');
        return;
    }

    // Aggregate ssid_clients from history samples first
    const ssidAggregates = new Map();
    let samplesWithClients = 0;
    samples.forEach(sample => {
        if (sample.ssid_clients && sample.ssid_clients.length > 0) {
            samplesWithClients++;
            sample.ssid_clients.forEach(entry => {
                const current = ssidAggregates.get(entry.hash) || { hash: entry.hash, total: 0, count: 0, max: 0 };
                current.total += entry.count;
                current.count++;
                current.max = Math.max(current.max, entry.count);
                ssidAggregates.set(entry.hash, current);
            });
        }
    });

    console.log(`[ssid-chart] ${samples.length} samples, ${samplesWithClients} with ssid_clients, ${ssidAggregates.size} unique SSIDs`);

    if (ssidAggregates.size === 0) return;

    // Try to get SSID names from scan report (may fail during bg scan)
    const hashToSsid = new Map();
    try {
        const data = await getScanReport();
        if (data && data.networks) {
            data.networks.forEach(net => {
                const hash = hashSsid(net.ssid || '');
                hashToSsid.set(hash, net.ssid || '(Hidden)');
            });
        }
    } catch (e) {
        console.warn('[charts] getScanReport failed, using hash fallback:', e.message);
    }

    const networks = Array.from(ssidAggregates.values())
        .map(agg => ({
            ssid: hashToSsid.get(agg.hash) || `Net-${(agg.hash & 0xFFFF).toString(16).toUpperCase()}`,
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

function renderCharts(samples, timeRange = null) {
    const needsMoreData = !samples || samples.length < HISTORY_READY_THRESHOLD;

    // Show/hide overlays based on data availability
    updateGraphOverlayState('activity', needsMoreData);
    updateGraphOverlayState('channel', needsMoreData);
    updateGraphOverlayState('ssid-clients', needsMoreData);

    if (!samples || samples.length === 0) return;

    // Filter samples to only those with valid timestamps (exclude uptime-only samples)
    // This prevents epoch_ts=0 samples from breaking the timeline (would appear in 1970)
    const validSamples = samples.filter(hasValidTimestamp);

    // Check if we have enough valid samples to render
    if (validSamples.length === 0) {
        console.warn('[charts] No samples with valid timestamps - charts cannot render. Waiting for time sync.');
        updateGraphOverlayState('activity', true);
        updateGraphOverlayState('channel', true);
        updateGraphOverlayState('ssid-clients', true);
        return;
    }

    // If no time range provided, calculate from valid samples only
    if (!timeRange) {
        const timestamps = validSamples.map(s => s.epoch_ts * 1000);
        const endTime = Math.max(...timestamps);
        const startTime = Math.min(...timestamps);
        timeRange = { startTime, endTime, days: (endTime - startTime) / (24 * 60 * 60 * 1000) };
    }
    logChartTimeRange('computed-render-range', timeRange, validSamples.length);

    // activity chart - show APs and clients as separate lines with smoothing
    // Ensure samples are sorted chronologically to avoid line jumps
    const sortedSamples = [...validSamples].sort((a, b) => a.epoch_ts - b.epoch_ts);

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
    logChartTimeRange('#activity-chart', timeRange, sortedSamples.length);

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
    logChartTimeRange('#channel-chart-time', timeRange, sortedSamples.length);

    // SSID clients bar chart (async - will hide overlay when done)
    drawSSIDClientsChart('#ssid-clients-chart', sortedSamples).then(() => {
        updateGraphOverlayState('ssid-clients', false);
    });
}

async function loadHistoryCharts(days) {
    // For 'from-start', fetch all available data (use large days value)
    const fetchDays = days === 'from-start' ? 365 : days;
    const data = await fetchJSON(`/history/samples?days=${fetchDays}`);
    
    // Parse compact format: {"s":[[epoch,ap,cli,[channels],[[hash,cnt],...]],...]}
    // parseCompactHistorySamples is defined in app.js and converts to object format
    const samples = (typeof parseCompactHistorySamples === 'function') 
        ? parseCompactHistorySamples(data)
        : (data && data.samples ? data.samples : []);
    
    if (!samples || samples.length === 0) {
        showToast('No history data available yet');
        return;
    }

    // Filter to valid timestamp samples for time range calculation and display
    const validSamples = samples.filter(hasValidTimestamp);

    if (validSamples.length === 0) {
        showToast('Waiting for time sync - samples available but no valid timestamps yet');
        const desc = document.querySelector('.history-description');
        if (desc) {
            desc.textContent = `Network activity charts (${samples.length} samples awaiting time sync)`;
        }
        renderCharts(samples, null);  // Will show overlay
        return;
    }

    const desc = document.querySelector('.history-description');
    if (desc) {
        if (days === 'from-start') {
            const oldestTime = new Date(validSamples[0].epoch_ts * 1000).toLocaleDateString();
            desc.textContent = `Network activity charts (from ${oldestTime})`;
        } else {
            desc.textContent = days === 1
                ? 'Network activity charts (last 24 hours)'
                : days < 1
                ? `Network activity charts (last ${Math.round(days * 24)} hours)`
                : `Network activity charts (last ${days} days)`;
        }
    }

    // Use all samples (renderCharts will filter) but calculate time range from valid ones only
    chartData = samples;

    // Calculate time range from valid samples only (prevents 1970 epoch_ts=0 from breaking timeline)
    const timestamps = validSamples.map(s => s.epoch_ts * 1000);
    const endTime = Math.max(...timestamps);
    const startTime = Math.min(...timestamps);
    const actualDays = (endTime - startTime) / (24 * 60 * 60 * 1000);
    const timeRange = { startTime, endTime, days: actualDays };
    const hours = Math.round(actualDays * 24 * 10) / 10;

    const invalidCount = samples.length - validSamples.length;
    const toastMsg = invalidCount > 0
        ? `Loaded ${validSamples.length} samples (${hours}h range, ${invalidCount} pending time sync)`
        : `Loaded ${validSamples.length} samples (${hours}h range)`;
    showToast(toastMsg);

    logChartTimeRange('load-history', timeRange, validSamples.length);
    logSampleExtremes('history-load', validSamples);

    renderCharts(samples, timeRange);
}
