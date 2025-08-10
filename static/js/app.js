// Extracted from inline script in index.html
let ws = null;
let isRunning = false;
let packetCount = 0;
let PROTOCOLS = [];
let LOCAL_IPS = [];
// Simple grouping
let smartGroups = {
    tcp_sessions: new Map(),
    udp_flows: new Map(),
    other_protocols: new Map()
};
let groupMetadata = new Map(); // group metadata
let estimatedMemoryUsage = 0; // estimated memory usage (MB)
let batchUpdateTimer = null; // batch update timer
let pendingUpdates = false; // pending update flag
let packetQueue = []; // packet processing queue
let isProcessingQueue = false; // queue processing flag
let cachedElements = new Map(); // DOM element cache
let shouldSort = false; // whether sorting is needed

// Enhanced Tab System
const topTab = document.getElementById('topTab');
const vizTab = document.getElementById('vizTab');
const topView = document.getElementById('topView');
const vizView = document.getElementById('vizView');
const topTabBadge = document.getElementById('topTabBadge');
const vizTabBadge = document.getElementById('vizTabBadge');
const tabContextMenu = document.getElementById('tabContextMenu');
const topViewSearch = document.getElementById('topViewSearch');
const vizViewSearch = document.getElementById('vizViewSearch');

let currentTab = 'top';
let searchFilters = { top: '', viz: '' };
let tabData = { top: { packets: 0, lastUpdate: 0 }, viz: { packets: 0, lastUpdate: 0 } };

// Chart.js contexts and charts
const timeCtx = document.getElementById('timeChart').getContext('2d');
const timeChart = new Chart(timeCtx, {
    type: 'line',
    data: { labels: [], datasets: [{ label: 'Bytes per second', data: [], borderColor: '#4299e1', backgroundColor: 'rgba(66,153,225,0.3)', fill: true, tension: 0.1 }] },
    options: { animation: false, scales: { x: { display: true }, y: { beginAtZero: true } } }
});

const trafficSeries = new Map();
let totalTraffic = 0;

const totalCtx = document.getElementById('totalTrafficChart').getContext('2d');
const totalChart = new Chart(totalCtx, {
    type: 'line',
    data: { labels: [], datasets: [{ label: 'Total Bytes', data: [], borderColor: '#68d391', backgroundColor: 'rgba(104,211,145,0.3)', fill: true, tension: 0.1 }] },
    options: { animation: false, scales: { x: { display: true }, y: { beginAtZero: true } } }
});

const protocolCounts = new Map();
const protocolCtx = document.getElementById('protocolChart').getContext('2d');
const protocolChart = new Chart(protocolCtx, {
    type: 'doughnut',
    data: { labels: [], datasets: [{ label: 'Protocols', data: [], backgroundColor: ['#4299e1', '#68d391', '#ed8936', '#e53e3e', '#9f7aea', '#ed64a6', '#f6ad55', '#38a169', '#718096'] }] },
    options: { animation: false }
});

// Top Sources Chart
const topSourcesData = new Map();
const topSourcesCtx = document.getElementById('topSourcesChart').getContext('2d');
const topSourcesChart = new Chart(topSourcesCtx, {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Packets Sent', data: [], backgroundColor: '#4299e1', borderColor: '#3182ce', borderWidth: 1 }] },
    options: { animation: false, responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } } }
});

// Top Destinations Chart
const topDestinationsData = new Map();
const topDestinationsCtx = document.getElementById('topDestinationsChart').getContext('2d');
const topDestinationsChart = new Chart(topDestinationsCtx, {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Packets Received', data: [], backgroundColor: '#68d391', borderColor: '#38a169', borderWidth: 1 }] },
    options: { animation: false, responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } } }
});

// Packet Size Distribution Chart
const packetSizeData = new Map();
const packetSizeCtx = document.getElementById('packetSizeChart').getContext('2d');
const packetSizeChart = new Chart(packetSizeCtx, {
    type: 'bar',
    data: { labels: ['0-64', '65-128', '129-256', '257-512', '513-1024', '1025-1500', '1501+'], datasets: [{ label: 'Packet Count', data: [0,0,0,0,0,0,0], backgroundColor: '#ed8936', borderColor: '#dd6b20', borderWidth: 1 }] },
    options: { animation: false, responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } } }
});

// Connection States Chart
const connectionStatesData = new Map();
const connectionStatesCtx = document.getElementById('connectionStatesChart').getContext('2d');
const connectionStatesChart = new Chart(connectionStatesCtx, {
    type: 'pie',
    data: { labels: ['TCP Sessions', 'UDP Flows', 'Other Protocols'], datasets: [{ label: 'Connection Types', data: [0,0,0], backgroundColor: ['#9f7aea', '#ed64a6', '#f6ad55'] }] },
    options: { animation: false, responsive: true, maintainAspectRatio: false }
});

// D3 chord diagram data
const chordSvg = d3.select('#chordDiagram');
const hostIndex = new Map();
let hosts = [];
let matrix = [];

const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const clearBtn = document.getElementById('clearBtn');
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const totalPacketsEl = document.getElementById('totalPackets');
const connectionStatusEl = document.getElementById('connectionStatus');
const flowList = document.getElementById('flowList');
const memoryStatusEl = document.getElementById('memoryStatus');
const applyFilterBtn = document.getElementById('applyFilterBtn');
const groupLanWanCheckbox = document.getElementById('groupLanWan');

function switchTab(targetTab) {
    const tabs = [topTab, vizTab];
    const views = [topView, vizView];
    const tabNames = ['top', 'viz'];
    currentTab = targetTab;
    tabs.forEach((tab, index) => {
        const isActive = tabNames[index] === targetTab;
        tab.classList.toggle('active', isActive);
        tab.setAttribute('aria-selected', isActive);
        tab.setAttribute('tabindex', isActive ? '0' : '-1');
        const view = views[index];
        if (isActive) {
            view.style.display = 'block';
            requestAnimationFrame(() => { view.classList.add('active'); });
        } else {
            view.classList.remove('active');
            setTimeout(() => { if (!view.classList.contains('active')) { view.style.display = 'none'; } }, 300);
        }
    });
    localStorage.setItem('activeTab', targetTab);
    updateSearchVisibility();
}

topTab.addEventListener('click', () => switchTab('top'));
vizTab.addEventListener('click', () => switchTab('viz'));
document.addEventListener('keydown', (e) => {
    if (e.altKey && (e.key === '1' || e.key === '2')) { e.preventDefault(); switchTab(e.key === '1' ? 'top' : 'viz'); }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') { e.preventDefault(); (currentTab === 'top' ? topViewSearch : vizViewSearch).focus(); }
});

function updateSearchVisibility() {
    const query = searchFilters[currentTab];
    if (currentTab === 'top') {
        if (query) console.log(`Filter top view by: ${query}`);
    } else {
        if (query) {
            const filteredHosts = hosts.filter(host => host.toLowerCase().includes(query));
            console.log(`Filtered to ${filteredHosts.length} hosts`);
        }
    }
}

function setupSearchFilters() {
    topViewSearch.addEventListener('input', (e) => { searchFilters.top = e.target.value.toLowerCase(); updateSearchVisibility(); });
    vizViewSearch.addEventListener('input', (e) => { searchFilters.viz = e.target.value.toLowerCase(); updateSearchVisibility(); });
}

function estimatePacketMemoryUsage(packet) {
    const baseSize = 0.001; // ~1KB
    const infoSize = packet.info.length * 0.000001;
    return baseSize + infoSize;
}

function updateMemoryDisplay() {
    memoryStatusEl.textContent = `Memory: ${estimatedMemoryUsage.toFixed(1)}MB`;
    const memoryLimit = parseInt(document.getElementById('memoryLimit').value) || 50;
    if (estimatedMemoryUsage > memoryLimit * 0.8) { memoryStatusEl.style.color = '#e53e3e'; }
    else if (estimatedMemoryUsage > memoryLimit * 0.6) { memoryStatusEl.style.color = '#ed8936'; }
    else { memoryStatusEl.style.color = '#718096'; }
}

function removeFlow(metadataKey) {
    const metadata = groupMetadata.get(metadataKey);
    if (!metadata) return;
    const { type, key } = metadata;
    const flowElement = smartGroups[type].get(key);
    if (flowElement && flowElement.parentNode) {
        estimatedMemoryUsage -= metadata.packetCount * 0.001;
        smartGroups[type].delete(key);
        flowList.removeChild(flowElement);
        groupMetadata.delete(metadataKey);
        rebuildHostMatrix();
        updateTabBadges();
    }
}

function cleanupOldFlows() {
    const flows = Array.from(groupMetadata.entries()).sort(([,a], [,b]) => a.lastSeen - b.lastSeen);
    const memoryLimit = parseInt(getCachedElement('memoryLimit').value) || 50;
    while (estimatedMemoryUsage > memoryLimit * 0.7 && flows.length > 0) {
        const [oldestKey] = flows.shift();
        removeFlow(oldestKey);
    }
}

function rebuildHostMatrix() {
    hostIndex.clear(); hosts = []; matrix = [];
    const maxSessions = parseInt(getCachedElement('maxSessions').value) || 20;
    const hostBytes = new Map();
    groupMetadata.forEach(meta => {
        const bytes = (meta.sentBytes || 0) + (meta.recvBytes || 0);
        hostBytes.set(meta.endpointA, (hostBytes.get(meta.endpointA) || 0) + bytes);
        hostBytes.set(meta.endpointB, (hostBytes.get(meta.endpointB) || 0) + bytes);
    });
    const sortedHosts = Array.from(hostBytes.entries()).sort(([,a], [,b]) => b - a).slice(0, maxSessions).map(([h]) => h);
    sortedHosts.forEach((h, idx) => { hostIndex.set(h, idx); hosts.push(h); });
    matrix = Array.from({length: hosts.length}, () => new Array(hosts.length).fill(0));
    groupMetadata.forEach(meta => {
        const i = hostIndex.get(meta.endpointA); const j = hostIndex.get(meta.endpointB);
        if (i === undefined || j === undefined) return;
        const bytes = (meta.sentBytes || 0) + (meta.recvBytes || 0);
        matrix[i][j] += bytes; matrix[j][i] += bytes;
    });
}

async function applyTsharkFilter() {
    const filterValue = document.getElementById('tsharkFilter').value.trim();
    try {
        const response = await fetch('/api/filter', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tshark_filter: filterValue || null }) });
        if (response.ok) {
            console.log('Filter applied:', filterValue);
            flowList.innerHTML = '';
            Object.keys(smartGroups).forEach(groupType => { smartGroups[groupType].clear(); });
            groupMetadata.clear();
            packetQueue.length = 0;
            estimatedMemoryUsage = 0;
            rebuildHostMatrix();
            updateMemoryDisplay();
        } else {
            console.error('Failed to apply filter');
        }
    } catch (error) { console.error('Filter error:', error); }
}

function addPacketToLog(packet) {
    const hideLocalhost = document.getElementById('hideLocalhost').checked;
    if (hideLocalhost && isLocalhostTraffic(packet)) return;
    const packetDiv = document.createElement('div');
    packetDiv.className = 'packet-item';
    const timestamp = new Date(packet.timestamp * 1000).toLocaleTimeString();
    const protoLabel = packet.sub_proto ? `${packet.protocol} (${packet.sub_proto})` : packet.protocol;
    packetDiv.innerHTML = `
        <div class="packet-info">
            <div class="packet-main">${getDisplayLabel(packet.src_ip)} → ${getDisplayLabel(packet.dst_ip)}</div>
            <div class="packet-detail">${timestamp} | ${packet.length} bytes | ${packet.info}</div>
        </div>
        <div class="packet-protocol">${protoLabel}</div>
    `;
    packetList.insertBefore(packetDiv, packetList.firstChild);
    while (packetList.children.length > 100) { packetList.removeChild(packetList.lastChild); }
}

async function updateStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        updateProtocolStats(stats.protocols);
        updateTopStats('sourceStats', stats.top_sources);
        updateTopStats('destStats', stats.top_destinations);
    } catch (error) { console.error('Failed to fetch statistics:', error); }
}

function updateProtocolStats(protocols) {
    const container = getCachedElement('protocolStats');
    if (!container) { console.error('protocolStats element not found'); return; }
    container.innerHTML = '';
    const sorted = Object.entries(protocols).sort(([,a], [,b]) => b - a).slice(0, 5);
    if (sorted.length === 0) { container.innerHTML = '<div class="stat-item"><span>No data</span><span>-</span></div>'; return; }
    sorted.forEach(([protocol, count]) => {
        const item = document.createElement('div'); item.className = 'stat-item';
        item.innerHTML = `<span>${protocol.toUpperCase()}</span><span>${count}</span>`; container.appendChild(item);
    });
}

function updateTopStats(containerId, data) {
    const container = getCachedElement(containerId);
    if (!container) { console.error(`${containerId} element not found`); return; }
    container.innerHTML = '';
    const sorted = Object.entries(data).sort(([,a], [,b]) => b - a).slice(0, 5);
    if (sorted.length === 0) { container.innerHTML = '<div class="stat-item"><span>No data</span><span>-</span></div>'; return; }
    sorted.forEach(([ip, count]) => {
        const item = document.createElement('div'); item.className = 'stat-item';
        item.innerHTML = `<span>${ip}</span><span>${count}</span>`; container.appendChild(item);
    });
}

function updateVisualization(packet) {
    const sec = Math.floor(packet.timestamp);
    trafficSeries.set(sec, (trafficSeries.get(sec) || 0) + packet.length);
    totalTraffic += packet.length;
    protocolCounts.set(packet.protocol, (protocolCounts.get(packet.protocol) || 0) + 1);
    updateChordTraffic(packet.src_ip, packet.dst_ip, packet.length);
    updateTopSourcesData(packet);
    updateTopDestinationsData(packet);
    updatePacketSizeData(packet);
    updateConnectionStatesData(packet);
}

function updateTopSourcesData(packet) {
    const currentCount = topSourcesData.get(packet.src_ip) || 0;
    topSourcesData.set(packet.src_ip, currentCount + 1);
}
function updateTopDestinationsData(packet) {
    const currentCount = topDestinationsData.get(packet.dst_ip) || 0;
    topDestinationsData.set(packet.dst_ip, currentCount + 1);
}
function updatePacketSizeData(packet) {
    const size = packet.length;
    let category;
    if (size <= 64) category = 0; else if (size <= 128) category = 1; else if (size <= 256) category = 2; else if (size <= 512) category = 3; else if (size <= 1024) category = 4; else if (size <= 1500) category = 5; else category = 6;
    packetSizeChart.data.datasets[0].data[category] += 1;
}
function updateConnectionStatesData(packet) {
    const protocol = packet.protocol.toUpperCase();
    if (protocol === 'TCP') connectionStatesChart.data.datasets[0].data[0] += 1;
    else if (protocol === 'UDP') connectionStatesChart.data.datasets[0].data[1] += 1;
    else connectionStatesChart.data.datasets[0].data[2] += 1;
}

function refreshTimeChart() {
    const now = Math.floor(Date.now() / 1000);
    const labels = [];
    const data = [];
    for (let i = 29; i >= 0; i--) {
        const t = now - i; labels.push(new Date(t * 1000).toLocaleTimeString()); data.push(trafficSeries.get(t) || 0);
    }
    timeChart.data.labels = labels; timeChart.data.datasets[0].data = data; timeChart.update('none');
    trafficSeries.forEach((_, key) => { if (key < now - 60) trafficSeries.delete(key); });
}
function refreshTotalTrafficChart() {
    const now = Math.floor(Date.now() / 1000);
    const labels = []; const data = []; let acc = 0;
    for (let i = 29; i >= 0; i--) { const t = now - i; acc += trafficSeries.get(t) || 0; labels.push(new Date(t * 1000).toLocaleTimeString()); data.push(acc); }
    totalChart.data.labels = labels; totalChart.data.datasets[0].data = data; totalChart.update('none');
}
function refreshProtocolChart() {
    const entries = Array.from(protocolCounts.entries());
    const labels = entries.map(([k]) => k); const data = entries.map(([,v]) => v);
    protocolChart.data.labels = labels; protocolChart.data.datasets[0].data = data; protocolChart.update('none');
}
function refreshTopSourcesChart() {
    const sorted = Array.from(topSourcesData.entries()).sort((a,b) => b[1] - a[1]).slice(0, 10);
    const labels = sorted.map(([k]) => k); const data = sorted.map(([,v]) => v);
    topSourcesChart.data.labels = labels; topSourcesChart.data.datasets[0].data = data; topSourcesChart.update('none');
}
function refreshTopDestinationsChart() {
    const sorted = Array.from(topDestinationsData.entries()).sort((a,b) => b[1] - a[1]).slice(0, 10);
    const labels = sorted.map(([k]) => k); const data = sorted.map(([,v]) => v);
    topDestinationsChart.data.labels = labels; topDestinationsChart.data.datasets[0].data = data; topDestinationsChart.update('none');
}
function refreshPacketSizeChart() { packetSizeChart.update('none'); }
function refreshConnectionStatesChart() { connectionStatesChart.update('none'); }

setInterval(() => {
    refreshTimeChart(); refreshTotalTrafficChart(); drawChordDiagram(); refreshProtocolChart(); refreshTopSourcesChart(); refreshTopDestinationsChart(); refreshPacketSizeChart(); refreshConnectionStatesChart();
}, 1000);

startBtn.addEventListener('click', function() { if (!isRunning) { connectWebSocket(); } });
stopBtn.addEventListener('click', function() { if (ws && isRunning) { ws.close(); } });
clearBtn.addEventListener('click', function() {
    flowList.innerHTML = '';
    Object.keys(smartGroups).forEach(groupType => { smartGroups[groupType].clear(); });
    groupMetadata.clear(); packetQueue.length = 0; packetCount = 0; estimatedMemoryUsage = 0; totalPacketsEl.textContent = '0'; protocolCounts.clear();
    topSourcesData.clear(); topDestinationsData.clear(); packetSizeChart.data.datasets[0].data = [0,0,0,0,0,0,0]; connectionStatesChart.data.datasets[0].data = [0,0,0];
    rebuildHostMatrix(); updateMemoryDisplay(); updateTabBadges();
});

getCachedElement('sortSessions').addEventListener('change', function() { sortFlows(); });
groupLanWanCheckbox.addEventListener('change', function() { clearBtn.click(); });
applyFilterBtn.addEventListener('click', applyTsharkFilter);
document.getElementById('tsharkFilter').addEventListener('keypress', function(e) { if (e.key === 'Enter') { applyTsharkFilter(); } });
setInterval(updateStats, 5000);
setInterval(updateMemoryDisplay, 2000);
updateStats();
setupSearchFilters();
restoreTabState();
updateTabBadges();

// initial connection deferred until window load so ws.js is ready
window.addEventListener('load', () => { try { connectWebSocket(); } catch (e) { console.error(e); } });

function isLocalhostTraffic(packet) {
    const localhostAddresses = ['127.0.0.1', '::1', 'localhost'];
    return localhostAddresses.includes(packet.src_ip) || localhostAddresses.includes(packet.dst_ip) || (packet.src_ip === packet.dst_ip && (packet.src_ip.startsWith('127.') || packet.src_ip.startsWith('::1')));
}

function classifyPacket(packet) {
    const protocol = packet.protocol.toUpperCase();
    const info = createSessionInfo(packet);
    let type = 'other_protocols'; if (protocol === 'TCP') type = 'tcp_sessions'; else if (protocol === 'UDP') type = 'udp_flows';
    return { type, key: info.key, direction: info.direction, a: info.a, b: info.b };
}
function isLan(ip) { return LOCAL_IPS.includes(ip) || ip.startsWith('10.') || ip.startsWith('192.168.') || (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)); }
function getDisplayLabel(ip) { return isLan(ip) ? `LAN_${ip}` : `WAN_${ip}`; }
function getDisplayKey(packet) {
    const portMatch = packet.info.match(/(\d+)\s*→\s*(\d+)/);
    let src = getDisplayLabel(packet.src_ip); let dst = getDisplayLabel(packet.dst_ip);
    if (portMatch) { src = `${src}:${portMatch[1]}`; dst = `${dst}:${portMatch[2]}`; }
    return `${src} ⇄ ${dst}`;
}
function createSessionInfo(packet) {
    const portMatch = packet.info.match(/(\d+)\s*→\s*(\d+)/);
    let src = packet.src_ip; let dst = packet.dst_ip;
    if (groupLanWanCheckbox && groupLanWanCheckbox.checked) { src = isLan(packet.src_ip) ? 'LAN' : 'WAN'; dst = isLan(packet.dst_ip) ? 'LAN' : 'WAN'; }
    if (portMatch) { src = `${src}:${portMatch[1]}`; dst = `${dst}:${portMatch[2]}`; }
    let a = src; let b = dst; let direction = 'a_to_b';
    if (a < b) { direction = 'a_to_b'; } else if (a > b) { direction = 'b_to_a'; const tmp = a; a = b; b = tmp; } else { direction = 'a_to_b'; }
    return { key: `${a} ⇄ ${b}`, direction, a, b };
}
function createFlowElement(groupType, groupKey, firstPacket) {
    const flowDiv = document.createElement('div'); flowDiv.className = 'tcp-session';
    flowDiv.id = `flow-${groupType}-${groupKey.replace(/[^a-zA-Z0-9]/g, '-')}`;
    const { icon, title, subtitle } = getFlowDisplayInfo(groupType, groupKey, firstPacket);
    const timestamp = new Date(firstPacket.timestamp * 1000).toLocaleTimeString();
    flowDiv.innerHTML = `
        <div class=\"session-header\" onclick=\"toggleFlowUltraFast('${flowDiv.id}')\">
            <div class=\"session-info\">
                <div class=\"session-title\">${icon} ${title}</div>
                <div class=\"session-subtitle\">
                    <span class=\"session-stats\">
                        <span>Started: ${timestamp}</span>
                        <span>Packets: <span id=\"${flowDiv.id}-count\">1</span></span>
                        <span>Sent: <span id=\"${flowDiv.id}-sent\">0B</span></span>
                        <span>Received: <span id=\"${flowDiv.id}-recv\">0B</span></span>
                        <span>${subtitle}</span>
                    </span>
                </div>
            </div>
            <div class=\"session-toggle collapsed\" id=\"${flowDiv.id}-toggle\">▶</div>
        </div>
        <div class=\"session-packets collapsed\" id=\"${flowDiv.id}-packets\">
            <div class=\"loading-skeleton\" style=\"display: none;\"> <div class=\"skeleton-line\"></div> <div class=\"skeleton-line\"></div> <div class=\"skeleton-line\"></div> </div>
        </div>`;
    return flowDiv;
}
function getFlowDisplayInfo(groupType, groupKey, packet) {
    const title = (groupLanWanCheckbox && groupLanWanCheckbox.checked) ? getDisplayKey(packet) : groupKey;
    switch (groupType) {
        case 'tcp_sessions': {
            const tcpSubtitle = packet.sub_proto ? `${packet.sub_proto} over TCP` : 'TCP Session';
            return { icon: '🔐', title, subtitle: tcpSubtitle };
        }
        case 'udp_flows': {
            const udpSubtitle = packet.sub_proto ? `${packet.sub_proto} over UDP` : 'UDP Flow';
            return { icon: '📦', title, subtitle: udpSubtitle };
        }
        default: return { icon: '❓', title, subtitle: `${packet.protocol}Protocol` };
    }
}

function processPacketQueue() {
    if (packetQueue.length === 0) { isProcessingQueue = false; return; }
    isProcessingQueue = true;
    const startTime = performance.now(); const maxProcessingTime = 8;
    while (packetQueue.length > 0 && (performance.now() - startTime) < maxProcessingTime) {
        const packet = packetQueue.shift(); processPacket(packet);
    }
    if (packetQueue.length > 0) { requestAnimationFrame(processPacketQueue); }
    else { isProcessingQueue = false; if (shouldSort) { shouldSort = false; sortFlows(); } }
}
function processPacket(packet) {
    const hideLocalhost = getCachedElement('hideLocalhost').checked; if (hideLocalhost && isLocalhostTraffic(packet)) return;
    addPacketToFlow(packet); updateVisualization(packet);
}
function addPacketToFlow(packet) {
    const { type, key, direction, a, b } = classifyPacket(packet);
    let flowElement = smartGroups[type].get(key);
    if (!flowElement) {
        flowElement = createFlowElement(type, key, packet);
        smartGroups[type].set(key, flowElement);
        const metadata = { type, key, packetCount: 0, packets: [], firstSeen: packet.timestamp, lastSeen: packet.timestamp, packetsContainer: flowElement.querySelector('.session-packets'), countElement: flowElement.querySelector(`#${flowElement.id}-count`), sentElement: flowElement.querySelector(`#${flowElement.id}-sent`), recvElement: flowElement.querySelector(`#${flowElement.id}-recv`), endpointA: a, endpointB: b, sentBytes: 0, recvBytes: 0, isExpanded: false };
        groupMetadata.set(`${type}-${key}`, metadata);
        flowList.insertBefore(flowElement, flowList.firstChild); shouldSort = true;
    }
    const metadata = groupMetadata.get(`${type}-${key}`);
    metadata.packets.push(packet); metadata.packetCount++; metadata.lastSeen = packet.timestamp; metadata.countElement.textContent = metadata.packetCount;
    if (direction === 'a_to_b') { metadata.sentBytes += packet.length; metadata.sentElement.textContent = formatBytes(metadata.sentBytes); }
    else { metadata.recvBytes += packet.length; metadata.recvElement.textContent = formatBytes(metadata.recvBytes); }
    if (metadata.isExpanded) { addPacketToExpandedFlow(metadata, packet); }
    estimatedMemoryUsage += 0.001; checkLimits(); updateTabBadges();
}
function addPacketToExpandedFlow(metadata, packet) {
    const packetDiv = document.createElement('div'); packetDiv.className = 'session-packet';
    const timestamp = new Date(packet.timestamp * 1000).toLocaleTimeString();
    packetDiv.textContent = `${timestamp} | ${packet.src_ip} → ${packet.dst_ip} | ${packet.length} bytes | ${packet.info}`;
    metadata.packetsContainer.insertBefore(packetDiv, metadata.packetsContainer.firstChild);
    const maxPacketsPerSession = parseInt(getCachedElement('maxPacketsPerSession').value) || 50;
    while (metadata.packetsContainer.children.length > maxPacketsPerSession) { metadata.packetsContainer.removeChild(metadata.packetsContainer.lastChild); }
}
function toggleFlowUltraFast(flowId) {
    const packets = document.getElementById(`${flowId}-packets`); const toggle = document.getElementById(`${flowId}-toggle`);
    const isCollapsed = packets.classList.contains('collapsed');
    packets.classList.toggle('collapsed'); toggle.classList.toggle('collapsed');
    const meta = groupMetadata.get(flowId.replace('flow-','').replace(/^[^-]+-/, (m)=>{return m;}));
    if (meta) { meta.isExpanded = !isCollapsed; const loader = packets.querySelector('.loading-skeleton'); if (meta.isExpanded) { if (loader) loader.style.display = 'block'; setTimeout(() => { if (loader) loader.style.display = 'none'; meta.packets.slice(-10).forEach(p => addPacketToExpandedFlow(meta, p)); }, 100); } }
}
function getCachedElement(id) { if (!cachedElements.has(id)) { cachedElements.set(id, document.getElementById(id)); } return cachedElements.get(id); }
function checkLimits() { cleanupOldFlows(); const memoryLimit = parseInt(getCachedElement('memoryLimit').value) || 50; const maxSessions = parseInt(getCachedElement('maxSessions').value) || 20; if (estimatedMemoryUsage > memoryLimit) { removeOldestPackets(); } enforceSessionLimit(maxSessions); }
function removeOldestPackets() { const sessions = Array.from(groupMetadata.values()); sessions.sort((a,b) => a.lastSeen - b.lastSeen); while (estimatedMemoryUsage > (parseInt(getCachedElement('memoryLimit').value)||50) * 0.9 && sessions.length > 0) { const s = sessions.shift(); if (!s) break; const key = `${s.type}-${s.key}`; removeFlow(key); } }
function enforceSessionLimit(maxSessions) { const sessions = Array.from(groupMetadata.values()); if (sessions.length <= maxSessions) return; sessions.sort((a,b) => a.lastSeen - b.lastSeen); while (groupMetadata.size > maxSessions) { const s = sessions.shift(); if (!s) break; removeFlow(`${s.type}-${s.key}`); } }
function formatBytes(bytes) { const units = ['B','KB','MB','GB']; let i = 0; let val = bytes; while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; } return `${val.toFixed(1)}${units[i]}`; }
function updateTabBadges() { topTabBadge.textContent = groupMetadata.size; vizTabBadge.textContent = hosts.length; topTabBadge.classList.toggle('zero', groupMetadata.size === 0); vizTabBadge.classList.toggle('zero', hosts.length === 0); }

function drawChordDiagram() {
    chordSvg.selectAll('*').remove();
    const width = 400, height = 400, innerRadius = Math.min(width, height) * 0.4, outerRadius = innerRadius + 10;
    const chord = d3.chord().padAngle(0.02).sortSubgroups(d3.descending);
    const arc = d3.arc().innerRadius(innerRadius).outerRadius(outerRadius);
    const ribbon = d3.ribbon().radius(innerRadius);
    if (hosts.length === 0) return;
    const chords = chord(matrix);
    const color = d3.scaleOrdinal(d3.schemeCategory10);
    const g = chordSvg.attr('viewBox', [-width/2, -height/2, width, height]).append('g');
    g.append('g').selectAll('g').data(chords.groups).enter().append('g')
        .append('path').attr('d', arc).attr('fill', d => color(d.index)).attr('stroke', '#4a5568');
    g.append('g').attr('fill-opacity', 0.75).selectAll('path').data(chords).enter().append('path')
        .attr('d', ribbon).attr('fill', d => color(d.target.index)).attr('stroke', '#2d3748');
    g.append('g').selectAll('text').data(chords.groups).enter().append('text')
        .attr('dy', '-0.35em').attr('transform', d => `rotate(${(d.startAngle + d.endAngle)/2 * 180/Math.PI - 90}) translate(${outerRadius + 5})`)
        .style('text-anchor', 'start').text((d,i) => hosts[i]);
}
function updateChordTraffic(src, dst, bytes) {
    const a = groupLanWanCheckbox && groupLanWanCheckbox.checked ? (isLan(src) ? 'LAN' : 'WAN') : src;
    const b = groupLanWanCheckbox && groupLanWanCheckbox.checked ? (isLan(dst) ? 'LAN' : 'WAN') : dst;
    if (!hostIndex.has(a)) { hostIndex.set(a, hosts.length); hosts.push(a); }
    if (!hostIndex.has(b)) { hostIndex.set(b, hosts.length); hosts.push(b); }
    const i = hostIndex.get(a); const j = hostIndex.get(b);
    const size = Math.max(i, j) + 1;
    while (matrix.length < size) { matrix.push(new Array(size).fill(0)); }
    for (let row of matrix) { while (row.length < size) { row.push(0); } }
    matrix[i][j] += bytes; matrix[j][i] += bytes;
}

