'use strict';

// =====================================================================
// WebShark front-end: aggregation + rendering.
// ws.js feeds data in through ingestBatch(), setContext(), noteDropped()
// and setConnState().
// =====================================================================

// ---------- Limits ----------
const KEEP_SECONDS = 900;          // throughput history
const FLOW_IDLE_EXPIRE = 300;      // drop flows idle this long (s)
const MAX_FLOWS = 4000;
const MAX_REMOTES = 3000;
const MAX_NAMES = 8000;
const MAX_DEVICES = 2000;
const MAX_LOG = 500;
const FLOW_RECENT = 40;            // packets kept per flow for the detail view
const ACTIVE_WINDOW = 60;          // "active" flow = seen in last N s
const GRAPH_WINDOW = 120;

const svgIcon = (body) => `<svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
const ICON_PAUSE = svgIcon('<path d="M5.5 3.5v9M10.5 3.5v9"/>');
const ICON_PLAY = svgIcon('<path d="M5 3.2v9.6L12.5 8z" fill="currentColor"/>');

const SEV_LABEL = { critical: '重大', serious: '警告', warning: '注意', info: '情報' };
const SEV_ICON = { critical: '⛔', serious: '⚠', warning: '△', info: 'ℹ' };

// Well-known services by transport/port. Port wins over the dissector name so
// that every packet of one connection gets the same label (a TCP ACK and a TLS
// record of the same HTTPS session both count as "HTTPS").
const PORTS = {
    TCP: {
        20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        139: 'NetBIOS', 143: 'IMAP', 179: 'BGP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 554: 'RTSP',
        587: 'SMTP', 631: 'IPP', 853: 'DNS over TLS', 993: 'IMAPS', 995: 'POP3S', 1883: 'MQTT',
        2049: 'NFS', 3000: 'HTTP-dev', 3306: 'MySQL', 3389: 'RDP', 5222: 'XMPP', 5223: 'Apple Push',
        5228: 'Google Push', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8008: 'HTTP-alt',
        8009: 'Cast', 8080: 'HTTP-alt', 8443: 'HTTPS-alt', 8883: 'MQTTS', 9100: 'Printer', 62078: 'iPhone Sync'
    },
    UDP: {
        53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 123: 'NTP', 137: 'NetBIOS', 138: 'NetBIOS',
        161: 'SNMP', 443: 'QUIC', 500: 'IPsec', 546: 'DHCPv6', 547: 'DHCPv6', 1900: 'SSDP',
        3478: 'STUN', 4500: 'IPsec', 5353: 'mDNS', 5355: 'LLMNR', 19302: 'STUN', 41641: 'Tailscale',
        51820: 'WireGuard'
    }
};
const DISSECTOR_NAMES = {
    tls: 'TLS', quic: 'QUIC', dns: 'DNS', mdns: 'mDNS', http: 'HTTP', http2: 'HTTP/2', ssdp: 'SSDP',
    ntp: 'NTP', dhcp: 'DHCP', dhcpv6: 'DHCPv6', arp: 'ARP', icmp: 'ICMP', icmpv6: 'ICMPv6', igmp: 'IGMP',
    ssh: 'SSH', llmnr: 'LLMNR', nbns: 'NetBIOS', nbdgm: 'NetBIOS', stun: 'STUN', lldp: 'LLDP', stp: 'STP',
    eapol: 'EAPOL', websocket: 'WebSocket', smb2: 'SMB', ipp: 'IPP', mqtt: 'MQTT', wg: 'WireGuard'
};
const GENERIC_LAYERS = new Set(['eth', 'ethertype', 'sll', 'ip', 'ipv6', 'tcp', 'udp', 'data', 'vlan',
    'ppp', 'pppoes', 'unknown', 'llc', 'ipv6.hopopts']);

// ---------- State ----------
const S = {
    protocols: [],
    selfIps: new Set(),
    lanNets: [],
    hostname: '',
    paused: false,
    firstT: null,
    skew: null,              // browser clock - capture clock (s)
    totalPkts: 0,
    dropped: 0,
    secs: new Map(),         // sec -> {down, up, int, pkts}
    devices: new Map(),      // deviceKey -> device
    knownDevices: new Set(), // device keys ever seen (kept across "clear")
    baseT: null,             // first packet ever (not reset by "clear")
    ipToDevice: new Map(),   // ip -> deviceKey
    selfMacs: new Set(),
    remotes: new Map(),      // ip -> {bytes, last}
    names: new Map(),        // ip -> hostname (DNS/mDNS answers, SNI)
    lanNames: new Map(),     // ip -> hostname resolved by the server for LAN devices
    flows: new Map(),        // flowKey -> flow
    flowSeq: 0,
    apps: new Map(),         // app -> bytes
    sizes: [0, 0, 0, 0, 0, 0, 0],
    log: [],
    alerts: [],
    alertSeq: 0,
    cooldown: new Map(),     // alert key -> t
    scans: new Map(),        // src ip -> {t0, perDst: Map, perPort: Map}
    expanded: new Set(),     // flow ids open in the table
    sort: { col: 'rate', dir: -1 },
    range: 300,
    graphMode: 'map',
    search: '',
    view: 'dash',
};

// ---------- Utilities ----------
const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const nowCapture = () => Date.now() / 1000 - (S.skew ?? 0);

function fmtNum(n, digits = 3) {
    if (n === 0) return '0';
    const v = Number(n.toPrecision(digits));
    return v >= 100 ? Math.round(v).toString() : v.toString();
}
function fmtScaled(n, units, base = 1000) {
    let i = 0;
    while (Math.abs(n) >= base && i < units.length - 1) { n /= base; i++; }
    return `${fmtNum(n)} ${units[i]}`;
}
const fmtBits = (bps) => fmtScaled(bps, ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps']);
const fmtBytes = (b) => fmtScaled(b, ['B', 'KB', 'MB', 'GB', 'TB']);
const fmtInt = (n) => Math.round(n).toLocaleString('ja-JP');
function fmtAgo(sec) {
    sec = Math.max(0, Math.round(sec));
    if (sec < 60) return `${sec}秒前`;
    if (sec < 3600) return `${Math.floor(sec / 60)}分前`;
    return `${Math.floor(sec / 3600)}時間前`;
}
function fmtClock(t, ms = false) {
    const d = new Date((t + (S.skew ?? 0)) * 1000);
    const s = d.toLocaleTimeString('ja-JP', { hour12: false });
    return ms ? `${s}.${String(d.getMilliseconds()).padStart(3, '0')}` : s;
}
/** "1.2.3.4:80" / "[2001:db8::1]:443" / "name:443" */
function withPort(host, port) {
    if (port === undefined || port === null) return host;
    return host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
}
function trunc(s, n) { s = String(s); return s.length > n ? s.slice(0, n - 1) + '…' : s; }
function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

// ---------- IP classification ----------
function parseV4(ip) {
    const p = ip.split('.');
    if (p.length !== 4) return null;
    let n = 0;
    for (const x of p) {
        const v = Number(x);
        if (!Number.isInteger(v) || v < 0 || v > 255 || x === '') return null;
        n = n * 256 + v;
    }
    return n;
}
function parseV6(ip) {
    ip = ip.split('%')[0];
    if (!ip.includes(':')) return null;
    let [head, tail] = ip.split('::');
    const h = head ? head.split(':') : [];
    let t = tail !== undefined ? (tail ? tail.split(':') : []) : null;
    const last = (t ?? h)[(t ?? h).length - 1];
    const extra = [];
    if (last && last.includes('.')) {         // embedded IPv4
        const v4 = parseV4(last);
        if (v4 === null) return null;
        (t ?? h).pop();
        extra.push((v4 >>> 16).toString(16), (v4 & 0xffff).toString(16));
    }
    const groups = t === null ? [...h, ...extra] : [...h, ...Array(8 - h.length - t.length - extra.length).fill('0'), ...t, ...extra];
    if (groups.length !== 8) return null;
    let n = 0n;
    for (const g of groups) {
        const v = parseInt(g || '0', 16);
        if (Number.isNaN(v) || v > 0xffff) return null;
        n = (n << 16n) | BigInt(v);
    }
    return n;
}
function parseCidr(cidr) {
    const [addr, bitsStr] = cidr.split('/');
    const bits = Number(bitsStr);
    const v4 = parseV4(addr);
    if (v4 !== null) {
        const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
        return { v: 4, net: (v4 & mask) >>> 0, mask };
    }
    const v6 = parseV6(addr);
    if (v6 !== null) {
        const mask = bits === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - bits)) - 1n);
        return { v: 6, net: v6 & mask, mask };
    }
    return null;
}
const BUILTIN_LOCAL = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '127.0.0.0/8',
    '100.64.0.0/10', 'fe80::/10', 'fc00::/7', '::1/128'].map(parseCidr);
const MULTICAST = ['224.0.0.0/4', '255.255.255.255/32', 'ff00::/8'].map(parseCidr);

function inNets(ip, nets) {
    const v4 = parseV4(ip);
    if (v4 !== null) return nets.some((n) => n && n.v === 4 && ((v4 & n.mask) >>> 0) === n.net);
    const v6 = parseV6(ip);
    if (v6 !== null) return nets.some((n) => n && n.v === 6 && (v6 & n.mask) === n.net);
    return false;
}
const classCache = new Map();
const LINK_LOCAL = ['169.254.0.0/16', 'fe80::/10'].map(parseCidr);
/**
 * 'self' | 'mcast' | 'lan' (a device on our LAN) | 'priv' (private/local
 * range beyond the gateway, e.g. VPN or CGNAT) | 'wan' | 'none'
 * Mirrors Classifier in src/history.rs.
 */
function classify(ip) {
    let c = classCache.get(ip);
    if (c) return c;
    if (!ip || ip === 'Unknown' || ip === '0.0.0.0' || ip === '::') c = 'none';
    else if (S.selfIps.has(ip)) c = 'self';
    else if (inNets(ip, MULTICAST)) c = 'mcast';
    else if (S.lanNets.length ? inNets(ip, S.lanNets) || inNets(ip, LINK_LOCAL) : inNets(ip, BUILTIN_LOCAL)) c = 'lan';
    else if (inNets(ip, BUILTIN_LOCAL)) c = 'priv';
    else c = 'wan';
    if (classCache.size > 20000) classCache.clear();
    classCache.set(ip, c);
    return c;
}
const isLocal = (ip) => { const c = classify(ip); return c !== 'wan'; };
const isDevice = (ip) => classify(ip) === 'lan';

function direction(src, dst) {
    const sl = isLocal(src), dl = isLocal(dst);
    if (sl && !dl) return 'up';
    if (!sl && dl) return 'down';
    return 'int';
}

function appName(p, l4) {
    const table = PORTS[l4];
    if (table) {
        const a = table[p.dP], b = table[p.sP];
        if (a && b) return p.dP <= p.sP ? a : b;
        if (a || b) return a || b;
    }
    const d = p.a || '';
    if (!GENERIC_LAYERS.has(d)) return DISSECTOR_NAMES[d] || d.toUpperCase();
    return l4 === 'TCP' || l4 === 'UDP' ? `${l4} その他` : (l4 || 'その他');
}

// ---------- Naming ----------
function setName(ip, name) {
    if (!ip || !name) return;
    name = name.replace(/\.$/, '');
    if (S.names.get(ip) === name) return;
    S.names.delete(ip);
    S.names.set(ip, name);
    if (S.names.size > MAX_NAMES) S.names.delete(S.names.keys().next().value);
}
const cleanHost = (n) => n.replace(/\.local$/i, '');
function deviceName(dev) {
    for (const ip of dev.ips) { const n = S.lanNames.get(ip); if (n) return cleanHost(n); }
    for (const ip of dev.ips) { const n = S.names.get(ip); if (n) return cleanHost(n); }
    return null;
}
function deviceAddr(dev) {
    const v4 = [...dev.ips].find((ip) => parseV4(ip) !== null);
    return v4 || [...dev.ips][0] || dev.mac || '?';
}
function deviceLabel(dev) {
    return deviceName(dev) || deviceAddr(dev);
}
function mergeLanNames(obj) {
    let changed = false;
    for (const [ip, name] of Object.entries(obj || {})) {
        if (S.lanNames.get(ip) !== name) { S.lanNames.set(ip, name); changed = true; }
    }
    return changed;
}
async function pollNames() {
    try {
        const r = await fetch('/api/names');
        if (r.ok && mergeLanNames(await r.json()) && !S.paused) render();
    } catch { /* ignore */ }
}
function hostLabel(ip) {
    const c = classify(ip);
    if (c === 'self') return S.hostname ? `${S.hostname} (ルーター)` : 'このルーター';
    if (c === 'lan') {
        const key = S.ipToDevice.get(ip);
        const dev = key && S.devices.get(key);
        if (dev) return deviceLabel(dev);
    }
    return S.names.get(ip) || ip;
}

// ---------- Ingest ----------
/** Own addresses / LAN networks; sent at connect and again when they change. */
function setNetwork(net) {
    S.selfIps = new Set(net.local_ips || []);
    S.lanNets = (net.lan_nets || []).map((n) => parseCidr(n.cidr)).filter(Boolean);
    S.hostname = net.hostname || '';
    classCache.clear();
}

function setContext(ctx) {
    S.protocols = ctx.protocols || [];
    setNetwork(ctx);
    mergeLanNames(ctx.lan_names);
    geoSetContext(ctx.geo);
    // Seed throughput history recorded by the server before we connected.
    for (const [sec, down, up, int, pkts] of ctx.history || []) {
        if (!S.secs.has(sec)) S.secs.set(sec, { down, up, int, pkts });
    }
    if (ctx.history && ctx.history.length) {
        const last = ctx.history[ctx.history.length - 1][0];
        if (S.skew === null) S.skew = Date.now() / 1000 - (last + 1);
    }
    $('hostLabel').textContent = S.hostname ? `@ ${S.hostname}` : '';
    document.title = S.hostname ? `WebShark · ${S.hostname}` : 'WebShark';
}

function noteDropped(n) { S.dropped += n; }

function ingestBatch(packets) {
    if (!packets.length) return;
    let maxT = 0;
    for (const p of packets) {
        ingest(p);
        if (p.t > maxT) maxT = p.t;
    }
    // Estimate clock skew between the capture box and this browser.
    const skewNow = Date.now() / 1000 - maxT;
    S.skew = S.skew === null ? skewNow : S.skew * 0.8 + skewNow * 0.2;
}

function ingest(p) {
    const t = p.t;
    const len = p.l || 0;
    const l4 = S.protocols[p.p] || '';
    if (S.firstT === null) S.firstT = t;
    if (S.baseT === null) S.baseT = t;
    S.totalPkts++;

    // DNS / mDNS answers and TLS SNI / HTTP Host give us names for addresses.
    if (p.dn && p.da) for (const a of p.da) setName(a, p.dn);

    const dir = direction(p.s, p.d);
    const app = appName(p, l4);

    // Throughput buckets
    const sec = Math.floor(t);
    let b = S.secs.get(sec);
    if (!b) { b = { down: 0, up: 0, int: 0, pkts: 0 }; S.secs.set(sec, b); }
    b[dir] += len;
    b.pkts++;

    S.apps.set(app, (S.apps.get(app) || 0) + len);
    S.sizes[sizeBin(len)]++;

    // Learn our own MAC(s) so they're never counted as a LAN device.
    if (p.sm && classify(p.s) === 'self') S.selfMacs.add(p.sm);

    // Devices (LAN side) and remotes (internet side)
    if (isDevice(p.s)) touchDevice(p.s, p.sm, t, len, 'up', dir);
    if (isDevice(p.d)) touchDevice(p.d, p.dm, t, len, 'down', dir);
    if (classify(p.s) === 'wan') touchRemote(p.s, t, len);
    if (classify(p.d) === 'wan') touchRemote(p.d, t, len);

    const flow = touchFlow(p, l4, app, t, len);
    if (p.sn && flow) {
        flow.name = p.sn;
        setName(flow.remote.ip, p.sn);
    }

    detect(p, l4, t, len, dir);

    const entry = { t, s: p.s, d: p.d, sP: p.sP, dP: p.dP, app, l: len, i: p.i };
    S.log.push(entry);
    if (S.log.length > MAX_LOG * 1.2) S.log.splice(0, S.log.length - MAX_LOG);
    if (flow) {
        flow.recent.push(entry);
        if (flow.recent.length > FLOW_RECENT) flow.recent.shift();
    }
}

function sizeBin(len) {
    if (len <= 64) return 0;
    if (len <= 128) return 1;
    if (len <= 256) return 2;
    if (len <= 512) return 3;
    if (len <= 1024) return 4;
    if (len <= 1514) return 5;
    return 6;
}

/** Individual (not multicast/broadcast) MAC address: group bit clear. */
const isUnicastMac = (mac) => !!mac && (parseInt(mac.slice(0, 2), 16) & 1) === 0;

function touchDevice(ip, mac, t, len, side, dir) {
    if (mac && !isUnicastMac(mac)) mac = null;
    // The router's own interfaces (any of its addresses) are not LAN devices.
    if (mac && S.selfMacs.has(mac)) return;
    const key = mac || S.ipToDevice.get(ip) || `ip:${ip}`;
    let dev = S.devices.get(key);
    if (!dev) {
        dev = { key, mac: mac || null, ips: new Set(), up: 0, down: 0, int: 0, pkts: 0, first: t, last: t, upRing: new Float64Array(10), ringSec: Math.floor(t) };
        S.devices.set(key, dev);
        if (S.devices.size > MAX_DEVICES) pruneDevices();
        // "Known" survives clearing the view, so clearing does not make every
        // quiet device look new; only devices first seen after a warm-up alert.
        if (!S.knownDevices.has(key)) {
            if (S.baseT !== null && t - S.baseT > 60) {
                raise('info', `new-dev:${key}`, '新しいデバイス', `${mac ? `MAC ${mac} / ` : ''}${ip} が初めて通信しました`, t, 24 * 3600);
            }
            S.knownDevices.add(key);
            if (S.knownDevices.size > MAX_DEVICES * 4) S.knownDevices.clear();
        }
    }
    dev.ips.add(ip);
    if (dev.ips.size > 16) dev.ips.delete(dev.ips.values().next().value);
    S.ipToDevice.set(ip, key);
    dev.last = t;
    dev.pkts++;
    if (dir === 'int') dev.int += len;
    else dev[side] += len;

    if (side === 'up' && dir === 'up') {
        // 10-second ring buffer of upload bytes for the heavy-upload rule.
        const sec = Math.floor(t);
        const steps = Math.min(10, Math.max(0, sec - dev.ringSec));
        for (let i = 1; i <= steps; i++) dev.upRing[(dev.ringSec + i) % 10] = 0;
        if (sec > dev.ringSec) dev.ringSec = sec;
        dev.upRing[sec % 10] += len;
        let sum = 0;
        for (const v of dev.upRing) sum += v;
        if (sum >= 50e6) {
            raise('warning', `upload:${key}`, '大量アップロード', `${deviceLabel(dev)} が10秒間に ${fmtBytes(sum)} を外部へ送信しています`, t, 300);
        }
    }
}

function pruneDevices() {
    const old = [...S.devices.values()].sort((a, b) => a.last - b.last).slice(0, S.devices.size - MAX_DEVICES * 0.8);
    for (const d of old) {
        S.devices.delete(d.key);
        for (const ip of d.ips) if (S.ipToDevice.get(ip) === d.key) S.ipToDevice.delete(ip);
    }
}

function touchRemote(ip, t, len) {
    let r = S.remotes.get(ip);
    if (!r) {
        r = { bytes: 0, last: t };
        S.remotes.set(ip, r);
        if (S.remotes.size > MAX_REMOTES) pruneRemotes();
    }
    r.bytes += len;
    r.last = t;
}
function pruneRemotes() {
    const keep = [...S.remotes.entries()].sort((a, b) => b[1].bytes - a[1].bytes).slice(0, MAX_REMOTES / 2);
    S.remotes = new Map(keep);
}

function touchFlow(p, l4, app, t, len) {
    if (p.s === 'Unknown' && p.d === 'Unknown') return null;
    const a = `${p.s}#${p.sP ?? ''}`, b = `${p.d}#${p.dP ?? ''}`;
    // The app label is not part of the key: for unlisted ports it comes from
    // the per-packet dissector and would split one connection in two.
    const key = `${l4}|${a < b ? `${a}|${b}` : `${b}|${a}`}`;
    let f = S.flows.get(key);
    if (!f) {
        // Orient the flow: "local" is the LAN side; for LAN<->LAN it is the initiator.
        const srcLocal = isLocal(p.s), dstLocal = isLocal(p.d);
        const localIsSrc = srcLocal === dstLocal ? true : srcLocal;
        f = {
            id: ++S.flowSeq, key, l4, app,
            local: localIsSrc ? { ip: p.s, port: p.sP } : { ip: p.d, port: p.dP },
            remote: localIsSrc ? { ip: p.d, port: p.dP } : { ip: p.s, port: p.sP },
            up: 0, down: 0, pkts: 0, first: t, last: t, name: null, win: new Map(), recent: [], closed: false,
        };
        S.flows.set(key, f);
        if (S.flows.size > MAX_FLOWS) pruneFlows(t, true);
    }
    if (isGenericApp(f.app) && !isGenericApp(app)) f.app = app;
    const fromLocal = p.s === f.local.ip && (p.sP ?? null) === (f.local.port ?? null);
    if (fromLocal) f.up += len; else f.down += len;
    f.pkts++;
    f.last = t;
    // Per-second [up, down] bytes for rates and the map; trimmed as we go so
    // long-lived flows cannot grow it without bound.
    const sec = Math.floor(t);
    let w = f.win.get(sec);
    if (!w) {
        w = [0, 0];
        f.win.set(sec, w);
        for (const k of f.win.keys()) { if (k >= sec - GRAPH_WINDOW - 2) break; f.win.delete(k); }
    }
    w[fromLocal ? 0 : 1] += len;
    if (p.f !== undefined && (p.f & 0x05)) f.closed = true;   // FIN or RST
    return f;
}
function pruneFlows(now, force = false) {
    for (const [k, f] of S.flows) {
        if (now - f.last > FLOW_IDLE_EXPIRE) { S.flows.delete(k); S.expanded.delete(f.id); }
    }
    if (force && S.flows.size > MAX_FLOWS) {
        const sorted = [...S.flows.values()].sort((x, y) => x.last - y.last);
        for (const f of sorted.slice(0, S.flows.size - MAX_FLOWS * 0.8)) { S.flows.delete(f.key); S.expanded.delete(f.id); }
    }
}
const isGenericApp = (a) => /^(TCP|UDP)( その他)?$|^その他$/.test(a);

/** Bytes of the last `seconds` complete seconds (the current one is partial). */
function flowWindow(f, nowSec, seconds) {
    let up = 0, down = 0;
    for (const [sec, w] of f.win) {
        if (sec >= nowSec - seconds && sec < nowSec) { up += w[0]; down += w[1]; }
    }
    return { up, down, total: up + down };
}
const flowWindowBytes = (f, nowSec, seconds) => flowWindow(f, nowSec, seconds).total;

// ---------- Detection ----------
function raise(sev, key, title, detail, t, cooldown = 300) {
    const last = S.cooldown.get(key);
    if (last !== undefined && t - last < cooldown) return;
    S.cooldown.set(key, t);
    S.alerts.unshift({ id: ++S.alertSeq, sev, title, detail, t, unread: true });
    if (S.alerts.length > 200) S.alerts.length = 200;
    renderAlertBadge();
    if (S.view === 'alerts') renderAlerts();
}

function detect(p, l4, t) {
    // SYN without ACK = connection attempt.
    if (l4 !== 'TCP' || p.f === undefined || (p.f & 0x12) !== 0x02 || p.dP === undefined) return;
    let st = S.scans.get(p.s);
    if (!st || t - st.t0 > 10) {
        st = { t0: t, perDst: new Map(), perPort: new Map() };
        S.scans.set(p.s, st);
        if (S.scans.size > 5000) S.scans.clear();
    }
    let ports = st.perDst.get(p.d);
    if (!ports) { ports = new Set(); st.perDst.set(p.d, ports); }
    ports.add(p.dP);
    if (ports.size >= 20) {
        raise('serious', `scan:${p.s}>${p.d}`, 'ポートスキャンの疑い',
            `${hostLabel(p.s)} が ${hostLabel(p.d)} の ${ports.size} 個以上のTCPポートへ10秒以内に接続を試みています`, t);
    }
    if (isDevice(p.d)) {
        let hosts = st.perPort.get(p.dP);
        if (!hosts) { hosts = new Set(); st.perPort.set(p.dP, hosts); }
        hosts.add(p.d);
        if (hosts.size >= 15) {
            raise('serious', `sweep:${p.s}:${p.dP}`, 'LAN内スイープの疑い',
                `${hostLabel(p.s)} がLAN内の ${hosts.size} 台以上のホストのTCP ${p.dP} 番へ10秒以内に接続を試みています`, t);
        }
    }
}

// ---------- Charts ----------
Chart.defaults.animation = false;
Chart.defaults.maintainAspectRatio = false;
Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
Chart.defaults.font.size = 12;

function baseScales(horizontal, stacked, valueFmt) {
    const value = {
        beginAtZero: true, stacked,
        grid: { color: () => cssVar('--grid'), drawTicks: false },
        border: { display: false },
        ticks: { color: () => cssVar('--muted'), callback: (v) => valueFmt(v), maxTicksLimit: 6, padding: 6 },
    };
    const cat = {
        stacked,
        grid: { display: false },
        border: { color: () => cssVar('--axis') },
        ticks: { color: () => cssVar('--ink-2'), autoSkip: !horizontal, maxRotation: 0 },
    };
    return horizontal ? { x: value, y: cat } : { x: cat, y: value };
}
function tooltipStyle() {
    return {
        backgroundColor: () => cssVar('--surface'),
        titleColor: () => cssVar('--ink'),
        bodyColor: () => cssVar('--ink-2'),
        borderColor: () => cssVar('--axis'),
        borderWidth: 1, padding: 10, boxPadding: 4, usePointStyle: true,
    };
}
function barDataset(label, colorVar) {
    return {
        label, data: [], backgroundColor: () => cssVar(colorVar),
        borderRadius: 4, borderSkipped: 'start', borderColor: () => cssVar('--surface'), borderWidth: { top: 0, bottom: 0, left: 0, right: 2 },
        maxBarThickness: 22,
    };
}

const charts = {};
function makeCharts() {
    charts.throughput = new Chart($('throughputChart'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                { label: '下り', data: [], borderColor: () => cssVar('--s-down'), backgroundColor: () => cssVar('--s-down') + '55', fill: 'origin', borderWidth: 2, pointRadius: 0, pointHoverRadius: 4, tension: 0.25 },
                { label: '上り', data: [], borderColor: () => cssVar('--s-up'), backgroundColor: () => cssVar('--s-up') + '55', fill: '-1', borderWidth: 2, pointRadius: 0, pointHoverRadius: 4, tension: 0.25 },
                { label: 'LAN内', data: [], borderColor: () => cssVar('--s-int'), backgroundColor: () => cssVar('--s-int') + '40', fill: '-1', borderWidth: 2, pointRadius: 0, pointHoverRadius: 4, tension: 0.25 },
            ],
        },
        options: {
            interaction: { mode: 'index', intersect: false },
            scales: (() => {
                const s = baseScales(false, true, fmtBits);
                s.x.ticks.autoSkip = true; s.x.ticks.maxTicksLimit = 8;
                return s;
            })(),
            plugins: {
                legend: { display: false },
                tooltip: { ...tooltipStyle(), callbacks: { label: (c) => ` ${c.dataset.label}  ${fmtBits(c.parsed.y)}` } },
            },
        },
    });

    charts.devices = new Chart($('devicesChart'), {
        type: 'bar',
        data: { labels: [], datasets: [barDataset('下り', '--s-down'), barDataset('上り', '--s-up'), barDataset('LAN内', '--s-int')] },
        options: {
            indexAxis: 'y',
            scales: baseScales(true, true, (v) => fmtBytes(v)),
            plugins: {
                legend: { display: false },
                tooltip: { ...tooltipStyle(), callbacks: { title: (c) => charts.devices.$full[c[0].dataIndex], label: (c) => ` ${c.dataset.label}  ${fmtBytes(c.parsed.x)}` } },
            },
        },
    });

    charts.apps = new Chart($('appsChart'), {
        type: 'bar',
        data: { labels: [], datasets: [barDataset('通信量', '--s-down')] },
        options: {
            indexAxis: 'y',
            scales: baseScales(true, false, (v) => fmtBytes(v)),
            plugins: {
                legend: { display: false },
                tooltip: { ...tooltipStyle(), callbacks: { label: (c) => ` ${fmtBytes(c.parsed.x)}  (${charts.apps.$pct[c.dataIndex]})` } },
            },
        },
    });

    charts.remotes = new Chart($('remotesChart'), {
        type: 'bar',
        data: { labels: [], datasets: [barDataset('通信量', '--s-up')] },
        options: {
            indexAxis: 'y',
            scales: baseScales(true, false, (v) => fmtBytes(v)),
            plugins: {
                legend: { display: false },
                tooltip: { ...tooltipStyle(), callbacks: { title: (c) => charts.remotes.$full[c[0].dataIndex], label: (c) => ` ${fmtBytes(c.parsed.x)}` } },
            },
        },
    });

    charts.sizes = new Chart($('sizeChart'), {
        type: 'bar',
        data: {
            labels: ['≤64', '65–128', '129–256', '257–512', '513–1024', '1025–1514', '1515+'],
            datasets: [{ ...barDataset('パケット数', '--s-int'), borderSkipped: 'start', borderWidth: { left: 2, right: 0, top: 0, bottom: 0 } }],
        },
        options: {
            scales: baseScales(false, false, (v) => fmtScaled(v, ['', 'K', 'M', 'G'])),
            plugins: {
                legend: { display: false },
                tooltip: { ...tooltipStyle(), callbacks: { title: (c) => `${c[0].label} バイト`, label: (c) => ` ${fmtInt(c.parsed.y)} パケット` } },
            },
        },
    });
}

/** Max label characters for a horizontal bar chart of this width. */
const labelBudget = (chart) => (chart.width < 420 ? 18 : chart.width < 600 ? 26 : 40);
/** Shorten a label; IPv6 addresses keep their (more distinctive) tail. */
function shortLabel(label, max) {
    if (label.length <= max) return label;
    return parseV6(label) !== null ? `…${label.slice(-(max - 1))}` : trunc(label, max);
}

function topN(entries, n) {
    entries.sort((a, b) => b[1] - a[1]);
    const top = entries.slice(0, n);
    const rest = entries.slice(n).reduce((s, e) => s + e[1], 0);
    return { top, rest };
}

function renderThroughput(now) {
    const range = S.range;
    const step = range <= 60 ? 1 : range <= 300 ? 2 : 5;
    const end = Math.floor(now) - 1;            // last complete second
    const start = end - range + 1;
    const labels = [], down = [], up = [], int = [];
    for (let t = start - ((start % step) + step) % step; t <= end; t += step) {
        let d = 0, u = 0, i = 0;
        for (let k = 0; k < step; k++) {
            const b = S.secs.get(t + k);
            if (b) { d += b.down; u += b.up; i += b.int; }
        }
        labels.push(fmtClock(t));
        down.push((d * 8) / step); up.push((u * 8) / step); int.push((i * 8) / step);
    }
    const c = charts.throughput;
    c.options.scales.x.ticks.maxTicksLimit = c.width < 500 ? 3 : 8;
    c.data.labels = labels;
    c.data.datasets[0].data = down;
    c.data.datasets[1].data = up;
    c.data.datasets[2].data = int;
    c.update('none');
}

function renderDevices(now) {
    const devs = [...S.devices.values()].sort((a, b) => (b.up + b.down + b.int) - (a.up + a.down + a.int)).slice(0, 10);
    const c = charts.devices;
    c.$full = devs.map((d) => `${deviceLabel(d)}${d.mac ? `  (${d.mac})` : ''}\n${[...d.ips].slice(0, 4).join(', ')}`);
    // Label = address, extended with the hostname once it resolves.
    const addrs = devs.map((d) => deviceAddr(d));
    const seen = new Map();
    for (const a of addrs) seen.set(a, (seen.get(a) || 0) + 1);
    const max = labelBudget(c);
    c.data.labels = devs.map((d, i) => {
        let addr = shortLabel(addrs[i], Math.min(max, 18));
        if (seen.get(addrs[i]) > 1 && d.mac) addr += ` (${d.mac.slice(-5)})`;
        const name = deviceName(d);
        return name ? `${shortLabel(name, Math.max(8, max - addr.length - 2))}  ${addr}` : addr;
    });
    c.data.datasets[0].data = devs.map((d) => d.down);
    c.data.datasets[1].data = devs.map((d) => d.up);
    c.data.datasets[2].data = devs.map((d) => d.int);
    c.update('none');
}

function renderApps() {
    const { top, rest } = topN([...S.apps.entries()], 9);
    if (rest > 0) top.push(['その他', rest]);
    const total = top.reduce((s, e) => s + e[1], 0) || 1;
    const c = charts.apps;
    c.data.labels = top.map((e) => e[0]);
    c.data.datasets[0].data = top.map((e) => e[1]);
    c.$pct = top.map((e) => `${((e[1] / total) * 100).toFixed(1)}%`);
    c.update('none');
}

function renderRemotes() {
    const top = [...S.remotes.entries()].sort((a, b) => b[1].bytes - a[1].bytes).slice(0, 10);
    const c = charts.remotes;
    c.$full = top.map(([ip]) => (S.names.get(ip) ? `${S.names.get(ip)}\n${ip}` : ip));
    const max = labelBudget(c);
    c.data.labels = top.map(([ip]) => shortLabel(S.names.get(ip) || ip, max));
    c.data.datasets[0].data = top.map(([, r]) => r.bytes);
    c.update('none');
}

function renderSizes() {
    charts.sizes.data.datasets[0].data = [...S.sizes];
    charts.sizes.update('none');
}

function renderKpis(now) {
    // Average over the last 3 complete seconds to smooth batch arrival.
    let d = 0, u = 0, pk = 0;
    for (let k = 1; k <= 3; k++) {
        const b = S.secs.get(Math.floor(now) - k);
        if (b) { d += b.down; u += b.up; pk += b.pkts; }
    }
    let peakD = 0, peakU = 0;
    const from = Math.floor(now) - S.range;
    for (const [sec, b] of S.secs) {
        if (sec < now - KEEP_SECONDS) { S.secs.delete(sec); continue; }
        if (sec >= from) { peakD = Math.max(peakD, b.down); peakU = Math.max(peakU, b.up); }
    }
    $('kpiDown').textContent = fmtBits((d * 8) / 3);
    $('kpiUp').textContent = fmtBits((u * 8) / 3);
    const rangeLabel = S.range === 60 ? '1分' : S.range === 300 ? '5分' : '15分';
    $('kpiDownPeak').textContent = `ピーク ${fmtBits(peakD * 8)}（${rangeLabel}）`;
    $('kpiUpPeak').textContent = `ピーク ${fmtBits(peakU * 8)}（${rangeLabel}）`;
    $('kpiPps').textContent = fmtInt(pk / 3);
    $('kpiTotal').textContent = `累計 ${fmtInt(S.totalPkts)}`;

    let active = 0;
    for (const f of S.flows.values()) if (now - f.last <= ACTIVE_WINDOW) active++;
    $('kpiFlows').textContent = fmtInt(active);
    $('flowCount').textContent = fmtInt(active);

    let devs = 0;
    for (const dev of S.devices.values()) if (now - dev.last <= 300) devs++;
    $('kpiDevices').textContent = fmtInt(devs);
    $('kpiDevicesSub').textContent = `直近5分（累計 ${fmtInt(S.devices.size)}）`;

    const unread = S.alerts.filter((a) => a.unread).length;
    $('kpiAlerts').textContent = fmtInt(unread);
    $('kpiAlerts').closest('.kpi').classList.toggle('alerting', unread > 0);
    $('kpiDropped').textContent = `取りこぼし ${fmtInt(S.dropped)}`;
}

// ---------- Network graph (d3-force) ----------
const graph = { nodes: new Map(), sim: null, svg: null, gLinks: null, gNodes: null, gLabels: null, w: 0, h: 0 };

function setupGraph() {
    const svg = d3.select('#graph');
    graph.svg = svg;
    const root = svg.append('g');
    graph.gLinks = root.append('g').attr('stroke-linecap', 'round');
    graph.gNodes = root.append('g');
    graph.gLabels = root.append('g');
    graph.empty = svg.append('text').attr('class', 'graph-empty').attr('text-anchor', 'middle').text('通信を待っています…');
    svg.call(d3.zoom().scaleExtent([0.3, 4]).on('zoom', (e) => root.attr('transform', e.transform)));
    graph.sim = d3.forceSimulation()
        .force('link', d3.forceLink().id((d) => d.id).distance((l) => 60 + 40 * (1 - l.w)).strength(0.4))
        .force('charge', d3.forceManyBody().strength(-180))
        .force('collide', d3.forceCollide().radius((d) => d.r + 4))
        .force('x', d3.forceX().strength(0.04))
        .force('y', d3.forceY().strength(0.06))
        .on('tick', graphTick);
    resizeGraph();
    new ResizeObserver(resizeGraph).observe($('graphBox'));
}
function resizeGraph() {
    const box = $('graphBox').getBoundingClientRect();
    graph.w = box.width; graph.h = box.height;
    graph.svg.attr('viewBox', [-box.width / 2, -box.height / 2, box.width, box.height]);
    graph.empty.attr('x', 0).attr('y', 0);
}
function graphTick() {
    graph.gLinks.selectAll('line')
        .attr('x1', (d) => d.source.x).attr('y1', (d) => d.source.y)
        .attr('x2', (d) => d.target.x).attr('y2', (d) => d.target.y);
    graph.gNodes.selectAll('circle').attr('cx', (d) => d.x).attr('cy', (d) => d.y);
    graph.gLabels.selectAll('text').attr('x', (d) => d.x).attr('y', (d) => d.y - d.r - 4);
}

function graphNodeOf(ip) {
    const c = classify(ip);
    if (c === 'none') return null;   // 0.0.0.0, ::, non-IP
    if (c === 'self') return { id: 'self', kind: 'self', label: S.hostname || 'router', title: hostLabel(ip) };
    if (c === 'lan') {
        const key = S.ipToDevice.get(ip) || `ip:${ip}`;
        const dev = S.devices.get(key);
        return { id: `dev:${key}`, kind: 'lan', label: dev ? deviceLabel(dev) : ip, title: dev ? `${deviceLabel(dev)}\n${[...dev.ips].slice(0, 3).join(', ')}` : ip };
    }
    if (c === 'mcast') return { id: `m:${ip}`, kind: 'lan', label: ip, title: `${ip}（マルチキャスト）` };
    return { id: ip, kind: 'wan', label: S.names.get(ip) || ip, title: S.names.get(ip) ? `${S.names.get(ip)}\n${ip}` : ip };
}

function renderGraph(now) {
    const pairs = new Map();
    const meta = new Map();
    for (const f of S.flows.values()) {
        if (now - f.last > GRAPH_WINDOW) continue;
        const bytes = flowWindowBytes(f, Math.floor(now), GRAPH_WINDOW);
        if (!bytes) continue;
        const a = graphNodeOf(f.local.ip), b = graphNodeOf(f.remote.ip);
        if (!a || !b || a.id === b.id) continue;
        if (f.name && b.kind === 'wan') { b.label = f.name; b.title = `${f.name}\n${f.remote.ip}`; }
        meta.set(a.id, a); meta.set(b.id, b);
        const k = a.id < b.id ? `${a.id}\u0000${b.id}` : `${b.id}\u0000${a.id}`;
        pairs.set(k, (pairs.get(k) || 0) + bytes);
    }
    const top = [...pairs.entries()].sort((x, y) => y[1] - x[1]).slice(0, 40);
    graph.empty.style('display', top.length ? 'none' : null);

    const nodeBytes = new Map();
    for (const [k, v] of top) for (const id of k.split('\u0000')) nodeBytes.set(id, (nodeBytes.get(id) || 0) + v);
    const maxNode = Math.max(1, ...nodeBytes.values());
    const maxLink = Math.max(1, ...top.map((e) => e[1]));
    const rScale = d3.scaleSqrt().domain([0, maxNode]).range([4, 22]);
    const wScale = d3.scaleSqrt().domain([0, maxLink]).range([1, 9]);

    // Reuse node objects so positions persist between updates.
    const next = new Map();
    for (const [id, bytes] of nodeBytes) {
        const m = meta.get(id);
        const n = graph.nodes.get(id) || { id, x: (Math.random() - 0.5) * 50, y: (Math.random() - 0.5) * 50 };
        Object.assign(n, m, { bytes, r: rScale(bytes) });
        next.set(id, n);
    }
    graph.nodes = next;
    const nodes = [...next.values()];
    const links = top.map(([k, v]) => {
        const [s, t] = k.split('\u0000');
        return { source: s, target: t, bytes: v, w: v / maxLink, width: wScale(v) };
    });
    const labelled = new Set(nodes.slice().sort((a, b) => b.bytes - a.bytes).slice(0, 14).map((n) => n.id));

    graph.gLinks.selectAll('line').data(links, (d) => `${d.source.id ?? d.source}-${d.target.id ?? d.target}`)
        .join('line')
        .attr('stroke', cssVar('--axis'))
        .attr('stroke-opacity', 0.9)
        .attr('stroke-width', (d) => d.width)
        .on('mousemove', (e, d) => showTip(e, `<b>${esc(trunc(d.source.label, 40))}</b> ⇄ <b>${esc(trunc(d.target.label, 40))}</b><div class="tt-row"><span>直近2分</span><span>${fmtBytes(d.bytes)}</span></div>`))
        .on('mouseleave', hideTip);

    graph.gNodes.selectAll('circle').data(nodes, (d) => d.id)
        .join((enter) => enter.append('circle').call(d3.drag()
            .on('start', (e, d) => { if (!e.active) graph.sim.alphaTarget(0.2).restart(); d.fx = d.x; d.fy = d.y; })
            .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
            .on('end', (e, d) => { if (!e.active) graph.sim.alphaTarget(0); d.fx = null; d.fy = null; })))
        .attr('r', (d) => d.r)
        .attr('fill', (d) => cssVar(d.kind === 'self' ? '--s-self' : d.kind === 'lan' ? '--s-lan' : '--s-wan'))
        .attr('stroke', cssVar('--surface'))
        .attr('stroke-width', 2)
        .on('mousemove', (e, d) => showTip(e, `${d.title.split('\n').map((l, i) => (i ? `<div class="tt-row"><span>${esc(l)}</span></div>` : `<b>${esc(l)}</b>`)).join('')}<div class="tt-row"><span>直近2分</span><span>${fmtBytes(d.bytes)}</span></div>`))
        .on('mouseleave', hideTip);

    graph.gLabels.selectAll('text').data(nodes.filter((n) => labelled.has(n.id)), (d) => d.id)
        .join('text')
        .attr('class', 'node-label')
        .attr('text-anchor', 'middle')
        .text((d) => trunc(d.label, 26));

    graph.sim.nodes(nodes);
    graph.sim.force('link').links(links);
    // Re-heat only when the topology changed; otherwise let it settle and stop.
    const sig = `${nodes.map((n) => n.id).sort().join(',')}|${top.map((e) => e[0]).sort().join(',')}`;
    if (sig !== graph.sig) {
        graph.sig = sig;
        graph.sim.alpha(Math.max(graph.sim.alpha(), 0.25)).restart();
    } else {
        graphTick();
    }
}

// ---------- Tooltip ----------
const tip = $('tooltip');
function showTip(e, html) {
    tip.innerHTML = html;
    tip.hidden = false;
    const pad = 14, r = tip.getBoundingClientRect();
    let x = e.clientX + pad, y = e.clientY + pad;
    if (x + r.width > innerWidth - 8) x = e.clientX - r.width - pad;
    if (y + r.height > innerHeight - 8) y = e.clientY - r.height - pad;
    tip.style.left = `${x}px`; tip.style.top = `${y}px`;
}
function hideTip() { tip.hidden = true; }

// ---------- Search ----------
function matches(...fields) {
    if (!S.search) return true;
    const hay = fields.filter((v) => v !== undefined && v !== null).join(' ').toLowerCase();
    return S.search.split(/\s+/).every((term) => hay.includes(term));
}

// ---------- Flows table ----------
function renderFlows(now) {
    const activeOnly = $('activeOnly').checked;
    const nowSec = Math.floor(now);
    const rows = [];
    for (const f of S.flows.values()) {
        if (activeOnly && now - f.last > ACTIVE_WINDOW) continue;
        const localName = hostLabel(f.local.ip);
        const remoteName = f.name || hostLabel(f.remote.ip);
        if (!matches(f.app, f.l4, f.local.ip, f.local.port, localName, f.remote.ip, f.remote.port, remoteName)) continue;
        rows.push({ f, localName, remoteName, rate: (flowWindowBytes(f, nowSec, 5) * 8) / 5 });
    }
    const { col, dir } = S.sort;
    const key = {
        app: (r) => r.f.app, local: (r) => r.localName, remote: (r) => r.remoteName,
        down: (r) => r.f.down, up: (r) => r.f.up, rate: (r) => r.rate, pkts: (r) => r.f.pkts, last: (r) => r.f.last,
    }[col];
    rows.sort((a, b) => {
        const x = key(a), y = key(b);
        return (typeof x === 'string' ? x.localeCompare(y) : x - y) * dir || b.f.last - a.f.last;
    });
    const shown = rows.slice(0, 300);
    $('flowsNote').textContent = `${fmtInt(rows.length)} 件${rows.length > shown.length ? `（上位${shown.length}件を表示）` : ''}`;
    const maxRate = Math.max(1, ...shown.map((r) => r.rate));

    const endpoint = (ip, port, name) => {
        const c = classify(ip);
        const badge = c === 'self' ? 'self-badge' : c === 'wan' ? 'wan-badge' : 'lan-badge';
        const showIp = name !== ip;
        const host = name.includes(':') && port !== undefined && port !== null ? `[${trunc(name, 40)}]` : trunc(name, 42);
        return `<span class="${badge}"></span>${esc(host)}${port !== undefined && port !== null ? `<span class="port">:${esc(port)}</span>` : ''}${showIp ? ` <span class="addr port">${esc(trunc(ip, 40))}</span>` : ''}`;
    };

    const html = shown.map((r) => {
        const f = r.f;
        const open = S.expanded.has(f.id);
        let out = `<tr class="flow-row${open ? ' open' : ''}" data-id="${f.id}">
            <td><span class="tag">${esc(f.app)}</span></td>
            <td>${endpoint(f.local.ip, f.local.port, r.localName)}</td>
            <td class="arrow">⇄</td>
            <td>${endpoint(f.remote.ip, f.remote.port, r.remoteName)}</td>
            <td class="num">${fmtBytes(f.down)}</td>
            <td class="num">${fmtBytes(f.up)}</td>
            <td class="num bar-cell"><div class="bar" style="width:${((r.rate / maxRate) * 100).toFixed(1)}%"></div><span>${r.rate ? fmtBits(r.rate) : '—'}</span></td>
            <td class="num">${fmtInt(f.pkts)}</td>
            <td class="num">${fmtAgo(now - f.last)}${f.closed ? ' · 終了' : ''}</td>
        </tr>`;
        if (open) {
            const lines = f.recent.slice().reverse().map((p) => `${fmtClock(p.t, true)}  ${withPort(p.s, p.sP)} → ${withPort(p.d, p.dP)}  ${String(p.l).padStart(5)} B  ${p.i}`);
            out += `<tr class="flow-detail"><td colspan="9"><div class="flow-pkts">${esc(lines.join('\n') || '（パケットなし）')}</div></td></tr>`;
        }
        return out;
    }).join('');
    $('flowsTable').tBodies[0].innerHTML = html || '<tr class="empty-row"><td colspan="9">該当するフローはありません</td></tr>';
}

// ---------- Packet log ----------
function renderPackets() {
    const out = [];
    for (let i = S.log.length - 1; i >= 0 && out.length < 300; i--) {
        const p = S.log[i];
        const src = withPort(hostLabel(p.s), p.sP);
        const dst = withPort(hostLabel(p.d), p.dP);
        if (!matches(p.s, p.d, src, dst, p.app, p.i, p.sP, p.dP)) continue;
        out.push(`<tr><td>${fmtClock(p.t, true)}</td><td title="${esc(p.s)}">${esc(trunc(src, 46))}</td><td title="${esc(p.d)}">${esc(trunc(dst, 46))}</td><td>${esc(p.app)}</td><td class="num">${p.l}</td><td class="info">${esc(trunc(p.i, 240))}</td></tr>`);
    }
    $('packetsTable').tBodies[0].innerHTML = out.join('') || '<tr class="empty-row"><td colspan="6">パケットを待っています…</td></tr>';
}

// ---------- Alerts ----------
function renderAlertBadge() {
    const unread = S.alerts.filter((a) => a.unread).length;
    const el = $('alertCount');
    el.textContent = unread;
    el.classList.toggle('hot', unread > 0);
}
function renderAlerts() {
    const list = S.alerts.filter((a) => matches(a.title, a.detail));
    $('alertsList').innerHTML = list.length
        ? list.map((a) => `<li class="alert${a.unread ? ' unread' : ''}" data-sev="${a.sev}">
            <span class="alert-sev">${SEV_ICON[a.sev]} ${SEV_LABEL[a.sev]}</span>
            <span class="alert-title">${esc(a.title)}</span>
            <span class="alert-time">${fmtClock(a.t)}</span>
            <span class="alert-detail">${esc(a.detail)}</span>
          </li>`).join('')
        : '<li class="alerts-empty">アラートはありません</li>';
}

// ---------- Render loop ----------
/** `force`: draw the visible view even while paused (tab switch, search...). */
function render(force = false) {
    const now = nowCapture();
    pruneFlows(now);
    for (const [k, t] of S.cooldown) if (now - t > 2 * 86400) S.cooldown.delete(k);
    renderKpis(now);
    if (S.paused && !force) return;
    if (S.view === 'dash') {
        renderThroughput(now);
        renderDevices(now);
        renderApps();
        renderRemotes();
        renderSizes();
        if (S.graphMode === 'map') geoRender(now); else renderGraph(now);
    } else if (S.view === 'flows') {
        renderFlows(now);
    } else if (S.view === 'packets') {
        renderPackets();
    } else if (S.view === 'alerts') {
        renderAlerts();
    }
}

// ---------- UI wiring ----------
function setGraphMode(mode) {
    S.graphMode = mode;
    for (const b of document.querySelectorAll('#graphModeSeg button')) b.classList.toggle('on', b.dataset.gmode === mode);
    for (const el of document.querySelectorAll('.map-only')) el.hidden = mode !== 'map';
    for (const el of document.querySelectorAll('.graph-only')) el.hidden = mode !== 'graph';
    try { localStorage.setItem('webshark-graph-mode', mode); } catch { /* ignore */ }
    if (mode === 'graph') resizeGraph(); else geoResetBase();
    updateMapActivity();
    render(true);
}
function updateMapActivity() {
    geoSetActive(S.view === 'dash' && S.graphMode === 'map' && !S.paused);
}

function setView(view) {
    S.view = view;
    for (const tab of document.querySelectorAll('.tab')) {
        const on = tab.dataset.view === view;
        tab.classList.toggle('active', on);
        tab.setAttribute('aria-selected', on);
    }
    for (const v of document.querySelectorAll('.view')) {
        const on = v.id === `view-${view}`;
        v.classList.toggle('active', on);
        v.hidden = !on;
    }
    if (view === 'alerts') renderAlerts();
    lanSetActive(view === 'lan');
    if (view === 'lan') lanRender();
    updateMapActivity();
    try { history.replaceState(null, '', `#${view}`); } catch { /* ignore */ }
    render(true);
}

function setPaused(p) {
    S.paused = p;
    const btn = $('pauseBtn');
    btn.setAttribute('aria-pressed', p);
    btn.innerHTML = p ? ICON_PLAY : ICON_PAUSE;
    btn.title = p ? '表示を再開 (Space)' : '表示を一時停止 (Space)';
    updateMapActivity();
}

function clearData() {
    Object.assign(S, {
        totalPkts: 0, dropped: 0, firstT: null, secs: new Map(), devices: new Map(), ipToDevice: new Map(),
        remotes: new Map(), flows: new Map(), apps: new Map(), sizes: [0, 0, 0, 0, 0, 0, 0], log: [],
        alerts: [], cooldown: new Map(), scans: new Map(), expanded: new Set(),
    });
    graph.nodes = new Map();
    renderAlertBadge();
    render(true);
}

function setConnState(state, text) {
    $('conn').dataset.state = state;
    $('connText').textContent = text;
}

async function loadFilter() {
    try {
        const r = await fetch('/api/filter');
        if (r.ok) $('filterInput').value = (await r.json()).tshark_filter || '';
    } catch { /* ignore */ }
}
async function applyFilter(value) {
    const msg = $('filterMsg');
    msg.className = 'filter-msg';
    msg.textContent = '適用中…';
    try {
        const r = await fetch('/api/filter', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tshark_filter: value || null }),
        });
        if (!r.ok) {
            msg.className = 'filter-msg err';
            msg.textContent = `エラー: ${(await r.text()) || r.status}`;
            return;
        }
        msg.className = 'filter-msg ok';
        msg.textContent = value ? '適用しました（表示をリセット）' : 'フィルタを解除しました';
        clearData();
    } catch (e) {
        msg.className = 'filter-msg err';
        msg.textContent = `エラー: ${e.message}`;
    }
}

function applyTheme(theme) {
    if (theme) document.documentElement.dataset.theme = theme;
    else delete document.documentElement.dataset.theme;
    for (const c of Object.values(charts)) c.update('none');
    render(true);
}

function init() {
    try {
        const t = localStorage.getItem('webshark-theme');
        if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
    } catch { /* storage unavailable */ }

    makeCharts();
    setupGraph();
    geoInit();
    lanInit();

    for (const tab of document.querySelectorAll('.tab')) tab.addEventListener('click', () => setView(tab.dataset.view));
    for (const btn of document.querySelectorAll('#graphModeSeg button')) {
        btn.addEventListener('click', () => setGraphMode(btn.dataset.gmode));
    }
    for (const btn of document.querySelectorAll('.seg button[data-range]')) {
        btn.addEventListener('click', () => {
            S.range = Number(btn.dataset.range);
            for (const b of document.querySelectorAll('.seg button[data-range]')) b.classList.toggle('on', b === btn);
            render(true);
        });
    }
    $('pauseBtn').addEventListener('click', () => setPaused(!S.paused));
    $('clearBtn').addEventListener('click', clearData);
    $('themeBtn').addEventListener('click', () => {
        const dark = getComputedStyle(document.documentElement).colorScheme.includes('dark');
        const next = dark ? 'light' : 'dark';
        try { localStorage.setItem('webshark-theme', next); } catch { /* ignore */ }
        applyTheme(next);
    });
    $('search').addEventListener('input', (e) => {
        S.search = e.target.value.trim().toLowerCase();
        render(true);
        if (S.view === 'lan') lanRender();
    });
    $('activeOnly').addEventListener('change', () => render(true));
    $('filterForm').addEventListener('submit', (e) => { e.preventDefault(); applyFilter($('filterInput').value.trim()); });
    $('filterReset').addEventListener('click', () => { $('filterInput').value = ''; applyFilter(''); });
    $('alertsClear').addEventListener('click', () => { for (const a of S.alerts) a.unread = false; renderAlertBadge(); renderAlerts(); });

    for (const th of document.querySelectorAll('#flowsTable th[data-sort]')) {
        th.addEventListener('click', () => {
            const col = th.dataset.sort;
            S.sort = { col, dir: S.sort.col === col ? -S.sort.dir : (['app', 'local', 'remote'].includes(col) ? 1 : -1) };
            for (const h of document.querySelectorAll('#flowsTable th')) h.classList.remove('sorted', 'asc', 'desc');
            th.classList.add('sorted', S.sort.dir > 0 ? 'asc' : 'desc');
            render(true);
        });
    }
    $('flowsTable').tBodies[0].addEventListener('click', (e) => {
        const row = e.target.closest('tr.flow-row');
        if (!row) return;
        const id = Number(row.dataset.id);
        if (S.expanded.has(id)) S.expanded.delete(id); else S.expanded.add(id);
        renderFlows(nowCapture());
    });

    document.addEventListener('keydown', (e) => {
        const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName);
        if (e.altKey && /^[1-5]$/.test(e.key)) { e.preventDefault(); setView(['dash', 'lan', 'flows', 'packets', 'alerts'][Number(e.key) - 1]); return; }
        if (typing) { if (e.key === 'Escape') document.activeElement.blur(); return; }
        if (e.key === '/') { e.preventDefault(); $('search').focus(); }
        else if (e.key === ' ') { e.preventDefault(); setPaused(!S.paused); }
    });
    matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => applyTheme(document.documentElement.dataset.theme));

    let mode = 'map';
    try { if (localStorage.getItem('webshark-graph-mode') === 'graph') mode = 'graph'; } catch { /* ignore */ }
    setGraphMode(mode);

    const initial = location.hash.slice(1);
    setView(['dash', 'lan', 'flows', 'packets', 'alerts'].includes(initial) ? initial : 'dash');
    loadFilter();
    renderAlertBadge();
    setInterval(render, 1000);
    setInterval(pollNames, 5000);
}

init();
