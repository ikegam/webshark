'use strict';

// =====================================================================
// LAN view: what this gateway can see of the local network.
// Data comes from GET /api/lan (server-side inventory accumulated since the
// service started + the gateway's interface / route / neighbour tables).
// Uses helpers from app.js (esc, fmtBytes, fmtAgo, trunc, PORTS, S) at call time.
// =====================================================================

const LAN_POLL_MS = 5000;
const LAN_ONLINE_S = 300;

const LAN = {
    data: null,
    error: null,
    timer: null,
    selected: null,       // device key (mac)
    hover: null,
    inflight: false,
};

const LAN_GROUPS = [
    ['infra', 'ネットワーク機器'],
    ['server', 'サーバー・NAS'],
    ['pc', 'PC'],
    ['phone', 'スマホ・タブレット'],
    ['media', 'TV・メディア'],
    ['printer', 'プリンタ'],
    ['iot', 'IoT・家電'],
    ['game', 'ゲーム機'],
    ['other', 'その他・不明'],
];

const MDNS_SERVICES = {
    _airplay: 'AirPlay', _raop: 'AirPlay音声', _googlecast: 'Chromecast', _ipp: '印刷 (IPP)', _ipps: '印刷 (IPPS)',
    _printer: '印刷 (LPD)', '_pdl-datastream': '印刷 (RAW)', _uscan: 'スキャナ', _uscans: 'スキャナ', _scanner: 'スキャナ',
    _smb: 'ファイル共有 (SMB)', _afpovertcp: 'ファイル共有 (AFP)', _nfs: 'ファイル共有 (NFS)', _adisk: 'Time Machine',
    _ssh: 'SSH', '_sftp-ssh': 'SFTP', _http: 'Web', _https: 'Web (HTTPS)', _hap: 'HomeKit', _homekit: 'HomeKit',
    '_companion-link': 'Apple連携', '_sleep-proxy': 'スリーププロキシ', '_spotify-connect': 'Spotify Connect',
    _matter: 'Matter', _matterc: 'Matter', '_device-info': 'デバイス情報', _workstation: 'ワークステーション',
    _qdiscover: 'QNAP', _rfb: '画面共有', _nvstream: 'NVIDIA GameStream', _airport: 'AirMac', _daap: 'iTunes共有',
    _touchable: 'Apple TVリモート', _mediaremotetv: 'Apple TVリモート', '_amzn-wplay': 'Fire TV', _rdlink: 'Apple連携',
};

// ---------- data ----------
async function lanFetch() {
    if (LAN.inflight) return;
    LAN.inflight = true;
    try {
        const r = await fetch('/api/lan');
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        LAN.data = await r.json();
        LAN.error = null;
    } catch (e) {
        LAN.error = e.message;
    }
    LAN.inflight = false;
    if (S.view === 'lan') lanRender();
}

function lanSetActive(on) {
    if (on && !LAN.timer) {
        lanFetch();
        LAN.timer = setInterval(lanFetch, LAN_POLL_MS);
    } else if (!on && LAN.timer) {
        clearInterval(LAN.timer);
        LAN.timer = null;
    }
}

function serviceLabel(svc) {
    const base = svc.replace(/\._(tcp|udp)$/, '');
    return MDNS_SERVICES[base] || base.replace(/^_/, '');
}
function portLabel(key) {
    const [proto, port] = key.split('/');
    const name = PORTS[proto.toUpperCase()]?.[port];
    return name ? `${name} (${port})` : `${proto.toUpperCase()} ${port}`;
}

/** Merge the inventory with neighbour-table-only devices; derive labels. */
function lanDevices(d) {
    const now = d.now;
    // Only neighbours on LAN interfaces; the WAN side (e.g. the ISP's IPv6
    // router on the uplink) is not part of the LAN.
    const lanIfs = new Set(d.interfaces.filter((i) => i.role === 'lan').map((i) => i.name));
    const neighByMac = new Map();
    for (const n of d.neighbors) {
        if (!lanIfs.has(n.dev)) continue;
        if (!neighByMac.has(n.mac)) neighByMac.set(n.mac, []);
        neighByMac.get(n.mac).push(n);
    }
    // Merge CDP and LLDP: CDP names the model, LLDP the OS / management address.
    const l2ByMac = new Map(d.l2.map((n) => {
        const c = n.cdp || {}, l = n.lldp || {};
        return [n.mac, {
            protos: [n.cdp && 'CDP', n.lldp && 'LLDP'].filter(Boolean).join(' / '),
            name: c.name || l.name, port: c.port || l.port, vlan: c.vlan || l.vlan, mgmt: l.mgmt || c.mgmt,
            model: c.platform ? c.platform.replace(/^cisco\s+/i, '') : null, os: l.platform || null,
        }];
    }));
    const ownMacs = new Set(d.interfaces.map((i) => (i.mac || '').toLowerCase()));
    const devs = new Map();
    for (const dev of d.devices) devs.set(dev.mac, { ...dev, neigh: neighByMac.get(dev.mac) || [], fromTraffic: true });
    for (const [mac, list] of neighByMac) {
        if (devs.has(mac) || ownMacs.has(mac)) continue;
        const ips = {};
        for (const n of list) ips[n.ip] = null;
        devs.set(mac, {
            mac, ips, names: [], dhcp_name: null, vendor: d.neighbor_vendors[mac] || null, random_mac: (parseInt(mac.slice(0, 2), 16) & 2) !== 0,
            first: null, last: null, up: 0, down: 0, internal: 0, pkts: 0, ports: {}, services: [], neigh: list, fromTraffic: false,
        });
    }
    for (const dev of devs.values()) {
        dev.l2 = l2ByMac.get(dev.mac) || null;
        dev.vrrp = dev.mac.startsWith('00:00:5e:00:01') || dev.mac.startsWith('00:00:5e:00:02');
        // Addresses from traffic plus the neighbour table (a quiet device may
        // only be known there, e.g. its IPv4 while it talks over IPv6).
        for (const n of dev.neigh) if (!(n.ip in dev.ips)) dev.ips[n.ip] = null;
        const addrs = Object.keys(dev.ips);
        dev.v4 = addrs.filter((a) => parseV4(a) !== null).sort((a, b) => parseV4(a) - parseV4(b));
        dev.v6 = addrs.filter((a) => a.includes(':'));
        const clientNames = addrs.map((a) => S.lanNames.get(a) || S.names.get(a)).filter(Boolean);
        const name = dev.l2?.name || dev.names[0] || clientNames[0] || dev.dhcp_name || null;
        dev.name = name ? cleanHost(name) : null;
        dev.label = dev.name || dev.v4[0] || dev.v6[0] || dev.mac;
        const reach = dev.neigh.some((n) => ['REACHABLE', 'DELAY', 'PROBE'].includes(n.state));
        dev.online = reach || (dev.last !== null && now - dev.last <= LAN_ONLINE_S);
        dev.total = dev.up + dev.down + dev.internal;
        dev.category = lanCategory(dev);
    }
    return [...devs.values()];
}

function lanCategory(dev) {
    const vendor = (dev.vendor || '').toLowerCase();
    const names = [dev.name, dev.dhcp_name, ...(dev.names || [])].filter(Boolean).join(' ').toLowerCase();
    const svc = new Set((dev.services || []).map((s) => s.replace(/\._(tcp|udp)$/, '')));
    const ports = new Set(Object.keys(dev.ports || {}).map((k) => Number(k.split('/')[1])));
    const has = (...xs) => xs.some((x) => svc.has(x));
    const v = (re) => re.test(vendor);
    const n = (re) => re.test(names);

    if (dev.l2 || dev.vrrp || v(/cisco|aruba|ubiquiti|juniper|allied telesis|yamaha|fortinet|mikrotik|ruckus|netgear|tp-link systems|buffalo inc|nec platforms/)) {
        if (!v(/buffalo/) || !(has('_smb', '_afpovertcp') || n(/nas|ls[0-9]/))) return 'infra';
    }
    if (has('_ipp', '_ipps', '_printer', '_pdl-datastream', '_uscan') || ports.has(9100) || ports.has(631) ||
        v(/brother|canon|seiko epson|kyocera|ricoh|xerox|hp inc/) || n(/^hp[0-9a-f]{6}|printer|prn/)) return 'printer';
    if (v(/qnap|synology|i-o data|asustor|western digital|buffalo/) || n(/nas|truenas|qnap|synology/) ||
        has('_smb', '_afpovertcp', '_nfs', '_adisk', '_qdiscover') || ports.has(445) || ports.has(2049)) return 'server';
    if (v(/nintendo|sony interactive|valve/) || n(/switch|ps[45]|xbox|steamdeck/)) return 'game';
    if (has('_googlecast', '_amzn-wplay', '_touchable', '_mediaremotetv') || n(/tv|chromecast|bravia|fire.?tv|roku|appletv|apple-tv/) ||
        v(/roku|lg electronics|sharp|panasonic|tcl/)) return 'media';
    if (v(/espressif|tuya|candy house|shelly|signify|philips lighting|nature inc|switchbot|ring llc|wyze|xiaomi|lumi|sonoff|itead|amazon technologies|murata/)) return 'iot';
    if (n(/iphone|ipad|pixel|android|galaxy|tablet|phone|xperia|aquos/) || has('_companion-link') && !has('_ssh', '_sftp-ssh', '_smb')) return 'phone';
    if (has('_ssh', '_sftp-ssh', '_workstation', '_rfb') || n(/macbook|imac|mac-?mini|desktop|laptop|pc|lllm/) ||
        v(/intel corp|realtek|dell|lenovo|asustek|micro-star|giga-byte|hewlett packard|liteon|azurewave|hon hai|framework|apple/)) {
        return v(/apple/) && !has('_ssh', '_sftp-ssh', '_smb', '_rfb') && !n(/mac/) ? 'phone' : 'pc';
    }
    if (dev.random_mac) return 'phone';
    return 'other';
}

// ---------- rendering ----------
function lanRender() {
    const root = document.getElementById('lanRoot');
    if (!root) return;
    const d = LAN.data;
    if (!d) {
        root.innerHTML = `<div class="lan-empty">${LAN.error ? `読み込みに失敗しました: ${esc(LAN.error)}` : '読み込み中…'}</div>`;
        return;
    }
    const devs = lanDevices(d);
    const q = S.search;
    const shown = devs.filter((dev) => !q || matches(dev.label, dev.mac, dev.vendor, ...dev.v4, ...dev.v6, dev.dhcp_name, LAN_GROUPS.find((g) => g[0] === dev.category)?.[1]));
    const byGroup = new Map(LAN_GROUPS.map(([k]) => [k, []]));
    for (const dev of shown) byGroup.get(dev.category).push(dev);
    for (const list of byGroup.values()) list.sort((a, b) => (b.online - a.online) || (b.total - a.total) || a.label.localeCompare(b.label));
    const maxTotal = Math.max(1, ...devs.map((x) => x.total));

    // summary
    const online = devs.filter((x) => x.online).length;
    const internal = devs.reduce((s, x) => s + x.internal, 0);
    const aps = devs.filter((x) => x.l2).length;
    const since = d.since ? fmtAgo(d.now - d.since).replace('前', '') : '—';

    const wan = d.interfaces.filter((i) => i.role === 'wan');
    const lanIfs = d.interfaces.filter((i) => i.role === 'lan');
    const other = d.interfaces.filter((i) => i.role !== 'wan' && i.role !== 'lan');
    const addrList = (i, scope) => i.addrs.filter((a) => !scope || a.scope === scope).map((a) => `${a.addr}/${a.prefix}`);
    const ifLine = (i) => `<div class="if-row"><span class="if-name">${esc(i.name)}</span><span class="if-addrs">${addrList(i, 'global').map(esc).join('<br>') || '<span class="muted">（グローバルアドレスなし）</span>'}</span></div>`;

    const card = (dev) => {
        const sel = LAN.selected === dev.mac ? ' selected' : '';
        const w = (x) => `${((x / maxTotal) * 100).toFixed(1)}%`;
        const sub = dev.vrrp ? 'VRRP 仮想MAC' : dev.l2?.model ? `${trunc(dev.vendor || '', 14)} ${dev.l2.model}`.trim()
            : dev.vendor ? trunc(dev.vendor, 30) : dev.random_mac ? 'ランダムMAC' : '—';
        const addr = dev.v4[0] || dev.v6[0] || '';
        return `<button class="lan-card${dev.online ? '' : ' offline'}${sel}" data-mac="${esc(dev.mac)}" title="${esc(dev.mac)}">
            <span class="lan-card-top"><span class="status-dot${dev.online ? ' on' : ''}"></span><span class="lan-card-name">${esc(trunc(dev.label, 28))}</span></span>
            <span class="lan-card-addr">${esc(addr)}${dev.v6.length ? ` <span class="badge">v6×${dev.v6.length}</span>` : ''}</span>
            <span class="lan-card-sub">${esc(sub)}</span>
            <span class="lan-card-bar" aria-hidden="true"><i class="b-down" style="width:${w(dev.down)}"></i><i class="b-up" style="width:${w(dev.up)}"></i><i class="b-int" style="width:${w(dev.internal)}"></i></span>
        </button>`;
    };

    const groups = LAN_GROUPS.filter(([k]) => byGroup.get(k).length).map(([k, label]) => `
        <section class="lan-group" data-group="${k}">
            <h3>${label} <span class="muted">${byGroup.get(k).length}</span></h3>
            <div class="lan-cards">${byGroup.get(k).map(card).join('')}</div>
        </section>`).join('');

    root.innerHTML = `
        <div class="lan-summary">
            <div class="kpi"><div class="kpi-label">LAN機器</div><div class="kpi-value">${online} <span class="kpi-unit">/ ${devs.length}</span></div><div class="kpi-sub">オンライン / 確認済み</div></div>
            <div class="kpi"><div class="kpi-label">LAN内通信（観測分）</div><div class="kpi-value">${fmtBytes(internal)}</div><div class="kpi-sub">${esc(d.hostname || 'ルーター')}との通信など・${esc(since)}の累計</div></div>
            <div class="kpi"><div class="kpi-label">アクセスポイント等</div><div class="kpi-value">${aps}</div><div class="kpi-sub">CDP/LLDPで検出</div></div>
            <div class="kpi"><div class="kpi-label">MAC ベンダー情報</div><div class="kpi-value small">${d.oui ? '利用可' : '未導入'}</div><div class="kpi-sub">${d.oui ? 'IEEE OUI' : 'make data で取得'}</div></div>
        </div>
        <div class="lan-layout">
            <div class="topo" id="lanTopo">
                <div class="topo-tier">
                    <div class="topo-node net">
                        <div class="topo-title">インターネット</div>
                        ${wan.map(ifLine).join('') || '<div class="muted">WAN インターフェースなし</div>'}
                        ${d.routes.map((r) => `<div class="if-route">既定経路 ${r.family === 'inet6' ? 'IPv6' : 'IPv4'}: ${esc(r.dev || '')}${r.via ? ` via ${esc(r.via)}` : ''}</div>`).join('')}
                    </div>
                </div>
                <div class="topo-tier">
                    <div class="topo-node router" id="lanRouter">
                        <div class="topo-title">${esc(d.hostname || 'ルーター')} <span class="muted">（このゲートウェイ）</span></div>
                        ${lanIfs.map(ifLine).join('')}
                        ${other.length ? `<div class="if-other">その他: ${other.map((i) => `${esc(i.name)}${i.role === 'down' ? '（停止）' : ''}`).join('、')}</div>` : ''}
                    </div>
                </div>
                <div class="lan-bus" aria-hidden="true"></div>
                <div class="lan-groups">${groups || '<div class="lan-empty">該当する機器はありません</div>'}</div>
                <svg class="topo-links" id="lanLinks" aria-hidden="true"></svg>
            </div>
            <aside class="lan-detail" id="lanDetail">${lanDetail(devs, d)}</aside>
        </div>
        <p class="lan-note">${esc(d.hostname || 'ルーター')} から見える範囲の情報です（自身のLANポートに届くパケット、ARP/NDP表、CDP/LLDP、mDNS、DHCP）。機器同士の直接の通信（例: PC⇄NAS）はスイッチ内で完結するため ${esc(d.hostname || 'ルーター')} には届かず、観測できた分だけを線で表示しています。スイッチ配下の配線や、どのAPに接続しているかも分かりません。通信量はサービス起動以降の累計です。</p>`;

    lanDrawLinks(d, devs);
}

function lanDetail(devs, d) {
    const dev = devs.find((x) => x.mac === LAN.selected);
    if (!dev) return '<div class="lan-detail-empty">機器を選択すると詳細を表示します</div>';
    const cat = LAN_GROUPS.find((g) => g[0] === dev.category)?.[1];
    const rows = [];
    const row = (k, v) => rows.push(`<tr><th>${k}</th><td>${v}</td></tr>`);
    row('種類（推定）', esc(cat));
    row('状態', dev.online ? '<span class="ok">オンライン</span>' : `オフライン${dev.last ? `（最終 ${fmtAgo(d.now - dev.last)}）` : ''}`);
    row('MAC', `<span class="mono">${esc(dev.mac)}</span>${dev.random_mac ? ' <span class="badge">ランダム</span>' : ''}`);
    row('メーカー', esc(dev.vrrp ? '—（VRRP 仮想MAC）' : dev.vendor || (dev.random_mac ? '（ランダムMACのため不明）' : '不明')));
    if (dev.vrrp) row('備考', 'VRRP 仮想MAC（冗長構成の仮想IP）');
    const ipRows = [...dev.v4, ...dev.v6].map((ip) => {
        const t = dev.ips[ip];
        return `<div class="mono">${esc(ip)}${t ? ` <span class="muted">${fmtAgo(d.now - t)}</span>` : ''}</div>`;
    });
    row('アドレス', ipRows.join('') || '—');
    const names = [...new Set([dev.l2?.name, ...dev.names, dev.dhcp_name].filter(Boolean))];
    if (names.length) row('名前', names.map(esc).join('<br>'));
    if (dev.l2) {
        row(esc(dev.l2.protos), [dev.l2.model && `機種 ${dev.l2.model}`, dev.l2.os, dev.l2.port && `ポート ${dev.l2.port}`,
            dev.l2.vlan && `VLAN ${dev.l2.vlan}`, dev.l2.mgmt && `管理 ${dev.l2.mgmt}`].filter(Boolean).map(esc).join('<br>'));
    }
    if (dev.neigh.length) row('ARP/NDP', dev.neigh.map((n) => `<div><span class="mono">${esc(n.ip)}</span> ${esc(n.state)}</div>`).join(''));
    if (dev.services.length) row('mDNS サービス', dev.services.map((s) => `<span class="tag">${esc(serviceLabel(s))}</span>`).join(' '));
    const ports = Object.entries(dev.ports).sort((a, b) => b[1] - a[1]);
    if (ports.length) row('待受を確認したポート', ports.map(([k, c]) => `<span class="tag" title="${c} 回">${esc(portLabel(k))}</span>`).join(' '));
    row('通信量', `↓ ${fmtBytes(dev.down)}　↑ ${fmtBytes(dev.up)}　LAN内 ${fmtBytes(dev.internal)}`);
    if (dev.first) row('初観測', `${fmtAgo(d.now - dev.first)}`);
    const peers = d.pairs.filter((p) => p.a === dev.mac || p.b === dev.mac)
        .map((p) => ({ mac: p.a === dev.mac ? p.b : p.a, bytes: p.bytes, last: p.last }))
        .sort((a, b) => b.bytes - a.bytes).slice(0, 8);
    if (peers.length) {
        row('LAN内の通信相手', peers.map((p) => {
            const other = devs.find((x) => x.mac === p.mac);
            return `<div class="peer"><button class="link" data-mac="${esc(p.mac)}">${esc(trunc(other ? other.label : p.mac, 26))}</button><span>${fmtBytes(p.bytes)}</span></div>`;
        }).join(''));
    }
    return `<h3>${esc(dev.label)}</h3><table class="kv">${rows.join('')}</table>`;
}

/** Overlay: router -> bus line, and LAN-internal traffic arcs between cards. */
function lanDrawLinks(d, devs) {
    const topo = document.getElementById('lanTopo');
    const svgEl = document.getElementById('lanLinks');
    if (!topo || !svgEl) return;
    const box = topo.getBoundingClientRect();
    const svg = d3.select(svgEl).attr('width', box.width).attr('height', box.height).attr('viewBox', [0, 0, box.width, box.height]);
    const pos = new Map();
    for (const el of topo.querySelectorAll('.lan-card')) {
        const r = el.getBoundingClientRect();
        pos.set(el.dataset.mac, { x: r.left - box.left + r.width / 2, y: r.top - box.top + r.height / 2, r });
    }
    const recent = d.pairs.filter((p) => pos.has(p.a) && pos.has(p.b)).sort((a, b) => b.bytes - a.bytes).slice(0, 40);
    const maxB = Math.max(1, ...recent.map((p) => p.bytes));
    const wScale = d3.scaleSqrt().domain([0, maxB]).range([1, 7]);
    const focus = LAN.hover || LAN.selected;
    svg.selectAll('path.pair').data(recent, (p) => `${p.a}|${p.b}`)
        .join('path')
        .attr('class', (p) => {
            const active = d.now - p.last < 60 ? ' active' : '';
            const dim = focus && p.a !== focus && p.b !== focus ? ' dim' : '';
            const hi = focus && (p.a === focus || p.b === focus) ? ' hi' : '';
            return `pair${active}${dim}${hi}`;
        })
        .attr('stroke-width', (p) => wScale(p.bytes))
        .attr('d', (p) => {
            const a = pos.get(p.a), b = pos.get(p.b);
            const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
            const dist = Math.hypot(b.x - a.x, b.y - a.y);
            // Bow the arc sideways so it does not run straight through other cards.
            const bow = Math.min(120, dist * 0.35) + 20;
            const nx = -(b.y - a.y) / (dist || 1), ny = (b.x - a.x) / (dist || 1);
            return `M${a.x},${a.y} Q${mx + nx * bow},${my + ny * bow} ${b.x},${b.y}`;
        });
}

function lanInit() {
    const root = document.getElementById('lanRoot');
    root.addEventListener('click', (e) => {
        const el = e.target.closest('[data-mac]');
        if (!el) return;
        LAN.selected = LAN.selected === el.dataset.mac && el.classList.contains('lan-card') ? null : el.dataset.mac;
        lanRender();
    });
    root.addEventListener('mouseover', (e) => {
        const el = e.target.closest('.lan-card');
        const mac = el ? el.dataset.mac : null;
        if (mac !== LAN.hover) { LAN.hover = mac; if (LAN.data) lanDrawLinks(LAN.data, lanDevices(LAN.data)); }
    });
    root.addEventListener('mouseleave', () => { LAN.hover = null; if (LAN.data) lanDrawLinks(LAN.data, lanDevices(LAN.data)); });
    new ResizeObserver(() => { if (S.view === 'lan' && LAN.data) lanDrawLinks(LAN.data, lanDevices(LAN.data)); }).observe(root);
}
