'use strict';

// =====================================================================
// GeoIP map: two panes side by side.
//   - world (70%): the whole world, Pacific-centred, connections abroad
//   - japan (30%): close-up of Japan, domestic connections
// Arcs run from this gateway ("home") to each remote location, with
// particles flying in the traffic direction (download = remote -> home,
// upload = home -> remote). Uses helpers/state from app.js at call time.
// =====================================================================

const WORLD_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-50m.json';
const MAP_MAX_LOCATIONS = 40;
const PARTICLE_SPEED = 140;       // px per second
const FALLBACK_HOME = { lat: 35.68, lon: 139.76, cc: 'JP', country: '日本', city: 'Tokyo' };
// Japan's four main islands plus Okinawa; far-flung islets would zoom the pane out.
const JAPAN_EXTENT = { type: 'MultiPoint', coordinates: [[127.5, 26.0], [146.2, 45.6]] };

const GEO = {
    enabled: false,
    home: null,
    attribution: '',
    attributionUrl: '',
    cache: new Map(),       // ip -> geo | null
    pending: new Set(),
    inflight: false,
    world: null,            // {land, borders}
    loadError: null,
    locs: [],
    panes: [],
    phases: new Map(),      // pane + loc key + dir -> particle phases
    raf: null,
    lastFrame: 0,
    active: false,
};

// ---------- data ----------
function geoSetContext(g) {
    GEO.enabled = !!(g && g.enabled);
    GEO.home = (g && g.home) || null;
    GEO.attribution = (g && g.attribution) || '';
    GEO.attributionUrl = (g && g.attribution_url) || '';
    const a = document.getElementById('geoAttribution');
    if (a) {
        a.textContent = GEO.attribution;
        a.href = GEO.attributionUrl || '#';
        a.hidden = !GEO.enabled;
    }
    geoResetBase();
}

function geoQueue(ip) {
    if (!GEO.enabled || GEO.cache.has(ip) || GEO.pending.has(ip)) return;
    GEO.pending.add(ip);
}

async function geoFlush() {
    if (GEO.inflight || !GEO.pending.size) return;
    const ips = [...GEO.pending].slice(0, 500);
    GEO.inflight = true;
    try {
        const r = await fetch('/api/geo', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ips }),
        });
        if (r.ok) {
            const res = await r.json();
            for (const ip of ips) { GEO.cache.set(ip, res[ip] || null); GEO.pending.delete(ip); }
            if (GEO.cache.size > 20000) GEO.cache.clear();
        }
    } catch { /* retry next tick */ }
    GEO.inflight = false;
}

async function geoLoadWorld() {
    try {
        const world = await (await fetch(WORLD_URL)).json();
        GEO.world = {
            land: topojson.feature(world, world.objects.land),
            borders: topojson.mesh(world, world.objects.countries, (a, b) => a !== b),
        };
    } catch (e) {
        GEO.loadError = '地図データを読み込めませんでした';
        console.error(e);
    }
    geoResetBase();
}

function geoHome() { return GEO.home || FALLBACK_HOME; }

// ---------- panes ----------
function geoMakePane(id, opts) {
    const box = document.getElementById(id);
    const svg = d3.select(box).select('svg');
    const pane = {
        id, box, svg, ...opts,
        w: 0, h: 0, proj: null, locs: [],
        gBase: svg.append('g').attr('class', 'map-base'),
    };
    pane.gBase.append('path').attr('class', 'map-land');
    pane.gBase.append('path').attr('class', 'map-borders');
    pane.gArcs = svg.append('g').attr('class', 'map-arcs');
    pane.gNodes = svg.append('g');
    pane.gParts = svg.append('g').attr('class', 'map-particles');
    pane.gHome = svg.append('g');
    pane.gLabels = svg.append('g');
    pane.msg = svg.append('text').attr('class', 'graph-empty').attr('text-anchor', 'middle');
    new ResizeObserver(() => { geoLayoutPane(pane); geoDrawPane(pane); }).observe(box);
    return pane;
}

function geoInit() {
    GEO.panes = [
        geoMakePane('mapWorld', {
            // Abroad only; domestic traffic is shown in the Japan pane.
            filter: (l) => l.cc !== 'JP',
            fit: (home) => {
                // Whole world, one map width, latitudes trimmed to inhabited areas.
                const c = home.lon + 15;
                return { type: 'MultiPoint', coordinates: [[c - 179.9, 75], [c + 179.9, -56]] };
            },
            empty: '海外との通信はありません',
            maxLabels: 10,
        }),
        geoMakePane('mapJapan', {
            filter: (l) => l.cc === 'JP',
            fit: () => JAPAN_EXTENT,
            empty: '国内との通信はありません',
            maxLabels: 6,
        }),
    ];
    document.addEventListener('visibilitychange', geoAnimate);
    setInterval(geoFlush, 1500);
    geoLoadWorld();
}

/** Size the pane, fit its projection and draw the land (only on layout changes). */
function geoLayoutPane(pane) {
    const r = pane.box.getBoundingClientRect();
    if (!r.width || !r.height) return;
    pane.w = r.width; pane.h = r.height;
    pane.svg.attr('viewBox', [0, 0, pane.w, pane.h]);
    pane.msg.attr('x', pane.w / 2).attr('y', pane.h / 2);
    const home = geoHome();
    // Centre the Pacific a little east of home so Japan <-> Americas arcs do
    // not cross the map edge.
    const pad = Math.min(24, pane.w * 0.05);
    pane.proj = d3.geoMercator().rotate([-(home.lon + 15), 0]).precision(0.2)
        .fitExtent([[pad, pad + 16], [pane.w - pad, pane.h - pad]], pane.fit(home));
    if (GEO.world) {
        const path = d3.geoPath(pane.proj);
        pane.gBase.select('.map-land').attr('d', path(GEO.world.land));
        pane.gBase.select('.map-borders').attr('d', path(GEO.world.borders));
    }
}

function geoResetBase() {
    for (const pane of GEO.panes) { geoLayoutPane(pane); geoDrawPane(pane); }
}

// ---------- aggregation & drawing ----------
function geoAggregate(now) {
    const nowSec = Math.floor(now);
    const locs = new Map();
    for (const f of S.flows.values()) {
        if (now - f.last > GRAPH_WINDOW) continue;
        const ip = f.remote.ip;
        if (classify(ip) !== 'wan') continue;
        geoQueue(ip);
        const g = GEO.cache.get(ip);
        if (!g) continue;
        const bytes = flowWindowBytes(f, nowSec, GRAPH_WINDOW);
        if (!bytes) continue;
        const recent = flowWindowBytes(f, nowSec, 5) / 5;
        const downShare = f.up + f.down ? f.down / (f.up + f.down) : 0.5;
        const key = `${g.lat.toFixed(1)},${g.lon.toFixed(1)}`;
        let l = locs.get(key);
        if (!l) { l = { key, lat: g.lat, lon: g.lon, cc: g.cc, country: g.country, city: g.city, down: 0, up: 0, rateDown: 0, rateUp: 0, hosts: new Map() }; locs.set(key, l); }
        l.down += bytes * downShare; l.up += bytes * (1 - downShare);
        l.rateDown += recent * downShare; l.rateUp += recent * (1 - downShare);
        const name = f.name || S.names.get(ip) || ip;
        l.hosts.set(name, (l.hosts.get(name) || 0) + bytes);
    }
    return [...locs.values()].sort((a, b) => (b.down + b.up) - (a.down + a.up));
}

function geoLabel(l) {
    if (l.cc === 'JP') return l.city || l.country;
    return l.city ? `${l.city}, ${l.country}` : l.country;
}

/** Quadratic arc from a to b bulging "upwards", kept inside the pane. */
function geoArc(pane, a, b) {
    const mx = (a[0] + b[0]) / 2, my = (a[1] + b[1]) / 2;
    const dx = b[0] - a[0], dy = b[1] - a[1];
    const d = Math.hypot(dx, dy) || 1;
    let nx = -dy / d, ny = dx / d;
    if (ny > 0) { nx = -nx; ny = -ny; }
    const lift = Math.min(160, d * 0.28);
    const m = 14;
    const c = [Math.max(m, Math.min(pane.w - m, mx + nx * lift)), Math.max(m, Math.min(pane.h - m, my + ny * lift))];
    return { a, b, c, len: d * 1.15, tiny: d < 6 };
}
function geoBezier(arc, t) {
    const u = 1 - t;
    return [u * u * arc.a[0] + 2 * u * t * arc.c[0] + t * t * arc.b[0], u * u * arc.a[1] + 2 * u * t * arc.c[1] + t * t * arc.b[1]];
}

function geoTooltip(e, d) {
    const hosts = [...d.hosts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6)
        .map(([n, b]) => `<div class="tt-row"><span>${esc(trunc(n, 34))}</span><span>${fmtBytes(b)}</span></div>`).join('');
    showTip(e, `<b>${esc(geoLabel(d))}</b><div class="tt-row"><span>下り / 上り（直近2分）</span><span>${fmtBytes(d.down)} / ${fmtBytes(d.up)}</span></div>${hosts}`);
}

function geoDrawPane(pane) {
    if (!pane.proj) return;
    const home = geoHome();
    const h = pane.proj([home.lon, home.lat]);
    const maxB = Math.max(1, ...pane.locs.map((l) => l.down + l.up));
    const w = d3.scaleSqrt().domain([0, maxB]).range([0.8, 4]);
    const r = d3.scaleSqrt().domain([0, maxB]).range([3, 12]);
    for (const l of pane.locs) {
        l.p = pane.proj([l.lon, l.lat]);
        l.arc = geoArc(pane, l.p, h);
        l.r = r(l.down + l.up);
        l.w = w(l.down + l.up);
    }
    pane.gArcs.selectAll('path').data(pane.locs.filter((l) => !l.arc.tiny), (d) => d.key)
        .join('path')
        .attr('d', (d) => `M${d.arc.a}Q${d.arc.c} ${d.arc.b}`)
        .attr('stroke-width', (d) => d.w);

    pane.gNodes.selectAll('circle.loc').data(pane.locs, (d) => d.key)
        .join('circle')
        .attr('class', 'loc')
        .attr('cx', (d) => d.p[0]).attr('cy', (d) => d.p[1]).attr('r', (d) => d.r)
        .on('mousemove', geoTooltip)
        .on('mouseleave', hideTip);

    pane.gHome.selectAll('g.home').data([home])
        .join((enter) => {
            const g = enter.append('g').attr('class', 'home');
            g.append('circle').attr('class', 'home-pulse').attr('r', 7);
            g.append('circle').attr('class', 'home-dot').attr('r', 5);
            return g;
        })
        .attr('transform', `translate(${h[0]},${h[1]})`)
        .on('mousemove', (e) => showTip(e, `<b>${esc(S.hostname || 'このルーター')}</b><div class="tt-row"><span>${esc([home.city, home.country].filter(Boolean).join(', ') || '設定された位置')}</span></div>`))
        .on('mouseleave', hideTip);

    // Labels: home first, then the busiest locations, skipping overlaps.
    const boxes = [];
    const fits = (x, y, text) => {
        const tw = text.length * 6.6 + 6, b = { x0: x - tw / 2, x1: x + tw / 2, y0: y - 12, y1: y + 3 };
        if (b.x0 < 0 || b.x1 > pane.w || b.y0 < 0 || b.y1 > pane.h) return false;
        if (boxes.some((o) => b.x0 < o.x1 && b.x1 > o.x0 && b.y0 < o.y1 && b.y1 > o.y0)) return false;
        boxes.push(b);
        return true;
    };
    const labels = [];
    const homeText = S.hostname || 'このルーター';
    if (fits(h[0], h[1] + 20, homeText)) labels.push({ key: '__home', x: h[0], y: h[1] + 20, text: homeText, home: true });
    for (const l of pane.locs) {
        if (labels.length > pane.maxLabels) break;
        const text = trunc(geoLabel(l), 26);
        const y = l.p[1] - l.r - 5;
        if (fits(l.p[0], y, text)) labels.push({ key: l.key, x: l.p[0], y, text });
    }
    pane.gLabels.selectAll('text').data(labels, (d) => d.key)
        .join('text')
        .attr('class', (d) => (d.home ? 'node-label home-label' : 'node-label'))
        .attr('text-anchor', 'middle')
        .attr('x', (d) => d.x).attr('y', (d) => d.y)
        .text((d) => d.text);

    let text = '';
    if (!GEO.enabled) text = pane.id === 'mapWorld' ? 'GeoIPデータベースが未導入です（make geoip）' : '';
    else if (GEO.loadError) text = GEO.loadError;
    else if (!GEO.world) text = '地図を読み込み中…';
    else if (!pane.locs.length) text = pane.empty;
    pane.msg.text(text).style('display', text ? null : 'none');
}

function geoParticleCount(rate) {
    if (rate <= 0) return 0;
    return Math.max(1, Math.min(7, Math.round(Math.log10(rate / 200))));
}

function geoStep(ts) {
    GEO.raf = null;
    if (!GEO.active || document.hidden) return;
    const dt = GEO.lastFrame ? Math.min(0.1, (ts - GEO.lastFrame) / 1000) : 0;
    GEO.lastFrame = ts;
    for (const pane of GEO.panes) {
        const parts = [];
        for (const l of pane.locs) {
            if (!l.arc || l.arc.tiny) continue;
            for (const [dir, rate] of [['down', l.rateDown], ['up', l.rateUp]]) {
                const n = geoParticleCount(rate);
                const key = `${pane.id}|${l.key}|${dir}`;
                let ph = GEO.phases.get(key);
                if (!ph || ph.length !== n) {
                    ph = Array.from({ length: n }, (_, i) => i / Math.max(1, n));
                    GEO.phases.set(key, ph);
                }
                const step = (dt * PARTICLE_SPEED) / Math.max(40, l.arc.len);
                for (let i = 0; i < ph.length; i++) {
                    ph[i] = (ph[i] + step) % 1;
                    // Download travels remote -> home (t: 0 -> 1); upload the reverse.
                    const t = dir === 'down' ? ph[i] : 1 - ph[i];
                    const p = geoBezier(l.arc, t);
                    const tail = geoBezier(l.arc, Math.max(0, Math.min(1, dir === 'down' ? t - 0.035 : t + 0.035)));
                    parts.push({ id: `${key}|${i}`, dir, p, tail });
                }
            }
        }
        pane.gParts.selectAll('line').data(parts, (d) => d.id)
            .join('line')
            .attr('class', (d) => `particle ${d.dir}`)
            .attr('x1', (d) => d.tail[0]).attr('y1', (d) => d.tail[1])
            .attr('x2', (d) => d.p[0]).attr('y2', (d) => d.p[1]);
    }
    if (GEO.phases.size > 2000) GEO.phases.clear();
    GEO.raf = requestAnimationFrame(geoStep);
}

function geoAnimate() {
    if (GEO.active && !document.hidden && !GEO.raf) {
        GEO.lastFrame = 0;
        GEO.raf = requestAnimationFrame(geoStep);
    }
}

/** Called once per second from app.js while the map is visible. */
function geoRender(now = nowCapture()) {
    if (!GEO.panes.length) return;
    GEO.locs = GEO.enabled ? geoAggregate(now) : [];
    for (const pane of GEO.panes) {
        pane.locs = GEO.locs.filter(pane.filter).slice(0, MAP_MAX_LOCATIONS);
        geoDrawPane(pane);
    }
    const countries = new Set(GEO.locs.map((l) => l.cc));
    const note = document.getElementById('geoNote');
    if (note) note.textContent = GEO.locs.length ? `直近2分・${countries.size}か国・${GEO.locs.length}拠点` : '直近2分';
}

function geoSetActive(on) {
    GEO.active = on;
    if (on) geoAnimate();
}
