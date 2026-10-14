'use strict';

// =====================================================================
// GeoIP map: arcs from this gateway to remote locations with "flying"
// particles (download = remote -> home, upload = home -> remote).
// The view auto-fits: Japan only -> map of Japan; anything farther away ->
// zoom out to include it. Uses helpers/state from app.js at call time.
// =====================================================================

const WORLD_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-50m.json';
const JAPAN_ID = '392';
const MAP_MAX_LOCATIONS = 40;
const ZOOM_IN_HOLD = 30;          // s a smaller extent must persist before zooming in
const PARTICLE_SPEED = 140;       // px per second
const FALLBACK_HOME = { lat: 35.68, lon: 139.76, cc: 'JP', country: '日本', city: 'Tokyo' };

const GEO = {
    enabled: false,
    home: null,
    attribution: '',
    attributionUrl: '',
    cache: new Map(),       // ip -> geo | null
    pending: new Set(),
    inflight: false,
    world: null,            // {land, borders, japan}
    loadError: null,
    // drawing
    svg: null, gBase: null, gArcs: null, gParts: null, gNodes: null, gHome: null, gLabels: null, msg: null,
    w: 0, h: 0,
    proj: null,
    base: null,             // {k, tx, ty} the land paths were drawn with
    view: null,             // current {k, tx, ty}
    goal: null,             // target view
    anim: null,
    smallerSince: null,
    fitKey: '',
    locs: [],
    phases: new Map(),      // loc key + dir -> particle phases
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
    if (GEO.svg) { geoResetBase(); geoMessage(); }
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
        const countries = topojson.feature(world, world.objects.countries);
        GEO.world = {
            land: topojson.feature(world, world.objects.land),
            borders: topojson.mesh(world, world.objects.countries, (a, b) => a !== b),
            japan: countries.features.find((f) => String(f.id) === JAPAN_ID),
        };
    } catch (e) {
        GEO.loadError = '地図データを読み込めませんでした';
        console.error(e);
    }
    geoResetBase();
    geoMessage();
}

// ---------- setup ----------
function geoInit() {
    const svg = d3.select('#geoMap');
    GEO.svg = svg;
    GEO.gBase = svg.append('g').attr('class', 'map-base');
    GEO.gBase.append('path').attr('class', 'map-land');
    GEO.gBase.append('path').attr('class', 'map-borders');
    GEO.gArcs = svg.append('g').attr('class', 'map-arcs');
    GEO.gNodes = svg.append('g');
    GEO.gParts = svg.append('g').attr('class', 'map-particles');
    GEO.gHome = svg.append('g');
    GEO.gLabels = svg.append('g');
    GEO.msg = svg.append('text').attr('class', 'graph-empty').attr('text-anchor', 'middle');
    new ResizeObserver(() => { geoResetBase(); geoRender(); }).observe(document.getElementById('mapBox'));
    document.addEventListener('visibilitychange', geoAnimate);
    setInterval(geoFlush, 1500);
    geoLoadWorld();
}

function geoHome() { return GEO.home || FALLBACK_HOME; }

/** Rebuild the projection and redraw land at the reference (world) scale. */
function geoResetBase() {
    const box = document.getElementById('mapBox').getBoundingClientRect();
    if (!box.width || !box.height) return;
    GEO.w = box.width; GEO.h = box.height;
    GEO.svg.attr('viewBox', [0, 0, GEO.w, GEO.h]);
    GEO.msg.attr('x', GEO.w / 2).attr('y', GEO.h / 2);
    const home = geoHome();
    // Centre the Pacific a little east of home so Japan <-> Americas arcs do not
    // cross the map edge.
    GEO.proj = d3.geoMercator().rotate([-(home.lon + 15), 0]).precision(0.2);
    const k0 = GEO.w / (2 * Math.PI);
    GEO.base = { k: k0, tx: GEO.w / 2, ty: GEO.h / 2 };
    geoApply(GEO.base);
    if (GEO.world) {
        const path = d3.geoPath(GEO.proj);
        GEO.gBase.select('.map-land').attr('d', path(GEO.world.land));
        GEO.gBase.select('.map-borders').attr('d', path(GEO.world.borders));
    }
    GEO.fitKey = '';
    GEO.view = null;
    geoFit(true);
}

function geoApply(v) {
    GEO.proj.scale(v.k).translate([v.tx, v.ty]);
}

/** Land is drawn once; any other scale/translate is an affine transform of it. */
function geoTransformBase(v) {
    const b = GEO.base, s = v.k / b.k;
    GEO.gBase.attr('transform', `translate(${v.tx - b.tx * s},${v.ty - b.ty * s}) scale(${s})`);
}

/** Projection parameters that fit `object` into the panel. */
function geoFitView(object) {
    const pad = Math.min(48, GEO.w * 0.08);
    const p = GEO.proj;
    p.fitExtent([[pad, pad + 10], [GEO.w - pad, GEO.h - pad]], object);
    let v = { k: p.scale(), tx: p.translate()[0], ty: p.translate()[1] };
    // Never zoom out past one world width; keep the fitted centre in place.
    const kMin = (GEO.w - 2 * pad) / (2 * Math.PI);
    if (v.k < kMin) {
        const c = p.invert([GEO.w / 2, GEO.h / 2]);
        p.scale(kMin).translate([GEO.w / 2, GEO.h / 2]);
        const q = p(c);
        v = { k: kMin, tx: GEO.w / 2 + (GEO.w / 2 - q[0]), ty: GEO.h / 2 + (GEO.h / 2 - q[1]) };
    }
    // fitExtent changed the live projection; put the current view back.
    geoApply(GEO.view || GEO.base);
    return v;
}

function geoTargetObject() {
    const home = geoHome();
    const japan = GEO.world && GEO.world.japan;
    const abroad = GEO.locs.filter((l) => l.cc !== 'JP');
    const points = [[home.lon, home.lat], ...abroad.map((l) => [l.lon, l.lat])];
    if (!abroad.length) {
        return { key: 'JP', object: japan || { type: 'MultiPoint', coordinates: [[129, 31], [146, 45]] } };
    }
    // Round the extent so tiny changes do not refit.
    const lons = points.map((p) => p[0]), lats = points.map((p) => p[1]);
    const key = [Math.min(...lons), Math.max(...lons), Math.min(...lats), Math.max(...lats)].map((v) => Math.round(v / 10)).join(',');
    const features = points.map((c) => ({ type: 'Feature', geometry: { type: 'Point', coordinates: c } }));
    if (japan) features.push(japan);
    return { key, object: { type: 'FeatureCollection', features } };
}

/** Decide the target view; zoom out at once, zoom in only after a while. */
function geoFit(immediate = false) {
    if (!GEO.proj) return;
    const { key, object } = geoTargetObject();
    const now = Date.now() / 1000;
    if (key === GEO.fitKey && GEO.view) { GEO.smallerSince = null; return; }
    const goal = geoFitView(object);
    if (!GEO.view || immediate) {
        GEO.view = goal; GEO.goal = goal; GEO.fitKey = key;
        geoApply(goal); geoTransformBase(goal);
        return;
    }
    if (goal.k > GEO.view.k * 1.05) {          // would zoom in
        if (GEO.smallerSince === null) GEO.smallerSince = now;
        if (now - GEO.smallerSince < ZOOM_IN_HOLD) return;
    }
    GEO.smallerSince = null;
    GEO.fitKey = key;
    geoAnimateTo(goal);
}

function geoAnimateTo(goal) {
    if (GEO.anim) GEO.anim.stop();
    const from = { ...GEO.view };
    const interp = d3.interpolateObject(from, goal);
    GEO.goal = goal;
    GEO.anim = d3.timer((elapsed) => {
        const t = Math.min(1, elapsed / 1400);
        GEO.view = interp(d3.easeCubicInOut(t));
        geoApply(GEO.view);
        geoTransformBase(GEO.view);
        geoDrawArcs();
        if (t >= 1) { GEO.anim.stop(); GEO.anim = null; }
    });
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
    return [...locs.values()].sort((a, b) => (b.down + b.up) - (a.down + a.up)).slice(0, MAP_MAX_LOCATIONS);
}

function geoLabel(l) {
    if (l.cc === 'JP') return l.city || l.country;
    return l.city ? `${l.city}, ${l.country}` : l.country;
}

/** Quadratic arc from a to b bulging "upwards" in screen space. */
function geoArc(a, b) {
    const mx = (a[0] + b[0]) / 2, my = (a[1] + b[1]) / 2;
    const dx = b[0] - a[0], dy = b[1] - a[1];
    const d = Math.hypot(dx, dy) || 1;
    let nx = -dy / d, ny = dx / d;
    if (ny > 0) { nx = -nx; ny = -ny; }
    const lift = Math.min(160, d * 0.28);
    // Keep the curve inside the panel (e.g. long arcs to Europe near the top).
    const m = 14;
    const c = [Math.max(m, Math.min(GEO.w - m, mx + nx * lift)), Math.max(m, Math.min(GEO.h - m, my + ny * lift))];
    return { a, b, c, len: d * 1.15 };
}
function geoBezier(arc, t) {
    const u = 1 - t;
    return [u * u * arc.a[0] + 2 * u * t * arc.c[0] + t * t * arc.b[0], u * u * arc.a[1] + 2 * u * t * arc.c[1] + t * t * arc.b[1]];
}

function geoDrawArcs() {
    if (!GEO.proj) return;
    const home = geoHome();
    const h = GEO.proj([home.lon, home.lat]);
    const maxB = Math.max(1, ...GEO.locs.map((l) => l.down + l.up));
    const w = d3.scaleSqrt().domain([0, maxB]).range([0.8, 4]);
    const r = d3.scaleSqrt().domain([0, maxB]).range([3, 12]);
    for (const l of GEO.locs) {
        l.p = GEO.proj([l.lon, l.lat]);
        l.arc = geoArc(l.p, h);
        l.r = r(l.down + l.up);
        l.w = w(l.down + l.up);
    }
    GEO.gArcs.selectAll('path').data(GEO.locs, (d) => d.key)
        .join('path')
        .attr('d', (d) => `M${d.arc.a}Q${d.arc.c} ${d.arc.b}`)
        .attr('stroke-width', (d) => d.w);

    GEO.gNodes.selectAll('circle.loc').data(GEO.locs, (d) => d.key)
        .join('circle')
        .attr('class', 'loc')
        .attr('cx', (d) => d.p[0]).attr('cy', (d) => d.p[1]).attr('r', (d) => d.r)
        .on('mousemove', (e, d) => {
            const hosts = [...d.hosts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6)
                .map(([n, b]) => `<div class="tt-row"><span>${esc(trunc(n, 34))}</span><span>${fmtBytes(b)}</span></div>`).join('');
            showTip(e, `<b>${esc(geoLabel(d))}</b><div class="tt-row"><span>下り / 上り（直近2分）</span><span>${fmtBytes(d.down)} / ${fmtBytes(d.up)}</span></div>${hosts}`);
        })
        .on('mouseleave', hideTip);

    GEO.gHome.selectAll('g.home').data([home])
        .join((enter) => {
            const g = enter.append('g').attr('class', 'home');
            g.append('circle').attr('class', 'home-pulse').attr('r', 7);
            g.append('circle').attr('class', 'home-dot').attr('r', 5);
            return g;
        })
        .attr('transform', `translate(${h[0]},${h[1]})`)
        .on('mousemove', (e) => showTip(e, `<b>${esc(S.hostname || 'このルーター')}</b><div class="tt-row"><span>${esc([home.city, home.country].filter(Boolean).join(', ') || '設定された位置')}</span></div>`))
        .on('mouseleave', hideTip);

    // Labels: home first, then the busiest locations, skipping any that would
    // overlap a label already placed.
    const boxes = [];
    const fits = (x, y, text) => {
        const w = text.length * 6.6 + 6, b = { x0: x - w / 2, x1: x + w / 2, y0: y - 12, y1: y + 3 };
        if (b.x0 < 0 || b.x1 > GEO.w || b.y0 < 0) return false;
        if (boxes.some((o) => b.x0 < o.x1 && b.x1 > o.x0 && b.y0 < o.y1 && b.y1 > o.y0)) return false;
        boxes.push(b);
        return true;
    };
    const labels = [];
    const homeText = S.hostname || 'このルーター';
    if (fits(h[0], h[1] + 20, homeText)) labels.push({ key: '__home', x: h[0], y: h[1] + 20, text: homeText, home: true });
    for (const l of GEO.locs) {
        if (labels.length >= 11) break;
        const text = trunc(geoLabel(l), 28);
        const y = l.p[1] - l.r - 5;
        if (fits(l.p[0], y, text)) labels.push({ key: l.key, x: l.p[0], y, text });
    }
    GEO.gLabels.selectAll('text').data(labels, (d) => d.key)
        .join('text')
        .attr('class', (d) => (d.home ? 'node-label home-label' : 'node-label'))
        .attr('text-anchor', 'middle')
        .attr('x', (d) => d.x).attr('y', (d) => d.y)
        .text((d) => d.text);
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
    const parts = [];
    for (const l of GEO.locs) {
        if (!l.arc) continue;
        for (const [dir, rate] of [['down', l.rateDown], ['up', l.rateUp]]) {
            const n = geoParticleCount(rate);
            const key = `${l.key}|${dir}`;
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
    GEO.gParts.selectAll('line').data(parts, (d) => d.id)
        .join('line')
        .attr('class', (d) => `particle ${d.dir}`)
        .attr('x1', (d) => d.tail[0]).attr('y1', (d) => d.tail[1])
        .attr('x2', (d) => d.p[0]).attr('y2', (d) => d.p[1]);
    GEO.raf = requestAnimationFrame(geoStep);
}

function geoAnimate() {
    if (GEO.active && !document.hidden && !GEO.raf) {
        GEO.lastFrame = 0;
        GEO.raf = requestAnimationFrame(geoStep);
    }
}

function geoMessage() {
    if (!GEO.msg) return;
    let text = '';
    if (!GEO.enabled) text = 'GeoIPデータベースが未導入です（make geoip）';
    else if (GEO.loadError) text = GEO.loadError;
    else if (!GEO.world) text = '地図を読み込み中…';
    else if (!GEO.locs.length) text = '外部との通信を待っています…';
    GEO.msg.text(text).style('display', text ? null : 'none');
}

/** Called once per second from app.js while the map is visible. */
function geoRender(now = nowCapture()) {
    if (!GEO.svg || !GEO.proj) return;
    GEO.locs = GEO.enabled ? geoAggregate(now) : [];
    const countries = new Set(GEO.locs.map((l) => l.cc));
    const note = document.getElementById('geoNote');
    if (note) note.textContent = GEO.locs.length ? `直近2分・${countries.size}か国・${GEO.locs.length}拠点` : '直近2分';
    geoMessage();
    geoFit();
    if (!GEO.anim) geoDrawArcs();
}

function geoSetActive(on) {
    GEO.active = on;
    if (on) geoAnimate();
}
