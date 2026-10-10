"use strict";

(function () {
  const TILE = 256;
  const MAX_LAT = 85.05112878;
  const MIN_ZOOM = 1;
  const MAX_ZOOM = 19;

  function clampLat(lat) {
    return Math.max(-MAX_LAT, Math.min(MAX_LAT, lat));
  }

  function worldSize(z) {
    return TILE * Math.pow(2, z);
  }

  function project(lat, lon, z) {
    const s = worldSize(z);
    const sin = Math.sin((clampLat(lat) * Math.PI) / 180);
    return [((lon + 180) / 360) * s, (0.5 - Math.log((1 + sin) / (1 - sin)) / (4 * Math.PI)) * s];
  }

  function unproject(x, y, z) {
    const s = worldSize(z);
    const n = Math.PI - (2 * Math.PI * y) / s;
    const lat = (180 / Math.PI) * Math.atan(0.5 * (Math.exp(n) - Math.exp(-n)));
    let lon = (x / s) * 360 - 180;
    lon = ((((lon + 180) % 360) + 360) % 360) - 180;
    return [lat, lon];
  }

  class SlippyMap {
    constructor(canvas, opts) {
      opts = opts || {};
      this.canvas = canvas;
      this.ctx = canvas.getContext("2d");
      this.tileUrl = opts.tileUrl || "";
      this.tileFilter = opts.tileFilter || "none";
      this.dark = !!opts.dark;
      this.lat = opts.lat ?? 20;
      this.lon = opts.lon ?? 0;
      this.zoom = opts.zoom ?? 3;
      this.markers = [];
      this.tracks = [];
      this.selected = "";
      this.tiles = new Map();
      this.onselect = null;
      this.onmove = null;
      this.pointers = new Map();
      this.dragged = false;
      this.pending = false;
      this.width = 0;
      this.height = 0;
      this.dpr = window.devicePixelRatio || 1;
      this.bind();
      this.resize();
      if (window.ResizeObserver) {
        this.observer = new ResizeObserver(() => this.resize());
        this.observer.observe(canvas);
      } else {
        window.addEventListener("resize", () => this.resize());
      }
    }

    destroy() {
      if (this.observer) this.observer.disconnect();
      this.tiles.clear();
      this.destroyed = true;
    }

    resize() {
      const r = this.canvas.getBoundingClientRect();
      this.dpr = window.devicePixelRatio || 1;
      this.width = Math.max(1, Math.round(r.width));
      this.height = Math.max(1, Math.round(r.height));
      this.canvas.width = Math.round(this.width * this.dpr);
      this.canvas.height = Math.round(this.height * this.dpr);
      this.draw();
    }

    center() {
      return project(this.lat, this.lon, this.zoom);
    }

    toScreen(lat, lon) {
      const [cx, cy] = this.center();
      const [x, y] = project(lat, lon, this.zoom);
      const s = worldSize(this.zoom);
      let dx = x - cx;
      if (dx > s / 2) dx -= s;
      if (dx < -s / 2) dx += s;
      return [this.width / 2 + dx, this.height / 2 + (y - cy)];
    }

    toLatLon(px, py) {
      const [cx, cy] = this.center();
      return unproject(cx + px - this.width / 2, cy + py - this.height / 2, this.zoom);
    }

    setView(lat, lon, zoom) {
      this.lat = clampLat(lat);
      this.lon = lon;
      if (zoom !== undefined) this.zoom = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, Math.round(zoom)));
      this.draw();
    }

    zoomAt(delta, px, py) {
      const next = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, this.zoom + delta));
      if (next === this.zoom) return;
      if (px === undefined) {
        px = this.width / 2;
        py = this.height / 2;
      }
      const [lat, lon] = this.toLatLon(px, py);
      this.zoom = next;
      const [x, y] = project(lat, lon, this.zoom);
      const [clat, clon] = unproject(x - (px - this.width / 2), y - (py - this.height / 2), this.zoom);
      this.lat = clampLat(clat);
      this.lon = clon;
      this.draw();
    }

    panBy(dx, dy) {
      const [cx, cy] = this.center();
      const s = worldSize(this.zoom);
      const ny = Math.max(0, Math.min(s, cy - dy));
      const [lat, lon] = unproject(cx - dx, ny, this.zoom);
      this.lat = clampLat(lat);
      this.lon = lon;
      this.draw();
    }

    fit(points, maxZoom) {
      const pts = points.filter((p) => Number.isFinite(p.lat) && Number.isFinite(p.lon) && !(p.lat === 0 && p.lon === 0));
      if (!pts.length) return false;
      let minLat = 90, maxLat = -90, minLon = 180, maxLon = -180;
      for (const p of pts) {
        minLat = Math.min(minLat, p.lat);
        maxLat = Math.max(maxLat, p.lat);
        minLon = Math.min(minLon, p.lon);
        maxLon = Math.max(maxLon, p.lon);
      }
      let z = maxZoom || 15;
      for (; z > MIN_ZOOM; z--) {
        const [x1, y1] = project(maxLat, minLon, z);
        const [x2, y2] = project(minLat, maxLon, z);
        if (Math.abs(x2 - x1) < this.width * 0.8 && Math.abs(y2 - y1) < this.height * 0.8) break;
      }
      this.setView((minLat + maxLat) / 2, (minLon + maxLon) / 2, z);
      return true;
    }

    setMarkers(list) {
      this.markers = list;
      this.draw();
    }

    setTracks(list) {
      this.tracks = list;
      this.draw();
    }

    setTileUrl(url) {
      this.tileUrl = url || "";
      this.tiles.clear();
      this.draw();
    }

    tileSrc(z, x, y) {
      const subs = "abc";
      return this.tileUrl
        .replace(/\{z\}/g, z)
        .replace(/\{x\}/g, x)
        .replace(/\{y\}/g, y)
        .replace(/\{-y\}/g, Math.pow(2, z) - 1 - y)
        .replace(/\{s\}/g, subs[(x + y) % subs.length]);
    }

    tile(z, x, y) {
      const key = z + "/" + x + "/" + y;
      let t = this.tiles.get(key);
      if (t) {
        this.tiles.delete(key);
        this.tiles.set(key, t);
        return t;
      }
      if (!this.tileUrl) return null;
      const img = new Image();
      t = { img: img, ok: false, failed: false };
      img.decoding = "async";
      img.referrerPolicy = "strict-origin-when-cross-origin";
      img.onload = () => {
        t.ok = true;
        this.draw();
      };
      img.onerror = () => {
        t.failed = true;
      };
      img.src = this.tileSrc(z, x, y);
      this.tiles.set(key, t);
      while (this.tiles.size > 600) {
        this.tiles.delete(this.tiles.keys().next().value);
      }
      return t;
    }

    draw() {
      if (this.pending || this.destroyed) return;
      this.pending = true;
      requestAnimationFrame(() => {
        this.pending = false;
        this.render();
      });
    }

    render() {
      const ctx = this.ctx;
      const w = this.width, h = this.height;
      ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      const pal = this.palette();
      ctx.fillStyle = pal.empty;
      ctx.fillRect(0, 0, w, h);
      ctx.filter = this.tileFilter;
      const z = this.zoom;
      const n = Math.pow(2, z);
      const [cx, cy] = this.center();
      const left = cx - w / 2, top = cy - h / 2;
      const x0 = Math.floor(left / TILE), x1 = Math.floor((left + w) / TILE);
      const y0 = Math.max(0, Math.floor(top / TILE)), y1 = Math.min(n - 1, Math.floor((top + h) / TILE));
      ctx.strokeStyle = pal.grid;
      ctx.lineWidth = 1;
      for (let ty = y0; ty <= y1; ty++) {
        for (let tx = x0; tx <= x1; tx++) {
          const wx = ((tx % n) + n) % n;
          const sx = Math.round(tx * TILE - left), sy = Math.round(ty * TILE - top);
          const t = this.tile(z, wx, ty);
          if (t && t.ok) {
            ctx.drawImage(t.img, sx, sy, TILE, TILE);
          } else {
            this.drawFallback(z, wx, ty, sx, sy);
          }
        }
      }
      ctx.filter = "none";
      if (top < 0) {
        ctx.fillStyle = pal.empty;
        ctx.fillRect(0, 0, w, -top);
      }
      if (top + h > n * TILE) {
        ctx.fillStyle = pal.empty;
        ctx.fillRect(0, n * TILE - top, w, top + h - n * TILE);
      }
      this.drawTracks();
      this.drawShapes();
      this.drawMarkers();
    }

    metersToPx(lat, meters) {
      return (meters * worldSize(this.zoom)) / (40075016.686 * Math.cos((clampLat(lat) * Math.PI) / 180));
    }

    shapePath(m) {
      const ctx = this.ctx;
      const sh = m.shape;
      ctx.beginPath();
      if (sh.radius) {
        const [x, y] = this.toScreen(m.lat, m.lon);
        const rx = Math.max(2, this.metersToPx(m.lat, sh.radius));
        const ry = Math.max(2, this.metersToPx(m.lat, sh.minor || sh.radius));
        ctx.ellipse(x, y, rx, ry, ((sh.angle || 0) * Math.PI) / 180, 0, Math.PI * 2);
        return;
      }
      sh.points.forEach((p, i) => {
        const [x, y] = this.toScreen(p[0], p[1]);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      if (sh.closed) ctx.closePath();
    }

    drawShapes() {
      const ctx = this.ctx;
      const pal = this.palette();
      ctx.lineJoin = "round";
      ctx.lineCap = "round";
      for (const m of this.markers) {
        const sh = m.shape;
        if (!sh) continue;
        const sel = m.uid === this.selected;
        const color = withAlpha(sh.stroke, 1) || (sh.route ? "#7fd3df" : pal.text);
        this.shapePath(m);
        if (sh.closed && sh.fill) {
          ctx.fillStyle = withAlpha(sh.fill, 0.35, true);
          ctx.fill();
        }
        const w = Math.min(Math.max(sh.width || (sh.route ? 3 : 2), 1.5), 6) + (sel ? 1.5 : 0);
        ctx.strokeStyle = pal.halo;
        ctx.lineWidth = w + 3;
        ctx.stroke();
        ctx.strokeStyle = color;
        ctx.lineWidth = w;
        if (sh.route) ctx.setLineDash([10, 6]);
        ctx.stroke();
        ctx.setLineDash([]);
        if (sh.route && sh.points) {
          for (const p of sh.points) {
            const [x, y] = this.toScreen(p[0], p[1]);
            ctx.beginPath();
            ctx.arc(x, y, 3.5, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.fill();
            ctx.strokeStyle = pal.ink;
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        }
      }
    }

    drawFallback(z, x, y, sx, sy) {
      const ctx = this.ctx;
      for (let dz = 1; dz <= 4 && z - dz >= 0; dz++) {
        const f = Math.pow(2, dz);
        const key = z - dz + "/" + Math.floor(x / f) + "/" + Math.floor(y / f);
        const t = this.tiles.get(key);
        if (t && t.ok) {
          const size = TILE / f;
          ctx.drawImage(t.img, (x % f) * size, (y % f) * size, size, size, sx, sy, TILE, TILE);
          return;
        }
      }
      ctx.strokeRect(sx + 0.5, sy + 0.5, TILE, TILE);
    }

    palette() {
      return this.dark
        ? { empty: "#1a1a1d", grid: "#2a2a2e", halo: "rgba(17,17,19,0.92)", text: "#f2f2f2", ink: "#111113", track: "#7fd3df", select: "#f2f2f2" }
        : { empty: "#e7e7e5", grid: "#d2d2d0", halo: "rgba(255,255,255,0.95)", text: "#161618", ink: "#161618", track: "#1f7f8c", select: "#161618" };
    }

    setStyle(tileFilter, dark) {
      this.tileFilter = tileFilter || "none";
      this.dark = !!dark;
      this.draw();
    }

    drawTracks() {
      const ctx = this.ctx;
      const pal = this.palette();
      ctx.lineJoin = "round";
      ctx.lineCap = "round";
      for (const tr of this.tracks) {
        if (!tr.points || tr.points.length < 2) continue;
        ctx.beginPath();
        tr.points.forEach((p, i) => {
          const [x, y] = this.toScreen(p.lat, p.lon);
          if (i === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        });
        ctx.strokeStyle = pal.halo;
        ctx.lineWidth = 5;
        ctx.stroke();
        ctx.strokeStyle = pal.track;
        ctx.lineWidth = 2;
        ctx.stroke();
      }
    }

    shape(kind, x, y, r) {
      const ctx = this.ctx;
      ctx.beginPath();
      switch (kind) {
        case "hostile":
          ctx.moveTo(x, y - r - 1);
          ctx.lineTo(x + r + 1, y);
          ctx.lineTo(x, y + r + 1);
          ctx.lineTo(x - r - 1, y);
          ctx.closePath();
          break;
        case "neutral":
          ctx.rect(x - r, y - r, r * 2, r * 2);
          break;
        case "medevac":
          ctx.rect(x - r - 1, y - r - 1, (r + 1) * 2, (r + 1) * 2);
          break;
        case "point":
          ctx.moveTo(x - r, y - r);
          ctx.lineTo(x + r, y + r);
          ctx.moveTo(x + r, y - r);
          ctx.lineTo(x - r, y + r);
          return;
        default:
          ctx.arc(x, y, r, 0, Math.PI * 2);
      }
    }

    leader(x, y, r, course, pal) {
      const ctx = this.ctx;
      const a = ((course - 90) * Math.PI) / 180;
      ctx.beginPath();
      ctx.moveTo(x + Math.cos(a) * (r + 1), y + Math.sin(a) * (r + 1));
      ctx.lineTo(x + Math.cos(a) * (r + 18), y + Math.sin(a) * (r + 18));
      ctx.lineCap = "round";
      ctx.strokeStyle = pal.halo;
      ctx.lineWidth = 5;
      ctx.stroke();
      ctx.strokeStyle = pal.text;
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    drawMarkers() {
      const ctx = this.ctx;
      const pal = this.palette();
      const fill = { friend: "#80e0ff", hostile: "#ff8080", neutral: "#aaffaa", unknown: "#ffff80", emergency: "#ff4d4f", medevac: "#ffffff" };
      const font = "'Atkinson Hyperlegible Next', system-ui, sans-serif";
      ctx.font = "600 12px " + font;
      ctx.textBaseline = "middle";
      const rank = { emergency: 0, medevac: 0, friend: 1, hostile: 1, unknown: 2, point: 3, neutral: 4 };
      const sorted = this.markers.slice().sort((a, b) => (a.kind === "emergency") - (b.kind === "emergency"));
      const labels = [];
      for (const m of sorted) {
        if (!Number.isFinite(m.lat) || !Number.isFinite(m.lon)) continue;
        const [x, y] = this.toScreen(m.lat, m.lon);
        if (x < -50 || y < -50 || x > this.width + 50 || y > this.height + 50) continue;
        const typ = m.type || (m.v && m.v.type) || "";
        const milsym = this.symbology !== "simple" && window.MilSym && (m.kind === "friend" || m.kind === "hostile" || m.kind === "neutral" || m.kind === "unknown") && typ.startsWith("a-");
        const r = m.kind === "emergency" ? 8 : milsym ? 11 : 6;
        if (m.kind === "shape") {
          if (m.label) labels.push({ m: m, x: x + 6, y: y, r: 0, p: m.uid === this.selected ? -1 : 3 });
          continue;
        }
        if (m.uid === this.selected) {
          ctx.beginPath();
          ctx.rect(x - r - 6, y - r - 6, (r + 6) * 2, (r + 6) * 2);
          ctx.strokeStyle = pal.select;
          ctx.lineWidth = 1.5;
          ctx.setLineDash([4, 3]);
          ctx.stroke();
          ctx.setLineDash([]);
        }
        if (milsym) {
          MilSym.draw(ctx, typ, x, y, 8, pal.ink);
          if (Number.isFinite(m.course) && m.speed > 0.5) this.leader(x, y, r, m.course, pal);
          if (m.label) labels.push({ m: m, x: x + r + 6, y: y, r: r, p: m.uid === this.selected ? -1 : rank[m.kind] ?? 3 });
          continue;
        }
        this.shape(m.kind, x, y, r);
        if (m.kind === "point") {
          ctx.strokeStyle = pal.halo;
          ctx.lineWidth = 5;
          ctx.stroke();
          ctx.strokeStyle = pal.text;
          ctx.lineWidth = 2;
          ctx.stroke();
        } else {
          ctx.fillStyle = fill[m.kind] || fill.unknown;
          ctx.fill();
          ctx.strokeStyle = pal.ink;
          ctx.lineWidth = 1.5;
          ctx.stroke();
          if (m.kind === "medevac") {
            ctx.fillStyle = "#d92d20";
            ctx.fillRect(x - 1.5, y - r + 1, 3, (r - 1) * 2);
            ctx.fillRect(x - r + 1, y - 1.5, (r - 1) * 2, 3);
          } else if (m.kind === "emergency") {
            ctx.beginPath();
            ctx.arc(x, y, r + 4, 0, Math.PI * 2);
            ctx.strokeStyle = fill.emergency;
            ctx.lineWidth = 2;
            ctx.stroke();
            ctx.fillStyle = "#ffffff";
            ctx.textAlign = "center";
            ctx.font = "700 11px " + font;
            ctx.fillText("!", x, y + 0.5);
            ctx.font = "600 12px " + font;
          } else if (m.kind === "unknown") {
            ctx.fillStyle = pal.ink;
            ctx.textAlign = "center";
            ctx.font = "700 9px " + font;
            ctx.fillText("?", x, y + 0.5);
            ctx.font = "600 12px " + font;
          }
          if (Number.isFinite(m.course) && m.speed > 0.5) this.leader(x, y, r, m.course, pal);
        }
        if (m.label) labels.push({ m: m, x: x + r + 6, y: y, r: r, p: m.uid === this.selected ? -1 : rank[m.kind] ?? 3 });
      }
      labels.sort((a, b) => a.p - b.p);
      const placed = [];
      ctx.textAlign = "left";
      ctx.lineWidth = 3.5;
      ctx.lineJoin = "round";
      for (const l of labels) {
        const w = ctx.measureText(l.m.label).width;
        const box = { x0: l.x - 2, y0: l.y - 8, x1: l.x + w + 2, y1: l.y + 8 };
        if (placed.some((b) => box.x0 < b.x1 && box.x1 > b.x0 && box.y0 < b.y1 && box.y1 > b.y0)) continue;
        placed.push(box);
        ctx.strokeStyle = pal.halo;
        ctx.strokeText(l.m.label, l.x, l.y);
        ctx.fillStyle = pal.text;
        ctx.fillText(l.m.label, l.x, l.y);
      }
    }

    hit(px, py) {
      let best = null, bestD = 14 * 14;
      for (const m of this.markers) {
        if (m.kind === "shape") continue;
        const [x, y] = this.toScreen(m.lat, m.lon);
        const d = (x - px) * (x - px) + (y - py) * (y - py);
        if (d <= bestD) {
          best = m;
          bestD = d;
        }
      }
      if (best) return best;
      bestD = 8 * 8;
      for (const m of this.markers) {
        const sh = m.shape;
        if (!sh) continue;
        let d = Infinity;
        if (sh.radius) {
          const [x, y] = this.toScreen(m.lat, m.lon);
          const r = this.metersToPx(m.lat, sh.radius);
          const c = Math.hypot(px - x, py - y);
          d = c <= r ? 0 : (c - r) * (c - r);
        } else if (sh.points) {
          const pts = sh.points.map((p) => this.toScreen(p[0], p[1]));
          if (sh.closed) pts.push(pts[0]);
          for (let i = 1; i < pts.length; i++) d = Math.min(d, segDist2(px, py, pts[i - 1], pts[i]));
          if (sh.closed && sh.fill && inPoly(px, py, pts)) d = 0;
        }
        if (d <= bestD) {
          best = m;
          bestD = d;
        }
      }
      return best;
    }

    local(ev) {
      const r = this.canvas.getBoundingClientRect();
      return [ev.clientX - r.left, ev.clientY - r.top];
    }

    bind() {
      const c = this.canvas;
      let last = null;
      let pinch = null;
      c.addEventListener("pointerdown", (ev) => {
        c.setPointerCapture(ev.pointerId);
        this.pointers.set(ev.pointerId, this.local(ev));
        this.dragged = false;
        if (this.pointers.size === 2) {
          const [a, b] = [...this.pointers.values()];
          pinch = { d: Math.hypot(a[0] - b[0], a[1] - b[1]) };
        }
        last = this.local(ev);
      });
      c.addEventListener("pointermove", (ev) => {
        const p = this.local(ev);
        if (this.onmove) {
          const [lat, lon] = this.toLatLon(p[0], p[1]);
          this.onmove(lat, lon);
        }
        if (!this.pointers.has(ev.pointerId)) return;
        this.pointers.set(ev.pointerId, p);
        if (this.pointers.size === 2 && pinch) {
          const [a, b] = [...this.pointers.values()];
          const d = Math.hypot(a[0] - b[0], a[1] - b[1]);
          const mid = [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2];
          if (d / pinch.d > 1.5) {
            this.zoomAt(1, mid[0], mid[1]);
            pinch.d = d;
          } else if (d / pinch.d < 0.66) {
            this.zoomAt(-1, mid[0], mid[1]);
            pinch.d = d;
          }
          this.dragged = true;
          return;
        }
        if (last) {
          const dx = p[0] - last[0], dy = p[1] - last[1];
          if (Math.abs(dx) + Math.abs(dy) > 2 || this.dragged) {
            this.dragged = true;
            c.classList.add("dragging");
            this.panBy(dx, dy);
            last = p;
          }
        }
      });
      const end = (ev) => {
        const wasDrag = this.dragged;
        this.pointers.delete(ev.pointerId);
        if (this.pointers.size < 2) pinch = null;
        c.classList.remove("dragging");
        if (ev.type === "pointerup" && !wasDrag && this.pointers.size === 0) {
          const p = this.local(ev);
          const m = this.hit(p[0], p[1]);
          const [lat, lon] = this.toLatLon(p[0], p[1]);
          this.selected = m ? m.uid : "";
          this.draw();
          if (this.onselect) this.onselect(m, lat, lon);
        }
        if (this.pointers.size === 0) last = null;
        else last = [...this.pointers.values()][0];
      };
      c.addEventListener("pointerup", end);
      c.addEventListener("pointercancel", end);
      let wheelAcc = 0;
      c.addEventListener(
        "wheel",
        (ev) => {
          ev.preventDefault();
          wheelAcc += ev.deltaY;
          if (Math.abs(wheelAcc) >= 60) {
            const p = this.local(ev);
            this.zoomAt(wheelAcc < 0 ? 1 : -1, p[0], p[1]);
            wheelAcc = 0;
          }
        },
        { passive: false }
      );
      c.addEventListener("dblclick", (ev) => {
        const p = this.local(ev);
        this.zoomAt(ev.shiftKey ? -1 : 1, p[0], p[1]);
      });
    }
  }

  function withAlpha(c, a, cap) {
    const m = /^rgba\((\d+),(\d+),(\d+),([\d.]+)\)$/.exec(c || "");
    if (!m) return "";
    const cur = Number(m[4]);
    if (!cap && cur === 0) return "";
    return "rgba(" + m[1] + "," + m[2] + "," + m[3] + "," + (cap ? Math.min(cur, a) : a) + ")";
  }

  function segDist2(px, py, a, b) {
    const dx = b[0] - a[0], dy = b[1] - a[1];
    const l = dx * dx + dy * dy;
    let t = l ? ((px - a[0]) * dx + (py - a[1]) * dy) / l : 0;
    t = Math.max(0, Math.min(1, t));
    const x = a[0] + t * dx - px, y = a[1] + t * dy - py;
    return x * x + y * y;
  }

  function inPoly(px, py, pts) {
    let inside = false;
    for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
      const [xi, yi] = pts[i], [xj, yj] = pts[j];
      if (yi > py !== yj > py && px < ((xj - xi) * (py - yi)) / (yj - yi) + xi) inside = !inside;
    }
    return inside;
  }

  SlippyMap.affiliation = function (type) {
    if (!type) return "unknown";
    if (type.startsWith("b-r-f-h-c")) return "medevac";
    if (type.startsWith("b-a-")) return "emergency";
    if (type.startsWith("a-") && type.length > 2) {
      const a = type[2];
      if (a === "f" || a === "a") return "friend";
      if (a === "h" || a === "s" || a === "j" || a === "k") return "hostile";
      if (a === "n") return "neutral";
      return "unknown";
    }
    return "point";
  };

  window.SlippyMap = SlippyMap;
})();
