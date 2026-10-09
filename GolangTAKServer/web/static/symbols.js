(function () {
  "use strict";

  const FILL = { friend: "#80e0ff", hostile: "#ff8080", neutral: "#aaffaa", unknown: "#ffff80" };

  function parse(type) {
    const p = (type || "").split("-");
    if (p[0] !== "a" || p.length < 2) return null;
    const a = p[1];
    let aff = "unknown";
    if (a === "f" || a === "a") aff = "friend";
    else if (a === "h" || a === "s" || a === "j" || a === "k") aff = "hostile";
    else if (a === "n") aff = "neutral";
    const dim = p[2] || "Z";
    const fn = p.slice(3).join("-");
    return { aff: aff, dashed: a === "a" || a === "s" || a === "p", dim: dim, fn: fn, ground: dim === "G" ? (fn.startsWith("E") ? "equipment" : fn.startsWith("I") ? "installation" : "unit") : "" };
  }

  function frameBox(s, sym) {
    const air = sym.dim === "A" || sym.dim === "P";
    const sub = sym.dim === "U";
    switch (sym.aff) {
      case "friend":
        if (sym.dim === "G" && sym.ground !== "equipment") return { w: s * 1.5, h: s, top: -s, bottom: s };
        if (air) return { w: s, h: s, top: -s * 1.2, bottom: s * 0.4 };
        if (sub) return { w: s, h: s, top: -s * 0.4, bottom: s * 1.2 };
        return { w: s, h: s, top: -s, bottom: s };
      case "hostile":
        if (air) return { w: s * 1.1, h: s * 1.1, top: -s * 1.4, bottom: s * 0.6 };
        if (sub) return { w: s * 1.1, h: s * 1.1, top: -s * 0.6, bottom: s * 1.4 };
        return { w: s * 1.35, h: s * 1.35, top: -s * 1.35, bottom: s * 1.35 };
      case "neutral":
        if (air) return { w: s, h: s, top: -s * 1.2, bottom: s * 0.6 };
        if (sub) return { w: s, h: s, top: -s * 0.6, bottom: s * 1.2 };
        return { w: s, h: s, top: -s, bottom: s };
    }
    if (air) return { w: s * 1.8, h: s, top: -s * 1.2, bottom: s * 0.6 };
    if (sub) return { w: s * 1.8, h: s, top: -s * 0.6, bottom: s * 1.2 };
    return { w: s * 1.2, h: s * 1.2, top: -s * 1.2, bottom: s * 1.2 };
  }

  function framePaths(x, y, s, sym) {
    const b = frameBox(s, sym);
    const fill = new Path2D(), line = new Path2D();
    const air = sym.dim === "A" || sym.dim === "P";
    const sub = sym.dim === "U";
    const w = b.w, t = y + b.top, bt = y + b.bottom;
    const both = (fn) => {
      fn(fill);
      fn(line);
    };
    if (sym.aff === "friend") {
      if (air || sub) {
        const flip = sub ? -1 : 1, base = sub ? t : bt;
        line.moveTo(x - w, base);
        line.bezierCurveTo(x - w, base - flip * w * 2.1, x + w, base - flip * w * 2.1, x + w, base);
        fill.addPath(line);
        fill.closePath();
      } else if (sym.dim === "G" && sym.ground !== "equipment") {
        both((p) => p.rect(x - w, t, w * 2, bt - t));
        if (sym.ground === "installation") both((p) => p.rect(x - w * 0.35, t - s * 0.35, w * 0.7, s * 0.35));
      } else {
        both((p) => p.arc(x, y, w, 0, Math.PI * 2));
      }
    } else if (sym.aff === "hostile") {
      if (air || sub) {
        const base = sub ? t : bt, mid = sub ? bt - w * 0.9 : t + w * 0.9;
        line.moveTo(x - w, base);
        line.lineTo(x - w, mid);
        line.lineTo(x, sub ? bt : t);
        line.lineTo(x + w, mid);
        line.lineTo(x + w, base);
        fill.addPath(line);
        fill.closePath();
      } else {
        both((p) => {
          p.moveTo(x, t);
          p.lineTo(x + w, y);
          p.lineTo(x, bt);
          p.lineTo(x - w, y);
          p.closePath();
        });
      }
    } else if (sym.aff === "neutral") {
      if (air || sub) {
        const base = sub ? t : bt, far = sub ? bt : t;
        line.moveTo(x - w, base);
        line.lineTo(x - w, far);
        line.lineTo(x + w, far);
        line.lineTo(x + w, base);
        fill.addPath(line);
        fill.closePath();
      } else {
        both((p) => p.rect(x - w, t, w * 2, bt - t));
      }
    } else {
      const clover = (p, cx, cy, r) => {
        const d = r * 0.95, u = (d + Math.sqrt(2 * r * r - d * d)) / 2, a1 = Math.atan2(d - u, u);
        for (let k = 0; k < 4; k++) {
          const th = (k * Math.PI) / 2;
          p.arc(cx + d * Math.sin(th), cy - d * Math.cos(th), r, Math.PI - a1 + th, 2 * Math.PI + a1 + th);
        }
        p.closePath();
      };
      if (air || sub) {
        const r = s * 0.85, base = sub ? t : bt;
        both((p) => clover(p, x, base, r));
        const clip = new Path2D();
        if (sub) clip.rect(x - s * 3, base, s * 6, s * 3);
        else clip.rect(x - s * 3, base - s * 3, s * 6, s * 3);
        return { fill: fill, line: line, box: b, clip: clip };
      }
      both((p) => clover(p, x, y, w * 0.48));
    }
    return { fill: fill, line: line, box: b };
  }

  function icon(ctx, x, y0, s, sym, ink, box) {
    const y = sym.dim === "A" || sym.dim === "P" || sym.dim === "U" ? y0 + (box.top + box.bottom) / 2 : y0;
    const fn = sym.fn;
    const has = (code) => fn === code || fn.startsWith(code + "-");
    const ib = sym.aff === "hostile" ? s * 0.62 : sym.aff === "friend" && sym.ground === "unit" ? s * 0.95 : s * 0.7;
    const ih = sym.aff === "friend" && sym.ground === "unit" ? s * 0.62 : ib;
    ctx.save();
    ctx.strokeStyle = ink;
    ctx.fillStyle = ink;
    ctx.lineWidth = Math.max(1.2, s / 7);
    ctx.lineCap = "round";
    ctx.lineJoin = "round";
    const seg = (pts) => {
      ctx.beginPath();
      ctx.moveTo(x + pts[0][0], y + pts[0][1]);
      for (let i = 1; i < pts.length; i++) ctx.lineTo(x + pts[i][0], y + pts[i][1]);
      ctx.stroke();
    };
    const fixedWing = (k) => {
      seg([[0, -ih * 0.8 * k], [0, ih * 0.75 * k]]);
      seg([[-ib * 0.85 * k, -ih * 0.05 * k], [0, -ih * 0.3 * k], [ib * 0.85 * k, -ih * 0.05 * k]]);
      seg([[-ib * 0.35 * k, ih * 0.7 * k], [ib * 0.35 * k, ih * 0.7 * k]]);
    };
    const bowtie = (k) => {
      ctx.beginPath();
      ctx.moveTo(x - ib * 0.8 * k, y - ih * 0.45 * k);
      ctx.lineTo(x + ib * 0.8 * k, y + ih * 0.45 * k);
      ctx.lineTo(x + ib * 0.8 * k, y - ih * 0.45 * k);
      ctx.lineTo(x - ib * 0.8 * k, y + ih * 0.45 * k);
      ctx.closePath();
      ctx.fill();
    };
    let drawn = true;
    if (sym.dim === "G") {
      if (has("U-C-I")) {
        seg([[-ib, -ih], [ib, ih]]);
        seg([[-ib, ih], [ib, -ih]]);
        if (fn.includes("I-Z") || fn.includes("I-A")) {
          ctx.beginPath();
          ctx.ellipse(x, y, ib * 0.6, ih * 0.45, 0, 0, Math.PI * 2);
          ctx.stroke();
        }
      } else if (has("U-C-A")) {
        ctx.beginPath();
        ctx.ellipse(x, y, ib * 0.65, ih * 0.5, 0, 0, Math.PI * 2);
        ctx.stroke();
      } else if (has("U-C-R")) seg([[-ib, ih], [ib, -ih]]);
      else if (has("U-C-F")) {
        ctx.beginPath();
        ctx.arc(x, y, Math.max(1.8, ih * 0.3), 0, Math.PI * 2);
        ctx.fill();
      } else if (has("U-C-E")) {
        seg([[-ib * 0.6, ih * 0.35], [-ib * 0.6, -ih * 0.35], [ib * 0.6, -ih * 0.35], [ib * 0.6, ih * 0.35]]);
        seg([[0, -ih * 0.35], [0, ih * 0.35]]);
      } else if (has("U-C-D")) {
        ctx.beginPath();
        ctx.arc(x, y + ih, ib * 0.7, Math.PI * 1.15, Math.PI * 1.85);
        ctx.stroke();
      } else if (has("U-C-V")) bowtie(0.9);
      else if (has("U-C-S")) {
        seg([[-ib * 0.5, ih * 0.5], [0, -ih * 0.5], [ib * 0.5, ih * 0.5]]);
      } else if (has("U-S-M") || has("U-C-M") || fn.startsWith("I-M")) {
        seg([[0, -ih * 0.7], [0, ih * 0.7]]);
        seg([[-ih * 0.7, 0], [ih * 0.7, 0]]);
      } else if (has("U-S")) {
        seg([[-ib, ih * 0.55], [ib, ih * 0.55]]);
      } else if (has("U-C") || has("U-U")) {
        seg([[-ib * 0.4, 0], [ib * 0.4, 0]]);
      } else if (has("E-V")) {
        ctx.beginPath();
        ctx.moveTo(x - ib * 0.6, y - ih * 0.15);
        ctx.lineTo(x + ib * 0.6, y - ih * 0.15);
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(x - ib * 0.35, y + ih * 0.25, Math.max(1.4, ih * 0.18), 0, Math.PI * 2);
        ctx.arc(x + ib * 0.35, y + ih * 0.25, Math.max(1.4, ih * 0.18), 0, Math.PI * 2);
        ctx.fill();
      } else if (has("E-W")) {
        seg([[0, ih * 0.7], [0, -ih * 0.7]]);
        seg([[-ib * 0.3, -ih * 0.35], [0, -ih * 0.7], [ib * 0.3, -ih * 0.35]]);
      } else drawn = false;
    } else if (sym.dim === "A") {
      if (has("M-F-Q") || has("C-F-Q") || fn === "M-Q" || fn === "Q") {
        seg([[-ib * 0.8, -ih * 0.3], [0, ih * 0.3], [ib * 0.8, -ih * 0.3]]);
      } else if (has("M-H") || has("C-H") || fn === "H") bowtie(0.8);
      else if (has("M-F") || has("C-F") || fn === "F" || fn === "M" || fn === "C") {
        const k = 0.75;
        ctx.save();
        ctx.translate(0, ih * 0.15);
        fixedWing(k);
        ctx.restore();
      } else drawn = false;
    } else if (sym.dim === "S") {
      if (fn) {
        ctx.beginPath();
        ctx.moveTo(x - ib * 0.8, y - ih * 0.1);
        ctx.lineTo(x + ib * 0.8, y - ih * 0.1);
        ctx.lineTo(x + ib * 0.45, y + ih * 0.5);
        ctx.lineTo(x - ib * 0.45, y + ih * 0.5);
        ctx.closePath();
        ctx.stroke();
        seg([[0, -ih * 0.1], [0, -ih * 0.6]]);
      } else drawn = false;
    } else if (sym.dim === "U") {
      if (fn) {
        ctx.beginPath();
        ctx.ellipse(x, y, ib * 0.75, ih * 0.28, 0, 0, Math.PI * 2);
        ctx.fill();
      } else drawn = false;
    } else drawn = false;
    ctx.restore();
    return drawn;
  }

  const MilSym = {
    fill: FILL,
    parse: parse,
    draw(ctx, type, x, y, s, ink, opts) {
      const sym = parse(type);
      if (!sym) return null;
      const fp = framePaths(x, y, s, sym);
      ctx.save();
      if (fp.clip) ctx.clip(fp.clip);
      ctx.fillStyle = (opts && opts.fill) || FILL[sym.aff];
      ctx.fill(fp.fill);
      ctx.strokeStyle = ink;
      ctx.lineWidth = Math.max(1.2, s / 7);
      ctx.lineJoin = "round";
      if (sym.dashed) ctx.setLineDash([Math.max(3, s / 3), Math.max(2, s / 4)]);
      ctx.stroke(fp.line);
      ctx.restore();
      if (sym.dim === "P") {
        ctx.save();
        if (fp.clip) ctx.clip(fp.clip);
        ctx.clip(fp.fill);
        ctx.fillStyle = ink;
        ctx.fillRect(x - s * 3, y + fp.box.top - s, s * 6, s * 1.45);
        ctx.restore();
      }
      if (sym.ground === "installation" && sym.aff !== "friend") {
        ctx.save();
        ctx.fillStyle = ink;
        ctx.fillRect(x - fp.box.w * 0.3, y + fp.box.top - s * 0.4, fp.box.w * 0.6, s * 0.35);
        ctx.restore();
      }
      icon(ctx, x, y, s, sym, ink, fp.box);
      return { w: fp.box.w, top: fp.box.top, bottom: fp.box.bottom, aff: sym.aff };
    },
  };

  window.MilSym = MilSym;
})();
