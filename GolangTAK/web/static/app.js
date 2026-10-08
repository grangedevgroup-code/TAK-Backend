"use strict";

(function () {
  const S = {
    me: null,
    csrf: "",
    events: new Map(),
    chats: [],
    listeners: new Set(),
    ws: null,
    wsDelay: 1000,
    cleanup: null,
    page: "",
    modals: new Set(),
  };

  const root = document.getElementById("app");

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    let value;
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === undefined || v === null || v === false) continue;
        if (k === "class") el.className = v;
        else if (k === "value") value = v;
        else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
        else if (k === "checked" || k === "selected" || k === "disabled" || k === "multiple" || k === "required" || k === "readOnly") el[k] = !!v;
        else el.setAttribute(k, v === true ? "" : String(v));
      }
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid === undefined || kid === null || kid === false) continue;
      el.append(kid instanceof Node ? kid : String(kid));
    }
    if (value !== undefined) el.value = value;
    return el;
  }

  function clear(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
    return el;
  }

  async function api(method, path, body) {
    const opt = { method: method, headers: { "X-Requested-With": "GolangTAK" }, credentials: "same-origin" };
    if (S.csrf && method !== "GET") opt.headers["X-CSRF-Token"] = S.csrf;
    if (body instanceof Blob) {
      opt.body = body;
      opt.headers["Content-Type"] = body.type || "application/octet-stream";
    } else if (body !== undefined) {
      opt.headers["Content-Type"] = "application/json";
      opt.body = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetch(path, opt);
    } catch (e) {
      throw new Error("The server did not respond. Check that it is running.");
    }
    const text = await res.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch (e) {
      data = text;
    }
    if (res.status === 401 && path !== "/api/login" && path !== "/api/me/password") {
      S.me = null;
      showLogin();
      throw new Error("Please sign in again.");
    }
    if (!res.ok) {
      const msg = (data && data.error) || (typeof data === "string" && data.trim()) || res.statusText || "Request failed";
      throw new Error(msg);
    }
    return data;
  }

  function toast(msg, err) {
    let box = document.getElementById("toast");
    if (!box) {
      box = h("div", { id: "toast" });
      document.body.append(box);
    }
    const t = h("div", { class: err ? "err" : "" }, msg);
    box.append(t);
    setTimeout(() => t.remove(), err ? 8000 : 3500);
  }

  function fail(e) {
    toast(e && e.message ? e.message : String(e), true);
  }

  function pad(n) {
    return String(n).padStart(2, "0");
  }

  function fmtTime(v) {
    if (!v) return "-";
    const d = new Date(v);
    if (isNaN(d) || d.getFullYear() < 1971) return "-";
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + " " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }

  function fmtDate(v) {
    const t = fmtTime(v);
    return t === "-" ? t : t.slice(0, 10);
  }

  function fmtAgo(v) {
    if (!v) return "-";
    const d = new Date(v);
    if (isNaN(d) || d.getFullYear() < 1971) return "never";
    const s = Math.round((Date.now() - d.getTime()) / 1000);
    if (s < 5) return "now";
    if (s < 60) return s + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  }

  function fmtDuration(sec) {
    sec = Math.max(0, Math.floor(sec));
    const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
    if (d) return d + "d " + hh + "h";
    if (hh) return hh + "h " + m + "m";
    return m + "m " + (sec % 60) + "s";
  }

  function fmtBytes(n) {
    n = Number(n) || 0;
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) {
      n /= 1024;
      i++;
    }
    return (i ? n.toFixed(1) : n) + " " + u[i];
  }

  function fmtCoord(lat, lon) {
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) return "-";
    return lat.toFixed(5) + ", " + lon.toFixed(5);
  }

  function joined(v) {
    return (v || []).join(", ") || "-";
  }

  function splitList(s) {
    return String(s || "")
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
  }

  function enc(s) {
    return encodeURIComponent(s);
  }

  function qrImg(text) {
    return h("img", { src: "/api/qr?format=png&data=" + enc(text), alt: "QR code", width: 240, height: 240 });
  }

  function table(cols, rows, empty, onRow) {
    if (!rows.length) return h("div", { class: "empty" }, empty || "Nothing here yet.");
    return h(
      "div",
      { class: "table-wrap" },
      h(
        "table",
        null,
        h("thead", null, h("tr", null, cols.map((c) => h("th", { class: c.cls }, c.title)))),
        h(
          "tbody",
          null,
          rows.map((r) =>
            h(
              "tr",
              { class: onRow ? "click" : "", onclick: onRow ? (ev) => { if (ev.target.closest("button,a,input,select")) return; onRow(r); } : null },
              cols.map((c) => {
                const v = c.render ? c.render(r) : r[c.key];
                return h("td", { class: c.cls }, v === undefined || v === null || v === "" ? "-" : v);
              })
            )
          )
        )
      )
    );
  }

  function kv(pairs) {
    return h(
      "dl",
      { class: "kv" },
      pairs.filter(Boolean).map(([k, v]) => [h("dt", null, k), h("dd", null, v === undefined || v === null || v === "" ? "-" : v)])
    );
  }

  function btn(label, onclick, cls, ic) {
    return h("button", { type: "button", class: cls || "", onclick: onclick }, ic ? icon(ic, 16) : null, ic ? h("span", { class: "bl" }, label) : label);
  }

  function linkBtn(label, href, cls, ic) {
    return h("a", { class: "button" + (cls ? " " + cls : ""), href: href }, ic ? icon(ic, 16) : null, label);
  }

  function modal(title, body, actions) {
    const back = h("div", { class: "modal-back" });
    const close = () => {
      back.remove();
      document.removeEventListener("keydown", onKey);
      S.modals.delete(close);
    };
    const onKey = (ev) => {
      if (ev.key === "Escape") close();
    };
    S.modals.add(close);
    document.addEventListener("keydown", onKey);
    back.addEventListener("mousedown", (ev) => {
      if (ev.target === back) close();
    });
    const buttons = h("div", { class: "buttons" });
    const box = h("div", { class: "modal", role: "dialog", "aria-modal": "true" }, h("h2", null, title), body, buttons);
    for (const a of actions || [{ label: "Close" }]) {
      buttons.append(
        btn(
          a.label,
          async () => {
            if (!a.run) return close();
            try {
              const keep = await a.run();
              if (keep !== true) close();
            } catch (e) {
              fail(e);
            }
          },
          [a.primary ? "primary" : "", a.left ? "left" : ""].join(" ").trim()
        )
      );
    }
    back.append(box);
    document.body.append(back);
    const first = box.querySelector("input,select,textarea");
    if (first) first.focus();
    return close;
  }

  function confirmAction(title, text, label, run) {
    modal(title, h("p", null, text), [{ label: "Cancel" }, { label: label || "Confirm", primary: true, run: run }]);
  }

  function pageHead(main, title, lead, ...actions) {
    const acts = actions.flat().filter(Boolean);
    main.append(h("div", { class: "page-head" }, h("div", { class: "text" }, h("h1", null, title), lead ? h("p", { class: "lead" }, lead) : null), acts.length ? h("div", { class: "page-actions" }, acts) : null));
  }

  function go(hash) {
    return () => {
      location.hash = hash;
    };
  }

  function searchBox(box, placeholder) {
    const q = h("input", { type: "search", placeholder: placeholder || "Filter", "aria-label": placeholder || "Filter", autocomplete: "off" });
    const apply = () => {
      const f = q.value.trim().toLowerCase();
      for (const tr of box.querySelectorAll("tbody tr")) tr.style.display = !f || tr.textContent.toLowerCase().includes(f) ? "" : "none";
    };
    q.addEventListener("input", apply);
    return { el: q, apply: apply };
  }

  function field(label, input, hint) {
    const target = input.id ? input : input.querySelector && input.querySelector("input,select,textarea");
    return [h("label", { for: target && target.id ? target.id : undefined }, label), h("div", null, input, hint ? h("div", { class: "hint" }, hint) : null)];
  }

  function input(id, value, attrs) {
    return h("input", Object.assign({ id: id, value: value === undefined || value === null ? "" : value }, attrs || {}));
  }

  function checkbox(id, checked, label) {
    return h("label", { class: "check" }, h("input", { type: "checkbox", id: id, checked: !!checked }), h("span", null, label || ""));
  }

  function select(id, options, value) {
    return h(
      "select",
      { id: id },
      options.map((o) => {
        const [v, t] = Array.isArray(o) ? o : [o, o];
        return h("option", { value: v, selected: String(v) === String(value) }, t);
      })
    );
  }

  function val(form, id) {
    const el = form.querySelector("#" + id);
    if (!el) return undefined;
    if (el.type === "checkbox") return el.checked;
    return el.value.trim();
  }

  function num(form, id) {
    const v = Number(val(form, id));
    return Number.isFinite(v) ? v : 0;
  }

  function download(url) {
    const a = h("a", { href: url, download: "" });
    document.body.append(a);
    a.click();
    a.remove();
  }

  function copy(text) {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(() => toast("Copied"), () => toast("Copy failed", true));
      return;
    }
    const t = h("textarea", { style: "position:fixed;opacity:0" });
    t.value = text;
    document.body.append(t);
    t.select();
    try {
      document.execCommand("copy");
      toast("Copied");
    } catch (e) {
      toast("Copy failed", true);
    }
    t.remove();
  }

  function theme() {
    let t = "auto";
    try {
      t = localStorage.getItem("golangtak-theme") || "auto";
    } catch (e) {}
    if (t === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", t);
    return t;
  }

  function setTheme(t) {
    try {
      localStorage.setItem("golangtak-theme", t);
    } catch (e) {}
    theme();
  }

  function alertName(type) {
    const names = { "b-a-o-tbl": "911 alert", "b-a-o-pan": "Ring the bell", "b-a-o-opn": "Troops in contact", "b-a-o-c": "Custom alert", "b-a-g": "Geofence breach" };
    return names[type] || type;
  }

  function isLive(v) {
    return !v.stale || new Date(v.stale).getTime() > Date.now();
  }

  function emergencies() {
    const out = [];
    for (const v of S.events.values()) {
      if (v.type && v.type.startsWith("b-a-") && v.type !== "b-a-o-can" && isLive(v)) out.push(v);
    }
    return out;
  }

  async function refreshEvents() {
    try {
      const list = await api("GET", "/api/cot/latest");
      S.events.clear();
      for (const v of list) S.events.set(v.uid, v);
      notify({ refresh: true });
    } catch (e) {}
  }

  function notify(v) {
    for (const fn of S.listeners) {
      try {
        fn(v);
      } catch (e) {}
    }
    updateAlert();
  }

  let refreshTimer = null;

  function onStream(v) {
    if (!v || !v.type) return;
    if (v.type === "t-x-c-t" || v.type === "t-x-c-t-r") return;
    if (v.type === "t-x-d-d" || v.type === "b-a-o-can") {
      clearTimeout(refreshTimer);
      refreshTimer = setTimeout(refreshEvents, 400);
    }
    if (v.type.startsWith("b-t-f")) {
      S.chats.push(v);
      if (S.chats.length > 1000) S.chats.splice(0, S.chats.length - 1000);
    } else if (!v.type.startsWith("t-")) {
      S.events.set(v.uid, v);
    }
    notify(v);
  }

  function connectStream() {
    if (S.ws || !S.me) return;
    const proto = location.protocol === "https:" ? "wss://" : "ws://";
    let ws;
    try {
      ws = new WebSocket(proto + location.host + "/api/stream");
    } catch (e) {
      return;
    }
    S.ws = ws;
    ws.onopen = () => {
      S.wsDelay = 1000;
      setLive(true);
      refreshEvents();
    };
    ws.onmessage = (ev) => {
      try {
        onStream(JSON.parse(ev.data));
      } catch (e) {}
    };
    ws.onclose = () => {
      S.ws = null;
      setLive(false);
      if (!S.me) return;
      setTimeout(connectStream, S.wsDelay);
      S.wsDelay = Math.min(S.wsDelay * 2, 30000);
    };
  }

  function disconnectStream() {
    if (S.ws) {
      const ws = S.ws;
      S.ws = null;
      ws.onclose = null;
      ws.close();
    }
  }

  const PAGES = [
    { group: "Operations" },
    { id: "overview", title: "Overview", icon: "overview", render: pageOverview, keys: "home status dashboard" },
    { id: "map", title: "Map", icon: "map", render: pageMap, keys: "markers positions tracks" },
    { id: "chat", title: "Chat", icon: "chat", render: pageChat, keys: "messages" },
    { group: "Devices" },
    { id: "connect", title: "Connect a device", icon: "connect", render: pageConnect, keys: "qr code enroll package atak itak wintak" },
    { id: "clients", title: "Online now", icon: "online", render: pageClients, count: true, keys: "connected clients disconnect" },
    { id: "devices", title: "All devices", icon: "devices", render: pageDevices, keys: "history forget" },
    { group: "Shared data" },
    { id: "files", title: "Files", icon: "files", render: pageFiles, keys: "data packages upload" },
    { id: "missions", title: "Missions", icon: "missions", render: pageMissions, keys: "data sync" },
    { id: "video", title: "Video feeds", icon: "video", render: pageVideo, keys: "rtsp camera" },
    { group: "Administration", admin: true },
    { id: "performance", title: "Performance", icon: "pulse", admin: true, render: pagePerformance, keys: "cpu memory ram disk load health resources" },
    { id: "users", title: "Users", icon: "users", admin: true, render: pageUsers, keys: "accounts passwords certificates" },
    { id: "groups", title: "Groups", icon: "groups", admin: true, render: pageGroups, keys: "channels teams" },
    { id: "links", title: "Server links", icon: "links", admin: true, render: pageLinks, keys: "federation peers tak server opentakserver freetakserver" },
    { id: "plugins", title: "Plugins and profiles", icon: "plugins", admin: true, render: pagePlugins, keys: "apk update server preferences" },
    { id: "settings", title: "Settings", icon: "settings", admin: true, render: pageSettings, keys: "configuration" },
    { id: "logs", title: "Logs", icon: "logs", admin: true, render: pageLogs, keys: "errors" },
    { group: "Account" },
    { id: "tokens", title: "API tokens", icon: "tokens", render: pageTokens, keys: "bearer scripts" },
    { id: "account", title: "My account", icon: "account", render: pageAccount, keys: "password theme dark light sign out" },
  ];

  let alertEl = null;
  let countEl = null;
  let countTimer = null;
  let liveEl = null;
  let crumbEl = null;

  function mark(size) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    const s = String(size || 28);
    svg.setAttribute("width", s);
    svg.setAttribute("height", s);
    svg.setAttribute("viewBox", "0 0 32 32");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("class", "mark");
    const bg = document.createElementNS(ns, "rect");
    bg.setAttribute("width", "32");
    bg.setAttribute("height", "32");
    bg.setAttribute("fill", "currentColor");
    const g = document.createElementNS(ns, "path");
    g.setAttribute("d", "M10 10h12v12H10z M16 4v6 M16 22v6 M4 16h6 M22 16h6");
    g.setAttribute("fill", "none");
    g.style.stroke = "var(--canvas)";
    g.setAttribute("stroke-width", "2.4");
    svg.append(bg, g);
    return svg;
  }

  function setLive(on) {
    if (!liveEl) return;
    liveEl.classList.toggle("off", !on);
    liveEl.title = on ? "Receiving live updates from the server" : "Live updates paused. Reconnecting to the server.";
    clear(liveEl).append(h("span", { class: "dot", "aria-hidden": "true" }), h("span", { class: "lt" }, on ? "Live" : "Reconnecting"));
  }

  function updateAlert() {
    if (!alertEl) return;
    const list = emergencies();
    alertEl.style.display = list.length ? "" : "none";
    if (!list.length) return;
    const first = list[0];
    const text = list.length === 1 ? "Emergency: " + (first.callsign || first.uid) + ", " + alertName(first.type) : list.length + " active emergencies";
    clear(alertEl).append(icon("alert", 18), h("span", null, text), h("span", { class: "go" }, "View on map"));
  }

  function isDevice(c) {
    return !c.internal && c.kind !== "peer" && c.kind !== "federation";
  }

  async function updateCount() {
    if (!countEl || !S.me) return;
    try {
      const list = await api("GET", "/api/clients");
      countEl.textContent = String(list.filter(isDevice).length);
    } catch (e) {}
  }

  function openPalette() {
    if (document.querySelector(".palette")) return;
    const items = [];
    for (const p of PAGES) {
      if (!p.id || (p.admin && !S.me.admin)) continue;
      items.push({ title: p.title, where: "Page", icon: p.icon, hash: "#/" + p.id, keys: p.keys || "" });
    }
    if (S.me.admin) for (const s of SETTINGS_SECTIONS) items.push({ title: s.title, where: "Settings", icon: "settings", hash: "#/settings/" + s.id, keys: s.keys || "" });
    const q = h("input", { type: "text", placeholder: "Go to a page or setting", "aria-label": "Go to a page or setting", autocomplete: "off", spellcheck: "false" });
    const list = h("ul", { role: "listbox" });
    const back = h("div", { class: "modal-back" });
    const box = h(
      "div",
      { class: "modal palette", role: "dialog", "aria-modal": "true", "aria-label": "Go to" },
      h("div", { class: "q" }, icon("search", 18), q),
      list,
      h("div", { class: "foot" }, h("span", null, h("kbd", null, "↑"), " ", h("kbd", null, "↓"), " to move"), h("span", null, h("kbd", null, "Enter"), " to open"), h("span", null, h("kbd", null, "Esc"), " to close"))
    );
    let shown = [];
    let at = 0;
    const close = () => {
      back.remove();
      document.removeEventListener("keydown", onKey, true);
      S.modals.delete(close);
    };
    S.modals.add(close);
    const pick = (it) => {
      close();
      if (it) location.hash = it.hash;
    };
    const draw = () => {
      const f = q.value.trim().toLowerCase();
      shown = items.filter((it) => !f || (it.title + " " + it.where + " " + it.keys).toLowerCase().includes(f));
      shown.sort((a, b) => Number(!a.title.toLowerCase().startsWith(f)) - Number(!b.title.toLowerCase().startsWith(f)));
      at = Math.min(at, Math.max(0, shown.length - 1));
      clear(list);
      if (!shown.length) list.append(h("li", { class: "none" }, "Nothing matches \"" + q.value.trim() + "\"."));
      shown.forEach((it, i) =>
        list.append(h("li", { class: i === at ? "on" : "", role: "option", "aria-selected": String(i === at), onmousemove: () => { if (at !== i) { at = i; draw(); } }, onmousedown: (ev) => (ev.preventDefault(), pick(it)) }, icon(it.icon, 16), h("span", { class: "t" }, it.title), h("span", { class: "where" }, it.where)))
      );
      const on = list.querySelector(".on");
      if (on) on.scrollIntoView({ block: "nearest" });
    };
    const onKey = (ev) => {
      if (ev.key === "Escape") {
        ev.preventDefault();
        close();
      } else if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
        ev.preventDefault();
        if (shown.length) at = (at + (ev.key === "ArrowDown" ? 1 : shown.length - 1)) % shown.length;
        draw();
      } else if (ev.key === "Enter") {
        ev.preventDefault();
        pick(shown[at]);
      }
    };
    q.addEventListener("input", () => {
      at = 0;
      draw();
    });
    document.addEventListener("keydown", onKey, true);
    back.addEventListener("mousedown", (ev) => {
      if (ev.target === back) close();
    });
    back.append(box);
    document.body.append(back);
    draw();
    q.focus();
  }

  document.addEventListener("keydown", (ev) => {
    if (!S.me || !document.getElementById("main")) return;
    const typing = ev.target.closest && ev.target.closest("input,textarea,select,[contenteditable]");
    if ((ev.key === "k" && (ev.ctrlKey || ev.metaKey)) || (ev.key === "/" && !typing && !ev.ctrlKey && !ev.metaKey && !ev.altKey)) {
      ev.preventDefault();
      openPalette();
    }
  });

  function layout() {
    clear(root);
    const side = h("aside", { class: "side", id: "side", "aria-label": "Navigation" });
    alertEl = h("a", { class: "banner", href: "#/map", style: "display:none", role: "alert" });
    liveEl = h("span", { class: "live", role: "status" });
    crumbEl = h("div", { class: "crumbs" });
    setLive(!!(S.ws && S.ws.readyState === 1));
    const mac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
    const setOpen = (open) => {
      side.classList.toggle("open", open);
      menuBtn.setAttribute("aria-expanded", String(open));
    };
    const menuBtn = btn("Menu", () => setOpen(!side.classList.contains("open")), "menu icon-only ghost", "menu");
    menuBtn.setAttribute("aria-controls", "side");
    menuBtn.setAttribute("aria-label", "Menu");
    menuBtn.setAttribute("aria-expanded", "false");
    const findMobile = btn("Search", openPalette, "mfind icon-only ghost", "search");
    findMobile.setAttribute("aria-label", "Go to a page or setting");
    const serverName = S.me.server || "GolangTAK";
    const nav = h("nav", { "aria-label": "Sections" });
    countEl = null;
    for (const p of PAGES) {
      if (p.admin && !S.me.admin) continue;
      if (p.group) {
        nav.append(h("div", { class: "group" }, p.group));
        continue;
      }
      const count = p.count ? h("span", { class: "count", title: "Connected now" }) : null;
      if (count) countEl = count;
      nav.append(h("a", { href: "#/" + p.id, "data-page": p.id, onclick: () => setOpen(false) }, icon(p.icon), h("span", { class: "t" }, p.title), count));
    }
    const signOutBtn = btn("Sign out", signOut, "icon-only ghost", "signout");
    signOutBtn.setAttribute("aria-label", "Sign out");
    signOutBtn.title = "Sign out";
    side.append(
      h("a", { class: "brand", href: "#/overview" }, mark(30), h("span", null, h("span", { class: "name" }, "GolangTAK"), h("span", { class: "srv", title: serverName }, serverName))),
      h("button", { type: "button", class: "find", onclick: openPalette, "aria-label": "Go to a page or setting" }, icon("search", 16), h("span", { class: "label" }, "Go to..."), h("kbd", null, mac ? "⌘K" : "Ctrl K")),
      nav,
      h(
        "div",
        { class: "me" },
        h("a", { class: "who", href: "#/account", title: "My account", onclick: () => setOpen(false) }, h("span", { class: "avatar", "aria-hidden": "true" }, (S.me.user || "?").slice(0, 1)), h("span", { style: "min-width:0" }, h("b", null, S.me.user), h("small", null, S.me.admin ? "Administrator" : "User"))),
        signOutBtn
      )
    );
    const main = h("main", { id: "main", tabindex: "-1" });
    const strip = h(
      "div",
      { class: "strip" },
      h("a", { class: "skip", href: "#main", onclick: (ev) => (ev.preventDefault(), document.getElementById("main").focus()) }, "Skip to content"),
      menuBtn,
      h("a", { class: "mbrand", href: "#/overview" }, mark(22), "GolangTAK"),
      crumbEl,
      h("span", { class: "spacer" }),
      liveEl,
      findMobile
    );
    const column = h("div", { class: "main", onmousedown: () => side.classList.contains("open") && setOpen(false) }, strip, alertEl, main);
    root.append(h("div", { class: "app" }, side, column));
    updateAlert();
    clearInterval(countTimer);
    countTimer = setInterval(updateCount, 10000);
    updateCount();
  }

  function setCrumbs(page, extra) {
    if (!crumbEl) return;
    let group = "";
    for (const p of PAGES) {
      if (p.group) group = p.group;
      if (p === page) break;
    }
    const parts = [];
    if (group) parts.push(h("span", null, group), h("span", { class: "sep" }, "/"));
    if (extra) parts.push(h("a", { href: "#/" + page.id }, page.title), h("span", { class: "sep" }, "/"), h("b", null, extra));
    else parts.push(h("b", null, page.title));
    clear(crumbEl).append(...parts);
  }

  async function route() {
    if (!S.me) return;
    const hash = location.hash.replace(/^#\/?/, "");
    const [id, ...rest] = hash.split("/");
    let page = PAGES.find((p) => p.id && p.id === id && (!p.admin || S.me.admin));
    if (!page) {
      page = PAGES.find((p) => p.id);
      if (id) {
        location.replace("#/" + page.id);
        return;
      }
    }
    if (S.cleanup) {
      try {
        S.cleanup();
      } catch (e) {}
      S.cleanup = null;
    }
    S.listeners.clear();
    for (const close of Array.from(S.modals)) close();
    if (!document.getElementById("main")) layout();
    const side = document.querySelector(".side");
    if (side) side.classList.remove("open");
    setCrumbs(page, page.id === "missions" && rest[0] ? decodeURIComponent(rest[0]) : "");
    for (const a of document.querySelectorAll(".side nav a")) {
      a.classList.toggle("active", a.dataset.page === page.id);
      if (a.dataset.page === page.id) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
    const main = clear(document.getElementById("main"));
    if (S.page !== page.id) window.scrollTo(0, 0);
    S.page = page.id;
    document.title = page.title + " - GolangTAK";
    try {
      const c = await page.render(main, rest.map(decodeURIComponent));
      if (typeof c === "function") S.cleanup = c;
    } catch (e) {
      main.append(h("div", { class: "notice" }, "Could not load this page: " + e.message));
    }
  }

  function showLogin(message) {
    disconnectStream();
    clearInterval(countTimer);
    S.me = null;
    S.csrf = "";
    if (S.cleanup) {
      try {
        S.cleanup();
      } catch (e) {}
      S.cleanup = null;
    }
    clear(root);
    const err = h("div", { class: "err", role: "alert" }, message || "");
    const form = h(
      "form",
      { class: "login", autocomplete: "on" },
      mark(40),
      h("h1", null, "Sign in to GolangTAK"),
      h("p", { class: "lead" }, "Manage devices, users and links on this server."),
      h("label", { for: "u" }, "User name"),
      h("input", { id: "u", name: "username", autocomplete: "username", required: true, autocapitalize: "none", spellcheck: "false" }),
      h("label", { for: "p" }, "Password"),
      h("input", { id: "p", name: "password", type: "password", autocomplete: "current-password", required: true }),
      h("button", { type: "submit", class: "primary" }, "Sign in"),
      err
    );
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      err.textContent = "";
      try {
        const r = await api("POST", "/api/login", { username: form.querySelector("#u").value.trim(), password: form.querySelector("#p").value });
        S.csrf = r.csrf;
        await boot();
      } catch (e) {
        err.textContent = e.message === "invalid credentials" ? "Wrong user name or password." : e.message;
      }
    });
    form.append(h("div", { class: "foot" }, "GolangTAK is open source and not affiliated with tak.gov or the TAK Product Center."));
    root.append(h("div", { class: "login-wrap" }, form));
    form.querySelector("#u").focus();
  }

  async function signOut() {
    try {
      await api("POST", "/api/logout");
    } catch (e) {}
    showLogin("Signed out.");
  }

  async function boot() {
    theme();
    try {
      S.me = await api("GET", "/api/me");
    } catch (e) {
      if (!S.me) showLogin(e.message === "Please sign in again." ? "" : e.message);
      return;
    }
    S.csrf = S.me.csrf || S.csrf;
    layout();
    connectStream();
    await route();
  }

  function panel(title, meta, ...body) {
    const flush = body.length === 1 && body[0] && body[0].classList && (body[0].classList.contains("table-wrap") || body[0].classList.contains("empty"));
    return h("section", { class: "panel" }, h("header", null, h("h2", null, title), meta || null), h("div", { class: "pb" + (flush ? " flush" : "") }, body));
  }

  function pill(state, text) {
    const s = String(state || "").toLowerCase();
    let cls = "";
    if (/^(connected|running|listening|online|ok|healthy|enabled)/.test(s)) cls = "ok";
    else if (/(connecting|starting|waiting|reconnect|retry|idle)/.test(s)) cls = "warn";
    else if (/(problem|error|fail|refused|down|stopped|disconnected|denied)/.test(s)) cls = "bad";
    return h("span", { class: "pill " + cls }, text || state || "unknown");
  }

  function fmtPct(v) {
    return (Number(v) || 0).toFixed(Number(v) >= 10 ? 0 : 1) + "%";
  }

  function fmtRate(v, unit) {
    v = Number(v) || 0;
    if (unit === "B") return fmtBytes(v) + "/s";
    return (v >= 100 ? Math.round(v) : v.toFixed(1)) + " " + unit + "/s";
  }

  function level(pct) {
    return pct >= 90 ? "bad" : pct >= 75 ? "warn" : "";
  }

  function meter(label, used, total, detail) {
    const pct = total > 0 ? Math.min(100, (used / total) * 100) : 0;
    const lv = level(pct);
    return h(
      "div",
      { class: "meter " + lv, role: "meter", "aria-label": label, "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": pct.toFixed(0) },
      h("div", { class: "row" }, h("span", null, label, lv ? h("span", { class: "state" }, lv === "bad" ? "  Critical" : "  High") : null), h("span", null, fmtPct(pct))),
      h("div", { class: "track" }, h("div", { class: "fill", style: "width:" + pct.toFixed(1) + "%" })),
      h("div", { class: "row small" }, h("span", { class: "muted" }, detail || ""), h("span", null, ""))
    );
  }

  function lineChart(points, opts) {
    const ns = "http://www.w3.org/2000/svg";
    const el = (tag, attrs) => {
      const e = document.createElementNS(ns, tag);
      for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, String(v));
      return e;
    };
    const wrap = h("div", { class: "chart" });
    const tip = h("div", { class: "tip" });
    let lastW = 0;
    const build = () => {
    const W = Math.max(240, Math.round(wrap.clientWidth || 600)), H = 170, L = 44, R = 70, T = 8, B = 22;
    if (W === lastW) return;
    lastW = W;
    const svg = el("svg", { viewBox: "0 0 " + W + " " + H, width: W, height: H, role: "img", "aria-label": opts.label });
    const vals = points.map((p) => p.v);
    let max = opts.max || Math.max(1, ...vals) * 1.15;
    const step = opts.bytes ? byteStep(max / 4) : niceStep(max / 4);
    max = Math.max(step * 4, opts.max || 0);
    const x = (i) => L + (points.length > 1 ? (i / (points.length - 1)) * (W - L - R) : 0);
    const y = (v) => T + (1 - v / max) * (H - T - B);
    for (let k = 0; k <= 4; k++) {
      const v = (max / 4) * k;
      svg.append(el("line", { class: "gl", x1: L, x2: W - R, y1: y(v), y2: y(v) }));
      const t = el("text", { class: "tick", x: L - 8, y: y(v) + 4, "text-anchor": "end" });
      t.textContent = opts.fmtAxis(v);
      svg.append(t);
    }
    if (points.length > 1) {
      const secs = Math.round((points[points.length - 1].t - points[0].t) / 1000);
      const t0 = el("text", { class: "tick", x: L, y: H - 4 });
      t0.textContent = secs < 120 ? secs + " s ago" : Math.round(secs / 60) + " min ago";
      const t1 = el("text", { class: "tick", x: W - R, y: H - 4, "text-anchor": "end" });
      t1.textContent = "now";
      svg.append(t0, t1);
      const d = points.map((p, i) => (i ? "L" : "M") + x(i).toFixed(1) + " " + y(p.v).toFixed(1)).join(" ");
      svg.append(el("path", { class: "area", d: d + " L" + x(points.length - 1).toFixed(1) + " " + y(0) + " L" + x(0) + " " + y(0) + " Z" }));
      svg.append(el("path", { class: "line", d: d }));
      const last = points[points.length - 1];
      const lab = el("text", { class: "tick", x: x(points.length - 1) + 10, y: y(last.v) + 4, style: "fill:var(--text);font-weight:600" });
      lab.textContent = opts.fmt(last.v);
      svg.append(lab);
    }
    const xh = el("line", { class: "xh", y1: T, y2: H - B, style: "display:none" });
    const dot = el("rect", { class: "end", width: 8, height: 8, style: "display:none" });
    svg.append(xh, dot);
    const hit = el("rect", { class: "hit", x: L, y: T, width: W - L - R, height: H - T - B, tabindex: "0" });
    svg.append(hit);
    const show = (i) => {
      if (i < 0 || i >= points.length) return;
      const p = points[i];
      const px = x(i), py = y(p.v);
      xh.setAttribute("x1", px);
      xh.setAttribute("x2", px);
      xh.style.display = "";
      dot.setAttribute("x", px - 4);
      dot.setAttribute("y", py - 4);
      dot.style.display = "";
      const r = svg.getBoundingClientRect();
      clear(tip).append(h("b", null, opts.fmt(p.v)), h("span", null, fmtTime(p.t).slice(11)));
      tip.style.left = px.toFixed(0) + "px";
      tip.style.top = (py - 12).toFixed(0) + "px";
      tip.style.display = "block";
    };
    const hide = () => {
      xh.style.display = dot.style.display = "none";
      tip.style.display = "none";
    };
    let cur = points.length - 1;
    hit.addEventListener("pointermove", (ev) => {
      const r = svg.getBoundingClientRect();
      const vx = ev.clientX - r.left;
      cur = Math.round(((vx - L) / (W - L - R)) * (points.length - 1));
      show(Math.max(0, Math.min(points.length - 1, cur)));
    });
    hit.addEventListener("pointerleave", hide);
    hit.addEventListener("focus", () => show((cur = points.length - 1)));
    hit.addEventListener("blur", hide);
    hit.addEventListener("keydown", (ev) => {
      if (ev.key === "ArrowLeft" || ev.key === "ArrowRight") {
        ev.preventDefault();
        cur = Math.max(0, Math.min(points.length - 1, cur + (ev.key === "ArrowLeft" ? -1 : 1)));
        show(cur);
      }
    });
    clear(wrap).append(svg, tip);
    };
    requestAnimationFrame(build);
    if (window.ResizeObserver) {
      const ro = new ResizeObserver(() => build());
      ro.observe(wrap);
    }
    return wrap;
  }

  function byteStep(raw) {
    let u = 1;
    while (raw / u >= 1024) u *= 1024;
    return niceStep(raw / u) * u;
  }

  function niceStep(raw) {
    if (!(raw > 0)) return 1;
    const p = Math.pow(10, Math.floor(Math.log10(raw)));
    const n = raw / p;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
  }

  function perfMeters(pf) {
    const sys = pf.system || {}, cur = pf.current || {};
    const out = [];
    if (pf.process && pf.process.cpuMeasured) out.push(meter("GolangTAK CPU", cur.cpu || 0, 100, "of " + sys.cpus + " CPU cores"));
    if (sys.cpuMeasured) out.push(meter("System CPU", cur.systemCpu || 0, 100, "all processes"));
    if (sys.memoryTotal && sys.memoryAvailable !== undefined) out.push(meter("System memory", sys.memoryTotal - sys.memoryAvailable, sys.memoryTotal, fmtBytes(sys.memoryTotal - sys.memoryAvailable) + " of " + fmtBytes(sys.memoryTotal)));
    else if (sys.memoryTotal) out.push(meter("GolangTAK memory", pf.process.memory, sys.memoryTotal, fmtBytes(pf.process.memory) + " of " + fmtBytes(sys.memoryTotal)));
    if (sys.disk) out.push(meter("Disk", sys.disk.total - sys.disk.free, sys.disk.total, fmtBytes(sys.disk.free) + " free of " + fmtBytes(sys.disk.total)));
    return out;
  }

  async function pageOverview(main) {
    const [st, em, clients, pf] = await Promise.all([
      api("GET", "/api/status"),
      api("GET", "/api/emergencies").catch(() => []),
      api("GET", "/api/clients").catch(() => []),
      S.me.admin ? api("GET", "/api/performance").catch(() => null) : null,
    ]);
    const online = clients.filter(isDevice);
    pageHead(main, "Overview", st.name + " is running. Up " + fmtDuration(st.uptimeSeconds) + ", version " + st.version + ".", btn("Open map", go("#/map"), "", "map"), btn("Connect a device", go("#/connect"), "primary", "connect"));

    if (S.me.admin) {
      const loopback = !st.address || /^(127\.|localhost$|::1$)/.test(st.address);
      const steps = [
        { done: !S.me.initialPassword, what: "Change the generated administrator password", hash: "#/account", action: "Change password" },
        { done: !loopback, what: "Set the address devices use to reach this server (now " + (st.address || "not set") + ")", hash: "#/settings/general", action: "Set address" },
        { done: st.users > 1, what: "Add a user for each person or team", hash: "#/users", action: "Add users" },
        { done: st.devices > 0, what: "Connect the first device", hash: "#/connect", action: "Connect a device" },
      ];
      const done = steps.filter((s) => s.done).length;
      if (done < steps.length) {
        main.append(
          h(
            "div",
            { class: "checklist" },
            h("div", { class: "head" }, h("b", null, "Finish setting up"), h("span", { class: "meter" }, h("span", { class: "bar" }, h("span", { style: "width:" + (done / steps.length) * 100 + "%" })), done + " of " + steps.length + " done")),
            h(
              "ol",
              null,
              steps.map((s) => h("li", { class: s.done ? "done" : "" }, h("span", { class: "box", "aria-hidden": "true" }, s.done ? icon("check", 13) : null), h("span", { class: "what" }, s.what, h("span", { class: "sr" }, s.done ? " (done)" : " (to do)")), s.done ? null : h("a", { class: "button small", href: s.hash }, s.action)))
            )
          )
        );
      }
    }

    const stat = (n, label, hash, ic, sub, bad) => h(hash ? "a" : "div", { class: "stat" + (bad ? " bad" : ""), href: hash || undefined }, h("div", { class: "sh" }, h("span", null, label), icon(ic, 16)), h("div", { class: "n" }, n), sub ? h("div", { class: "sub" }, sub) : null);
    const cur = pf && pf.current;
    main.append(
      h(
        "div",
        { class: "stats" },
        stat(online.length, "Online now", "#/clients", "online", st.devices + " devices seen in total"),
        stat(em.length, "Emergencies", "#/map", "alert", em.length ? "Active now" : "None active", em.length > 0),
        stat(st.missions, "Missions", "#/missions", "missions", st.files + " shared files"),
        cur ? stat(fmtPct(cur.cpu), "Server CPU", "#/performance", "cpu", fmtRate(cur.messages, "msg")) : stat(st.users, "Users", S.me.admin ? "#/users" : null, "users"),
        cur ? stat(fmtBytes(cur.memory), "Server memory", "#/performance", "memory", pf.system.memoryTotal ? "of " + fmtBytes(pf.system.memoryTotal) + " installed" : "in use") : null
      )
    );

    online.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
    const name = (c) => (c.info && c.info.callsign) || c.name || c.remote;
    main.append(
      h(
        "div",
        { class: "cols" },
        panel(
          "Online now",
          h("a", { class: "meta", href: "#/clients" }, online.length > 8 ? "View all " + online.length : "View list"),
          table(
            [
              { title: "Callsign", cls: "nowrap", render: (r) => h("b", null, name(r)) },
              { title: "Software", render: (r) => (r.info ? [r.info.platform, r.info.version].filter(Boolean).join(" ") : "") || r.kind },
              { title: "Battery", cls: "num", render: (r) => (r.info && r.info.battery ? r.info.battery + "%" : "-") },
              { title: "Last seen", cls: "nowrap", render: (r) => fmtAgo(r.lastSeen) },
            ],
            online.slice(0, 8),
            h("span", null, "No devices are connected. ", h("a", { href: "#/connect" }, "Connect a device"), " to get started."),
            () => (location.hash = "#/clients")
          )
        ),
        panel(
          "Active emergencies",
          em.length ? pill("problem", em.length + " active") : pill("ok", "All clear"),
          table(
            [
              { title: "Callsign", render: (r) => h("b", null, r.callsign || "-") },
              { title: "Alert", render: (r) => alertName(r.type) },
              { title: "Position", render: (r) => h("span", { class: "mono small" }, fmtCoord(r.lat, r.lon)) },
              { title: "Since", cls: "nowrap", render: (r) => fmtAgo(r.time) },
            ],
            em,
            "No active emergencies.",
            () => (location.hash = "#/map")
          )
        )
      )
    );

    const links = [];
    for (const p of st.peers || []) links.push({ name: p.name, kind: "Server link", state: p.state, detail: p.error || p.url, hash: "#/links" });
    if (st.federation && st.federation.enabled) links.push({ name: "Federation", kind: "TAK Server federation", state: "listening", detail: "Port " + (st.ports || {}).federation, hash: "#/links" });
    const mesh = st.meshtastic || {};
    if (mesh.enabled) {
      const problem = mesh.brokerError || mesh.upstreamError;
      links.push({ name: "Meshtastic", kind: "LoRa mesh", state: problem ? "problem" : "running", detail: problem || (mesh.nodes || []).length + " nodes heard, " + mesh.packetsIn + " packets in, " + mesh.packetsOut + " out", hash: "#/settings/meshtastic" });
    }
    for (const f of (st.feeds || []).filter((x) => x.enabled)) links.push({ name: f.name === "adsb" ? "ADS-B aircraft" : "AIS ships", kind: "Data feed", state: f.error ? "problem" : "running", detail: f.error || f.items + " items, updated " + fmtAgo(f.lastOk), hash: "#/settings/feeds" });

    const right = pf
      ? panel("Server load", h("a", { class: "meta", href: "#/performance" }, "Details"), h("div", { class: "meters" }, perfMeters(pf)))
      : panel("Server", null, kv([["Host", st.hostname], ["System", st.os + "/" + st.arch], ["Started", fmtTime(st.started)]]));
    main.append(
      h(
        "div",
        { class: "cols" },
        panel(
          "Links and integrations",
          S.me.admin ? h("a", { class: "meta", href: "#/links" }, "Manage") : null,
          table(
            [
              { title: "Name", cls: "nowrap", render: (r) => h("b", null, r.name) },
              { title: "Kind", cls: "nowrap", key: "kind" },
              { title: "State", cls: "nowrap", render: (r) => pill(r.state) },
              { title: "Detail", render: (r) => h("span", { class: "small muted" }, r.detail || "-") },
            ],
            links,
            S.me.admin ? h("span", null, "Nothing linked yet. Connect other servers under ", h("a", { href: "#/links" }, "Server links"), ", or turn on ", h("a", { href: "#/settings/meshtastic" }, "Meshtastic"), " and ", h("a", { href: "#/settings/feeds" }, "data feeds"), ".") : "No links to other servers.",
            S.me.admin ? (r) => (location.hash = r.hash) : null
          )
        ),
        right
      )
    );

    const p = st.ports || {};
    const portRows = [
      ["TAK SSL (TLS)", p.tls, "ATAK, WinTAK, iTAK, TAK Aware with certificates"],
      ["TAK TCP", p.tcp, st.allowAnonymous ? "Unencrypted, no sign-in" : "Disabled for unsigned clients"],
      ["TAK TCP (second port)", p.tcpAlt, "Unencrypted"],
      ["UDP", p.udp, "Unencrypted datagrams"],
      ["Certificate enrollment", p.enroll, "HTTPS, sign in with user name and password"],
      ["Web and API (HTTPS)", p.https, "Marti API with client certificates"],
      ["Web and API (HTTP)", p.http, "Marti API and this dashboard"],
      ["WebSocket CoT", p.websocket, "Browser and TAK-compatible software"],
      ["FreeTAKServer API", p.api, "REST API compatible with FreeTAKServer"],
      ["Federation", st.federation && st.federation.enabled ? p.federation : 0, "Server-to-server"],
      ["Meshtastic MQTT", mesh.enabled ? mesh.brokerPort : 0, "Meshtastic gateway nodes"],
    ].filter((r) => r[1] > 0);
    const kinds = Object.entries(st.clientsByKind || {}).map(([k, v]) => k + " " + v).join(", ");
    const more = (title, ...body) => h("details", { class: "more" }, h("summary", null, title), h("div", { class: "inner" }, body));
    main.append(
      more("Ports", table([{ title: "Service", render: (r) => r[0] }, { title: "Port", render: (r) => h("span", { class: "mono" }, r[1]) }, { title: "Used by", render: (r) => r[2] }], portRows)),
      more(
        "Server details",
        kv([
          ["Name", st.name],
          ["Address", st.address],
          ["Certificate names", joined(st.serverNames)],
          ["Host", st.hostname + " (" + st.os + "/" + st.arch + ", " + st.cpus + " CPU)"],
          ["Started", fmtTime(st.started)],
          ["Connections by type", kinds || "none"],
          ["Events handled", String(st.events)],
          ["Data directory", h("span", { class: "mono" }, st.dataDir)],
          ["Stored files", fmtBytes(st.filesBytes) + " in " + st.files + " files"],
          ["History", fmtBytes(st.historyBytes) + " over " + st.historyDays + " days"],
        ])
      ),
      more(
        "Certificates",
        kv([
          ["Certificate authority", st.caSubject],
          ["Fingerprint (SHA-256)", h("span", { class: "mono break" }, st.caFingerprint)],
          ["Authority valid until", fmtDate(st.caExpires)],
          ["Server certificate valid until", fmtDate(st.serverCertExpires)],
        ])
      ),
      mesh.enabled
        ? more(
            "Meshtastic nodes",
            table([{ title: "Node", render: (r) => r.callsign || r.name || r.id }, { title: "ID", render: (r) => h("span", { class: "mono small" }, r.id) }, { title: "Position", render: (r) => h("span", { class: "mono small" }, fmtCoord(r.lat, r.lon)) }, { title: "Battery", render: (r) => (r.battery ? r.battery + "%" : "-") }, { title: "Last heard", render: (r) => fmtAgo(r.lastSeen) }], mesh.nodes || [], "No mesh nodes heard yet.")
          )
        : null
    );
  }

  async function pagePerformance(main) {
    pageHead(main, "Performance", "How hard this server is working. Sampled every few seconds, with the last ten minutes kept in memory.");
    const body = h("div");
    main.append(body);
    const draw = (pf) => {
      const sys = pf.system || {}, pr = pf.process || {}, rt = pf.runtime || {}, tr = pf.traffic || {};
      const hist = pf.history || [];
      const series = (key) => hist.map((s) => ({ t: s.t, v: Number(s[key]) || 0 }));
      const cur = pf.current || {};
      const chartPanel = (title, key, value, sub, opts) => panel(title, h("span", { class: "meta" }, sub), h("div", { class: "cbox" }, h("div", { class: "now" }, h("b", null, value), h("span", null, opts.caption || "")), hist.length > 1 ? lineChart(series(key), opts) : h("div", { class: "empty" }, "Collecting samples. The chart appears in a few seconds.")));
      const pctOpts = (label) => ({ label: label, max: 100, fmt: fmtPct, fmtAxis: (v) => v.toFixed(0) + "%" });
      const charts = [];
      if (pr.cpuMeasured) charts.push(chartPanel("GolangTAK CPU", "cpu", fmtPct(cur.cpu), "share of all " + sys.cpus + " cores", Object.assign(pctOpts("GolangTAK CPU use over time"), { caption: "now" })));
      if (sys.cpuMeasured) charts.push(chartPanel("System CPU", "systemCpu", fmtPct(cur.systemCpu), "every process on the machine", Object.assign(pctOpts("System CPU use over time"), { caption: "now" })));
      charts.push(chartPanel("GolangTAK memory", "memory", fmtBytes(cur.memory || pr.memory), pr.memoryIsRss ? "resident in RAM" : "reserved by the Go runtime", { label: "GolangTAK memory over time", bytes: true, fmt: fmtBytes, fmtAxis: (v) => fmtBytes(v).replace(".0 ", " "), caption: "now" }));
      charts.push(chartPanel("Messages", "messages", fmtRate(cur.messages, "msg"), "CoT events received", { label: "Messages per second over time", fmt: (v) => fmtRate(v, "msg"), fmtAxis: (v) => String(Math.round(v)), caption: "per second now" }));
      charts.push(chartPanel("Data sent", "bytesOut", fmtRate(cur.bytesOut, "B"), "to devices and links", { label: "Bytes sent per second over time", bytes: true, fmt: (v) => fmtRate(v, "B"), fmtAxis: (v) => fmtBytes(v).replace(".0 ", " "), caption: "now" }));
      charts.push(chartPanel("Connections", "clients", String(cur.clients || 0), "devices, links and listeners", { label: "Connections over time", fmt: (v) => String(Math.round(v)), fmtAxis: (v) => String(Math.round(v)), caption: "open now" }));
      clear(body).append(
        panel("Capacity", h("span", { class: "meta" }, sys.hostname + ", " + sys.os + "/" + sys.arch), h("div", { class: "meters" }, perfMeters(pf))),
        h("div", { class: "perf" }, charts),
        h(
          "div",
          { class: "cols" },
          panel(
            "Machine",
            null,
            kv([
              ["Host", sys.hostname],
              ["System", sys.os + " on " + sys.arch],
              ["CPU cores", String(sys.cpus)],
              ["Installed memory", sys.memoryTotal ? fmtBytes(sys.memoryTotal) : "not reported on this system"],
              ["Available memory", sys.memoryAvailable !== undefined ? fmtBytes(sys.memoryAvailable) : "not reported on this system"],
              ["Load average", sys.load ? sys.load.map((v) => v.toFixed(2)).join("  ") + "  (1, 5, 15 min)" : "not reported on this system"],
              ["Data disk", sys.disk ? fmtBytes(sys.disk.free) + " free of " + fmtBytes(sys.disk.total) : "not reported on this system"],
            ])
          ),
          panel(
            "GolangTAK process",
            null,
            kv([
              ["Process ID", h("span", { class: "mono" }, String(pr.pid))],
              ["Running for", fmtDuration(pr.uptimeSeconds)],
              ["Memory", fmtBytes(pr.memory) + (pr.memoryIsRss ? " resident" : " reserved")],
              ["Go heap in use", fmtBytes(rt.heapInUse)],
              ["Goroutines", String(rt.goroutines)],
              ["Garbage collections", rt.gcCycles + ", " + (rt.gcPauseTotalMs || 0).toFixed(1) + " ms paused in total"],
              ["Events received", String(tr.events)],
              ["Deliveries", String(tr.delivered) + ", " + fmtBytes(tr.bytesOut) + " sent"],
              ["Go version", rt.go],
            ])
          )
        )
      );
    };
    const load = async () => draw(await api("GET", "/api/performance"));
    await load();
    const timer = setInterval(() => {
      if (document.querySelector(".chart .tip[style*='block']")) return;
      load().catch(() => {});
    }, 4000);
    return () => clearInterval(timer);
  }

  async function pageConnect(main) {
    const info = await api("GET", "/api/connect");
    let users = [{ name: S.me.user }];
    if (S.me.admin) {
      try {
        users = (await api("GET", "/api/users")).filter((u) => !u.disabled);
      } catch (e) {}
    }
    const hosts = Array.from(new Set([info.host].concat(info.hosts || []))).filter(Boolean);
    pageHead(main, "Connect a device", "Pick the address and account, then scan a QR code on the device, copy a connection package to it, or enter the settings by hand.");
    const hostSel = select("host", hosts, info.host);
    const userSel = select("cuser", users.map((u) => u.name), users.some((u) => u.name === S.me.user) ? S.me.user : users[0] && users[0].name);
    main.append(h("form", { class: "inline", onsubmit: (e) => e.preventDefault() }, h("label", { for: "host" }, "Server address"), hostSel, S.me.admin ? [h("label", { for: "cuser" }, "Account"), userSel] : null));
    if (S.me.admin && users.length === 0) main.append(h("p", { class: "muted" }, "Create a user first under Users."));
    const body = h("div");
    main.append(body);
    const draw = () => {
      const host = hostSel.value;
      const user = S.me.admin ? userSel.value : S.me.user;
      const tls = info.ports.tls, tcp = info.ports.tcp || info.ports.tcpAlt;
      const itak = (info.name || "GolangTAK").replace(/,/g, " ") + "," + host + "," + tls + ",SSL";
      clear(body);
      const enrollBox = h("div", { class: "qr" }, h("h3", null, "ATAK and WinTAK enrollment"), h("p", { class: "muted small" }, "Creates a one-time code for " + user + ". In ATAK: Settings, Network, Servers, Add, Scan QR."));
      const enrollOut = h("div");
      enrollBox.append(
        enrollOut,
        btn("Create enrollment QR code", async () => {
          try {
            const r = await api("POST", "/api/connect/enroll", { user: user, host: host, hours: 24 });
            clear(enrollOut).append(qrImg(r.atak), h("div", { class: "mono small break" }, r.atak), h("p", { class: "small" }, "One-time code ", h("b", { class: "mono" }, r.token), " valid until " + fmtTime(r.expires) + ". It also works as the password in iTAK."));
          } catch (e) {
            fail(e);
          }
        }, "primary", "connect")
      );
      const linkBox = h("div", { class: "qr" }, h("h3", null, "Download link QR code"), h("p", { class: "muted small" }, "A single-use link to a complete connection package with a certificate for " + user + ". Scan it with ATAK, or open it on the device."));
      const linkOut = h("div");
      const plain = checkbox("plain", false, "Use HTTP for devices that do not trust this server yet");
      linkBox.append(
        linkOut,
        h("div", { class: "small" }, plain),
        btn("Create download link", async () => {
          try {
            const r = await api("POST", "/api/package/link", { type: "cert", user: user, host: host, minutes: 30, plain: body.querySelector("#plain").checked });
            clear(linkOut).append(qrImg(r.import), h("div", { class: "mono small break" }, r.url), h("p", { class: "small" }, "Valid once, until " + fmtTime(r.expires) + ". ", btn("Copy link", () => copy(r.url), "link")));
          } catch (e) {
            fail(e);
          }
        }, "primary", "connect")
      );
      body.append(
        h("h2", null, "Scan a QR code"),
        h(
          "div",
          { class: "qr-grid" },
          enrollBox,
          h("div", { class: "qr" }, h("h3", null, "iTAK quick connect"), h("p", { class: "muted small" }, "In iTAK: Settings, Network, Servers, Connect with QR. iTAK then asks for a user name and password."), qrImg(itak), h("div", { class: "mono small" }, itak)),
          linkBox
        )
      );
      const pkg = (type) => "/api/package?type=" + type + "&user=" + enc(user) + "&host=" + enc(host);
      body.append(
        h("h2", null, "Or copy a connection package"),
        h("p", null, "Copy a package to the device and import it (ATAK: Import, Local SD; iTAK: Settings, Network, Servers, Upload server package; WinTAK: Import)."),
        h(
          "div",
          { class: "toolbar" },
          linkBtn("Certificate package for " + user, pkg("cert"), "primary", "download"),
          linkBtn("Enrollment package (signs in with password)", pkg("enroll"), "", "download"),
          info.ports.tcp || info.ports.tcpAlt ? linkBtn("TCP package (unencrypted)", pkg("tcp"), "", "download") : null
        )
      );
      body.append(
        h("h2", null, "Or enter the settings by hand"),
        kv([
          ["Address", h("span", { class: "mono" }, host)],
          ["SSL port", h("span", { class: "mono" }, tls + "  (protocol SSL / TLS)")],
          tcp ? ["TCP port", h("span", { class: "mono" }, tcp + "  (protocol TCP, unencrypted)")] : null,
          ["Enrollment", "Enable \"Enroll for client certificate\" and \"Use authentication\", then sign in as " + user + " (enrollment port " + info.ports.enroll + ")."],
          ["Truststore", h("span", null, h("a", { href: "/api/truststore.p12" }, "truststore.p12"), " password ", h("span", { class: "mono" }, info.truststorePassword))],
          ["CA certificate", h("a", { href: "/api/ca.pem" }, "golangtak-ca.pem")],
          ["CA fingerprint", h("span", { class: "mono break small" }, info.caFingerprint)],
          info.ports.websocket ? ["WebSocket", h("span", { class: "mono" }, "ws://" + (host.includes(":") ? "[" + host + "]" : host) + ":" + info.ports.websocket + "/  (one CoT XML event per message)")] : null,
          ["Update server URL", h("span", { class: "mono" }, "https://" + (host.includes(":") ? "[" + host + "]" : host) + ":" + info.ports.https + "/api/packages")],
        ])
      );
    };
    hostSel.addEventListener("change", draw);
    userSel.addEventListener("change", draw);
    draw();
  }

  async function pageMap(main) {
    pageHead(main, "Map", "Live positions, markers and alerts from every connected device.");
    const coords = h("div", { class: "map-coords" }, "");
    const infoBox = h("div", { class: "map-info" });
    const canvas = h("canvas");
    let style = "auto";
    try {
      style = localStorage.getItem("golangtak-map-style") || "auto";
    } catch (e) {}
    const isDark = () => getComputedStyle(document.documentElement).colorScheme === "dark";
    const mapLook = () => {
      const s = style === "auto" ? (isDark() ? "dark" : "light") : style;
      if (s === "dark") return ["grayscale(1) invert(1) brightness(0.86) contrast(0.92)", true];
      if (s === "light") return ["grayscale(1) contrast(1.02)", false];
      return ["none", isDark()];
    };
    const styleSel = select("mapstyle", [["auto", "Match theme"], ["dark", "Dark"], ["light", "Light"], ["color", "Color"]], style);
    styleSel.setAttribute("aria-label", "Map style");
    const wrap = h("div", { class: "map-wrap" }, canvas, infoBox, coords, h("div", { class: "map-attr" }, S.me.tileUrl && S.me.tileUrl.includes("openstreetmap") ? "Map data © OpenStreetMap contributors" : ""));
    let addMode = false;
    let showTracks = false;
    const addBtn = btn("Add marker", () => {
      addMode = !addMode;
      addBtn.classList.toggle("primary", addMode);
      addBtn.lastChild.textContent = addMode ? "Click the map to place it" : "Add marker";
    }, "", "plus");
    const countEl = h("span", { class: "muted" });
    main.append(
      h(
        "div",
        { class: "toolbar" },
        btn("Show all", () => fitAll(true), "", "overview"),
        addBtn,
        checkbox("tracks", false, "Tracks (last hour)"),
        h("span", { class: "grow" }),
        countEl,
        styleSel
      ),
      wrap,
      h(
        "div",
        { class: "legend", style: "margin-top:12px" },
        [["#80e0ff", "Friendly"], ["#ff8080", "Hostile"], ["#aaffaa", "Neutral"], ["#ffff80", "Unknown"], ["#ff4d4f", "Emergency"]].map(([c, t]) => h("span", null, h("i", { style: "background:" + c }), t))
      )
    );
    const [tf, dk] = mapLook();
    const map = new SlippyMap(canvas, { tileUrl: S.me.tileUrl, lat: 20, lon: 0, zoom: 3, tileFilter: tf, dark: dk });
    const tools = h("div", { class: "map-tools" }, btn("+", () => map.zoomAt(1)), btn("-", () => map.zoomAt(-1)));
    wrap.append(tools);
    map.onmove = (lat, lon) => {
      coords.textContent = lat.toFixed(5) + ", " + lon.toFixed(5);
    };
    const markers = () => {
      const out = [];
      for (const v of S.events.values()) {
        if (!isLive(v)) continue;
        if (v.lat === 0 && v.lon === 0) continue;
        if (!v.type || v.type.startsWith("t-") || v.type.startsWith("b-t-f") || v.type.startsWith("b-f-t")) continue;
        out.push({ uid: v.uid, lat: v.lat, lon: v.lon, label: v.callsign || "", kind: SlippyMap.affiliation(v.type), v: v });
      }
      return out;
    };
    const redraw = () => {
      const m = markers();
      map.setMarkers(m);
      countEl.textContent = m.length + " on map";
    };
    let fitted = false;
    const fitAll = (force) => {
      if (map.fit(markers(), 15) || force) fitted = true;
    };
    const showInfo = (m) => {
      clear(infoBox);
      if (!m) {
        infoBox.classList.remove("show");
        return;
      }
      const v = S.events.get(m.uid) || m.v;
      infoBox.classList.add("show");
      infoBox.append(
        h("b", null, v.callsign || v.uid),
        kv([
          ["Type", h("span", { class: "mono" }, v.type)],
          ["Position", h("span", { class: "mono" }, fmtCoord(v.lat, v.lon))],
          ["Altitude", v.hae && v.hae < 9999999 ? Math.round(v.hae) + " m" : "-"],
          ["Team", v.team],
          ["Updated", fmtAgo(v.time)],
          ["Stale", fmtTime(v.stale)],
          ["Remarks", v.remarks],
          ["UID", h("span", { class: "mono small break" }, v.uid)],
        ]),
        h(
          "div",
          { class: "toolbar" },
          btn("Message", () => {
            location.hash = "#/chat/" + enc(v.callsign || v.uid);
          }),
          btn("Delete", () =>
            confirmAction("Delete " + (v.callsign || v.uid), "Remove this item from the map on all connected devices?", "Delete", async () => {
              await api("DELETE", "/api/cot/" + enc(v.uid));
              S.events.delete(v.uid);
              showInfo(null);
              redraw();
            })
          ),
          btn("Close", () => {
            map.selected = "";
            showInfo(null);
            map.draw();
          })
        )
      );
    };
    map.onselect = (m, lat, lon) => {
      if (addMode) {
        addMode = false;
        addBtn.classList.remove("primary");
        addBtn.lastChild.textContent = "Add marker";
        const f = h(
          "form",
          { class: "grid" },
          field("Name", input("mname", "Marker", { required: true })),
          field("Type", select("mtype", [["a-u-G", "Unknown ground"], ["a-f-G", "Friendly ground"], ["a-h-G", "Hostile ground"], ["a-n-G", "Neutral ground"], ["b-m-p-s-m", "Spot map point"], ["b-m-p-w", "Waypoint"]], "a-u-G")),
          field("Position", h("span", { class: "mono" }, fmtCoord(lat, lon))),
          field("Remarks", input("mrem", "")),
          field("Keep for", select("mmin", [["60", "1 hour"], ["1440", "1 day"], ["10080", "7 days"], ["43200", "30 days"]], "1440"))
        );
        modal("New marker", f, [
          { label: "Cancel" },
          {
            label: "Place marker",
            primary: true,
            run: async () => {
              const r = await api("POST", "/api/markers", { name: val(f, "mname"), type: val(f, "mtype"), lat: lat, lon: lon, remarks: val(f, "mrem"), minutes: num(f, "mmin") });
              toast("Marker sent to all devices");
              S.events.set(r.uid, { uid: r.uid, type: val(f, "mtype"), callsign: val(f, "mname"), lat: lat, lon: lon, time: new Date().toISOString(), remarks: val(f, "mrem") });
              redraw();
            },
          },
        ]);
        return;
      }
      showInfo(m);
    };
    const tracksBox = main.querySelector("#tracks");
    const loadTracks = async () => {
      if (!showTracks) {
        map.setTracks([]);
        return;
      }
      try {
        const t = await api("GET", "/api/tracks?minutes=60");
        map.setTracks(Object.values(t).map((x) => ({ points: x.points })));
      } catch (e) {
        fail(e);
      }
    };
    tracksBox.addEventListener("change", () => {
      showTracks = tracksBox.checked;
      loadTracks();
    });
    styleSel.addEventListener("change", () => {
      style = styleSel.value;
      try {
        localStorage.setItem("golangtak-map-style", style);
      } catch (e) {}
      map.setStyle(...mapLook());
    });
    S.listeners.add((v) => {
      redraw();
      if (!fitted && S.events.size) fitAll();
      if (map.selected && v && v.uid === map.selected) showInfo({ uid: v.uid, v: v });
    });
    await refreshEvents();
    redraw();
    fitAll();
    const timer = setInterval(() => {
      redraw();
      if (showTracks) loadTracks();
    }, 15000);
    return () => {
      clearInterval(timer);
      map.destroy();
    };
  }

  async function pageChat(main, params) {
    pageHead(main, "Chat", "Messages from the last 24 hours. What you send appears on TAK devices in the room or contact you choose.");
    const log = h("div", { class: "chat-log", "aria-live": "polite" });
    const seen = new Set();
    const add = (v) => {
      if (!v.chat || seen.has(v.uid)) return;
      seen.add(v.uid);
      const none = log.querySelector(".none");
      if (none) none.remove();
      const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 30;
      log.append(h("div", { class: "msg" }, h("div", { class: "meta" }, h("b", null, v.callsign || "Unknown"), " to " + (v.to || "All Chat Rooms") + ", " + fmtTime(v.time)), h("div", { class: "body" }, v.chat)));
      if (atBottom) log.scrollTop = log.scrollHeight;
    };
    let history = [];
    try {
      history = await api("GET", "/api/cot/history?type=b-t-f&secago=86400&limit=500");
    } catch (e) {}
    history.sort((a, b) => new Date(a.time) - new Date(b.time));
    history.forEach(add);
    S.chats.forEach(add);
    const to = h("select", { id: "to" }, h("option", { value: "All Chat Rooms" }, "All Chat Rooms"));
    try {
      const clients = await api("GET", "/api/clients");
      const names = Array.from(new Set(clients.map((c) => c.info && c.info.callsign).filter(Boolean))).sort();
      for (const n of names) to.append(h("option", { value: n }, n));
    } catch (e) {}
    if (params[0]) {
      if (![...to.options].some((o) => o.value === params[0])) to.append(h("option", { value: params[0] }, params[0]));
      to.value = params[0];
    }
    const msg = h("input", { id: "msg", placeholder: "Write a message", autocomplete: "off" });
    const form = h("form", { class: "chat-form" }, h("label", { for: "to", class: "skip" }, "Send to"), to, h("label", { for: "msg", class: "skip" }, "Message"), msg, h("button", { type: "submit", class: "primary" }, icon("send", 16), "Send"));
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const text = msg.value.trim();
      if (!text) return;
      try {
        await api("POST", "/api/chat", { message: text, to: to.value, sender: S.me.user });
        msg.value = "";
      } catch (e) {
        fail(e);
      }
    });
    if (!seen.size) log.append(h("div", { class: "none" }, "No messages in the last 24 hours."));
    main.append(log, form);
    log.scrollTop = log.scrollHeight;
    S.listeners.add((v) => {
      if (v && v.chat) add(v);
    });
    msg.focus();
  }

  async function pageClients(main) {
    pageHead(main, "Online now", "Devices and server links connected right now. Updates every 5 seconds.", btn("Connect a device", go("#/connect"), "primary", "connect"));
    const box = h("div");
    const search = searchBox(box, "Filter by callsign, user or address");
    main.append(h("div", { class: "toolbar" }, search.el), box);
    const load = async () => {
      const list = await api("GET", "/api/clients");
      list.sort((a, b) => ((a.info && a.info.callsign) || a.remote).localeCompare((b.info && b.info.callsign) || b.remote));
      clear(box).append(
        table(
          [
            { title: "Callsign", render: (r) => (r.info && r.info.callsign) || r.name || "-" },
            { title: "User", render: (r) => r.user || "anonymous" },
            { title: "Connection", render: (r) => r.kind + (r.protocol ? " / " + r.protocol : "") },
            { title: "Address", render: (r) => h("span", { class: "mono small" }, r.remote) },
            { title: "Groups", render: (r) => joined(r.groups) },
            { title: "Software", render: (r) => (r.info ? [r.info.platform, r.info.version].filter(Boolean).join(" ") : "") },
            { title: "Battery", render: (r) => (r.info && r.info.battery ? r.info.battery + "%" : "-") },
            { title: "Connected", render: (r) => fmtAgo(r.connected) },
            { title: "Last seen", render: (r) => fmtAgo(r.lastSeen) },
            { title: "In / out", cls: "nowrap", render: (r) => r.rx + " / " + r.tx },
            S.me.admin
              ? {
                  title: "",
                  cls: "actions",
                  render: (r) =>
                    r.internal ? h("span", { class: "muted" }, "built in") : btn("Disconnect", () =>
                      confirmAction("Disconnect", "Disconnect " + ((r.info && r.info.callsign) || r.remote) + "? The device will usually reconnect by itself.", "Disconnect", async () => {
                        await api("DELETE", "/api/clients/" + r.id);
                        load().catch(fail);
                      })
                    ),
                }
              : null,
          ].filter(Boolean),
          list,
          h("span", null, "No devices are connected. ", h("a", { href: "#/connect" }, "Connect a device"), ".")
        )
      );
      search.apply();
    };
    await load();
    const t = setInterval(() => load().catch(() => {}), 5000);
    return () => clearInterval(t);
  }

  async function pageDevices(main) {
    pageHead(main, "All devices", "Every device that has connected, with its last known position.");
    const box = h("div");
    const search = searchBox(box, "Filter by callsign, user or software");
    main.append(h("div", { class: "toolbar" }, search.el), box);
    const load = async () => {
      const list = await api("GET", "/api/devices");
      list.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
      clear(box).append(
        table(
          [
            { title: "Callsign", key: "callsign" },
            { title: "Status", render: (r) => (r.lastStatus === "Connected" ? pill("connected", "Connected") : h("span", { class: "pill" }, r.lastStatus || "Not seen")) },
            { title: "User", key: "user" },
            { title: "Software", render: (r) => [r.platform, r.version].filter(Boolean).join(" ") },
            { title: "Device", render: (r) => [r.device, r.os].filter(Boolean).join(" ") },
            { title: "Position", render: (r) => h("span", { class: "mono small" }, fmtCoord(r.lat, r.lon)) },
            { title: "Last seen", render: (r) => fmtTime(r.lastSeen) },
            { title: "UID", render: (r) => h("span", { class: "mono small" }, r.uid) },
            S.me.admin
              ? {
                  title: "",
                  cls: "actions",
                  render: (r) =>
                    btn("Forget", () =>
                      confirmAction("Forget device", "Remove " + (r.callsign || r.uid) + " from the device list?", "Forget", async () => {
                        await api("DELETE", "/api/devices/" + enc(r.uid));
                        load().catch(fail);
                      })
                    ),
                }
              : null,
          ].filter(Boolean),
          list,
          h("span", null, "No devices have connected yet. ", h("a", { href: "#/connect" }, "Connect a device"), ".")
        )
      );
      search.apply();
    };
    await load();
  }

  async function groupNames() {
    try {
      return (await api("GET", "/api/groups")).map((g) => g.name);
    } catch (e) {
      return [];
    }
  }

  async function pageFiles(main) {
    pageHead(main, "Files", "Data packages and files shared with TAK devices through Data Sync and the data package server.");
    const fileInput = h("input", { type: "file", id: "upfile", multiple: true });
    const groups = input("upgroups", "", { placeholder: "Groups (optional)" });
    const kw = input("upkw", "", { placeholder: "Keywords (optional)" });
    const box = h("div");
    const upload = async () => {
      if (!fileInput.files.length) return toast("Choose a file first", true);
      for (const f of fileInput.files) {
        try {
          await api("POST", "/api/files?name=" + enc(f.name) + "&groups=" + enc(groups.value) + "&keywords=" + enc(kw.value), f);
          toast("Uploaded " + f.name);
        } catch (e) {
          fail(e);
        }
      }
      fileInput.value = "";
      load().catch(fail);
    };
    const search = searchBox(box, "Filter files");
    main.append(h("h2", null, "Upload"), h("form", { class: "inline", onsubmit: (e) => e.preventDefault() }, fileInput, groups, kw, btn("Upload", upload, "primary", "upload")), h("h2", null, "Shared files"), h("div", { class: "toolbar" }, search.el), box);
    const load = async () => {
      const list = await api("GET", "/api/files");
      list.sort((a, b) => new Date(b.submitted) - new Date(a.submitted));
      clear(box).append(
        table(
          [
            { title: "Name", render: (r) => h("a", { href: "/api/files/" + enc(r.uid) + "/download" }, r.name) },
            { title: "Size", cls: "nowrap", render: (r) => fmtBytes(r.size) },
            { title: "Kind", render: (r) => (r.package ? "Data package" : r.mimeType) },
            { title: "Uploaded by", key: "submitter" },
            { title: "Date", cls: "nowrap", render: (r) => fmtTime(r.submitted) },
            { title: "Groups", render: (r) => joined(r.groups) },
            { title: "Visible", render: (r) => (r.tool === "private" ? "private" : "public") },
            {
              title: "",
              cls: "actions",
              render: (r) => [
                btn("Send", () => shareFile(r)),
                btn("Edit", () => editFile(r)),
                btn("Delete", () =>
                  confirmAction("Delete file", "Delete " + r.name + "?", "Delete", async () => {
                    await api("DELETE", "/api/files/" + enc(r.uid));
                    load().catch(fail);
                  })
                ),
              ],
            },
          ],
          list,
          "No files yet. Upload one above, or share a data package from a TAK device."
        )
      );
      search.apply();
    };
    const shareFile = async (r) => {
      const clients = await api("GET", "/api/clients");
      const named = clients.filter((c) => c.info && c.info.uid);
      const f = h(
        "form",
        null,
        h("p", null, "Send " + r.name + " to devices. They receive a download notice. Leave all unchecked to send to everyone who can see the file."),
        named.length ? named.map((c) => h("div", null, h("label", null, h("input", { type: "checkbox", value: c.info.uid, class: "to" }), " " + (c.info.callsign || c.info.uid)))) : h("p", { class: "muted" }, "No devices are connected.")
      );
      modal("Send file", f, [
        { label: "Cancel" },
        {
          label: "Send",
          primary: true,
          run: async () => {
            const to = [...f.querySelectorAll("input.to:checked")].map((x) => x.value);
            await api("POST", "/api/files/" + enc(r.uid) + "/share", { to: to });
            toast("Sent");
          },
        },
      ]);
    };
    const editFile = (r) => {
      const f = h(
        "form",
        { class: "grid" },
        field("Name", input("fname", r.name)),
        field("Groups", input("fgroups", (r.groups || []).join(", ")), "Comma separated. Empty means everyone."),
        field("Keywords", input("fkw", (r.keywords || []).join(", "))),
        field("Visibility", select("ftool", [["public", "Public (listed for devices)"], ["private", "Private"]], r.tool === "private" ? "private" : "public"))
      );
      modal("Edit file", f, [
        { label: "Cancel" },
        {
          label: "Save",
          primary: true,
          run: async () => {
            await api("PUT", "/api/files/" + enc(r.uid), { name: val(f, "fname"), groups: splitList(val(f, "fgroups")), keywords: splitList(val(f, "fkw")), tool: val(f, "ftool") });
            load().catch(fail);
          },
        },
      ]);
    };
    await load();
  }

  async function pageMissions(main, params) {
    if (params[0]) return missionDetail(main, params[0]);
    pageHead(main, "Missions", "Data Sync missions: shared collections of map items and files that devices subscribe to.", btn("New mission", () => createMission(), "primary", "plus"));
    const box = h("div");
    main.append(box);
    const load = async () => {
      const list = await api("GET", "/api/missions");
      list.sort((a, b) => String(a.name).localeCompare(String(b.name)));
      clear(box).append(
        table(
          [
            { title: "Name", render: (r) => h("a", { href: "#/missions/" + enc(r.name) }, r.name) },
            { title: "Description", key: "description" },
            { title: "Groups", render: (r) => joined(r.groups) },
            { title: "Items", key: "items" },
            { title: "Files", key: "files" },
            { title: "Subscribers", key: "subscribers" },
            { title: "Created", cls: "nowrap", render: (r) => fmtDate(r.createTime) },
          ],
          list,
          "No missions yet. Create one here or from a TAK device.",
          (r) => (location.hash = "#/missions/" + enc(r.name))
        )
      );
    };
    const createMission = async () => {
      const names = await groupNames();
      const f = h(
        "form",
        { class: "grid" },
        field("Name", input("mname", "", { required: true })),
        field("Description", input("mdesc", "")),
        field("Groups", input("mgroups", ""), "Comma separated. Empty uses your groups. Available: " + (names.join(", ") || "-")),
        field("Password", input("mpw", "", { type: "password", autocomplete: "new-password" }), "Optional. Devices need it to subscribe."),
        field("Default role", select("mrole", [["MISSION_SUBSCRIBER", "Subscriber (can add items)"], ["MISSION_READONLY_SUBSCRIBER", "Read only"], ["MISSION_OWNER", "Owner"]], "MISSION_SUBSCRIBER")),
        field("Invite only", checkbox("minv", false, "Only invited devices can subscribe"))
      );
      modal("New mission", f, [
        { label: "Cancel" },
        {
          label: "Create",
          primary: true,
          run: async () => {
            await api("POST", "/api/missions", { name: val(f, "mname"), description: val(f, "mdesc"), groups: splitList(val(f, "mgroups")), password: val(f, "mpw"), defaultRole: val(f, "mrole"), inviteOnly: val(f, "minv") });
            load().catch(fail);
          },
        },
      ]);
    };
    await load();
  }

  async function missionDetail(main, name) {
    const m = await api("GET", "/api/missions/" + enc(name));
    main.append(
      h("p", { class: "crumb" }, h("a", { href: "#/missions" }, "Missions"), " / " + m.name),
      h("h1", null, m.name),
      m.description ? h("p", { class: "lead" }, m.description) : null,
      h("h2", null, "Details"),
      kv([
        ["Created", fmtTime(m.createTime)],
        ["Creator", m.creatorUid],
        ["Groups", joined(m.groups)],
        ["Default role", m.defaultRole && m.defaultRole.type],
        ["Password protected", m.passwordProtected ? "yes" : "no"],
        ["Invite only", m.inviteOnly ? "yes" : "no"],
        ["Keywords", joined(m.keywords)],
      ]),
      h(
        "div",
        { class: "toolbar" },
        btn("Delete mission", () =>
          confirmAction("Delete mission", "Delete mission " + m.name + " for all subscribers?", "Delete", async () => {
            await api("DELETE", "/api/missions/" + enc(m.name));
            location.hash = "#/missions";
          })
        )
      )
    );
    const contents = (m.contents || []).map((c) => c.data || c);
    main.append(h("h2", null, "Files"), table([{ title: "Name", render: (r) => h("a", { href: "/Marti/sync/content?hash=" + enc(r.hash) }, r.name) }, { title: "Size", render: (r) => fmtBytes(r.size) }, { title: "Added by", render: (r) => r.submitter || "-" }, { title: "Date", render: (r) => fmtTime(r.submissionTime) }], contents, "No files."));
    main.append(h("h2", null, "Map items"), table([{ title: "UID", render: (r) => h("span", { class: "mono small" }, r.data || r.uid || r) }, { title: "Callsign", render: (r) => (r.details && r.details.callsign) || "-" }, { title: "Type", render: (r) => (r.details && r.details.type) || "-" }], m.uids || [], "No map items."));
    main.append(h("h2", null, "Subscribers"), table([{ title: "Callsign", key: "callsign" }, { title: "User", key: "username" }, { title: "Role", render: (r) => (r.role && r.role.type) || r.role }, { title: "Since", render: (r) => fmtTime(r.created) }, { title: "UID", render: (r) => h("span", { class: "mono small" }, r.clientUid) }], m.subscriptions || [], "No subscribers."));
    const changes = (m.missionChanges || []).slice(-100).reverse();
    main.append(h("h2", null, "Recent changes"), table([{ title: "Time", render: (r) => fmtTime(r.timestamp) }, { title: "Change", key: "type" }, { title: "Item", render: (r) => (r.contentResource && r.contentResource.name) || r.contentUid || "-" }, { title: "By", render: (r) => r.creatorUid || "-" }], changes, "No changes."));
  }

  async function pageVideo(main) {
    pageHead(main, "Video feeds", "Video streams listed for TAK devices: RTSP, RTMP, SRT, UDP and HTTP.", btn("Add feed", () => addFeed(), "primary", "plus"));
    const box = h("div");
    main.append(box);
    const load = async () => {
      const list = await api("GET", "/api/video");
      clear(box).append(
        table(
          [
            { title: "Name", render: (r) => r.feed.alias },
            { title: "URL", render: (r) => h("span", { class: "mono small break" }, r.url) },
            { title: "Groups", render: (r) => joined(r.feed.groups) },
            { title: "Added by", render: (r) => r.feed.creator || "-" },
            {
              title: "",
              cls: "actions",
              render: (r) => [
                btn("Send to devices", async () => {
                  try {
                    await api("POST", "/api/video/" + enc(r.feed.uid) + "/share", {});
                    toast("Sent");
                  } catch (e) {
                    fail(e);
                  }
                }),
                btn("Delete", () =>
                  confirmAction("Delete feed", "Delete " + r.feed.alias + "?", "Delete", async () => {
                    await api("DELETE", "/api/video/" + enc(r.feed.uid));
                    load().catch(fail);
                  })
                ),
              ],
            },
          ],
          list,
          "No video feeds."
        )
      );
    };
    const addFeed = () => {
      const f = h(
        "form",
        { class: "grid" },
        field("Name", input("valias", "")),
        field("URL", input("vurl", "", { required: true, placeholder: "rtsp://camera.local:554/stream" })),
        field("Groups", input("vgroups", ""), "Comma separated. Empty uses your groups."),
        field("Latitude", input("vlat", "")),
        field("Longitude", input("vlon", ""))
      );
      modal("Add video feed", f, [
        { label: "Cancel" },
        {
          label: "Add",
          primary: true,
          run: async () => {
            await api("POST", "/api/video", { alias: val(f, "valias"), url: val(f, "vurl"), groups: splitList(val(f, "vgroups")), latitude: val(f, "vlat"), longitude: val(f, "vlon") });
            load().catch(fail);
          },
        },
      ]);
    };
    await load();
  }

  async function pageUsers(main) {
    pageHead(main, "Users", "Accounts for people and devices. Users sign in to TAK clients with their name and password, or with a certificate from a connection package.", btn("Add user", () => addUser(), "primary", "plus"));
    const box = h("div");
    const search = searchBox(box, "Filter users");
    main.append(h("div", { class: "toolbar" }, search.el), box);
    const load = async () => {
      const users = await api("GET", "/api/users");
      users.sort((a, b) => a.name.localeCompare(b.name));
      clear(box).append(
        table(
          [
            { title: "Name", render: (r) => h("b", null, r.name) },
            { title: "Role", render: (r) => (r.admin ? "admin" : "user") + (r.external ? ", directory" : "") + (r.disabled ? ", disabled" : "") },
            { title: "Callsign", key: "callsign" },
            { title: "Receives from", render: (r) => joined(r.in) },
            { title: "Sends to", render: (r) => joined(r.out) },
            { title: "Certificates", render: (r) => String((r.certs || []).filter((c) => !c.revoked).length) },
            { title: "Online", key: "online" },
            { title: "Last sign-in", cls: "nowrap", render: (r) => fmtAgo(r.lastLogin) },
            {
              title: "",
              cls: "actions",
              render: (r) => [btn("Enroll QR", () => enrollQR(r.name), "small"), h("a", { class: "button small", href: "/api/package?type=cert&user=" + enc(r.name) }, "Package"), btn("Password", () => setPassword(r), "small"), btn("Edit", () => editUser(r), "small")],
            },
          ],
          users,
          "No users."
        )
      );
      search.apply();
    };
    const enrollQR = async (name) => {
      try {
        const r = await api("POST", "/api/connect/enroll", { user: name, hours: 24 });
        modal(
          "Enroll a device for " + name,
          h("div", null, h("p", null, "Scan with ATAK (Settings, Network, Servers, Add, Scan QR). The code works once, until " + fmtTime(r.expires) + "."), qrImg(r.atak), h("p", { class: "small" }, "iTAK: scan the quick connect code on the Connect page and use the one-time code ", h("b", { class: "mono" }, r.token), " as the password."))
        );
      } catch (e) {
        fail(e);
      }
    };
    const addUser = async () => {
      const names = await groupNames();
      const f = h(
        "form",
        { class: "grid" },
        field("Name", input("uname", "", { required: true, autocomplete: "off", autocapitalize: "none" }), "Letters, numbers, dot, dash and underscore."),
        field("Password", input("upw", "", { type: "password", autocomplete: "new-password" }), "Leave empty to generate one."),
        field("Groups", input("ugroups", ""), "Comma separated; new groups are created. Existing: " + (names.join(", ") || "-")),
        field("Callsign", input("ucs", "")),
        field("Administrator", checkbox("uadmin", false, "Can manage this server"))
      );
      modal("Add user", f, [
        { label: "Cancel" },
        {
          label: "Create",
          primary: true,
          run: async () => {
            const r = await api("POST", "/api/users", { name: val(f, "uname"), password: val(f, "upw"), admin: val(f, "uadmin"), groups: splitList(val(f, "ugroups")), callsign: val(f, "ucs") || undefined });
            load().catch(fail);
            if (r.password) {
              modal("User created", h("div", null, h("p", null, "Password for " + r.user.name + ":"), h("p", { class: "mono" }, h("b", null, r.password)), h("p", { class: "muted" }, "Share it with the user. It is not shown again.")), [{ label: "Copy password", run: () => (copy(r.password), true) }, { label: "Done", primary: true }]);
            } else {
              toast("User created");
            }
          },
        },
      ]);
    };
    const editUser = async (u) => {
      const f = h(
        "form",
        { class: "grid" },
        field("Callsign", input("ecs", u.callsign)),
        field("Team", select("eteam", ["", "Cyan", "White", "Yellow", "Orange", "Magenta", "Red", "Maroon", "Purple", "Dark Blue", "Blue", "Teal", "Green", "Dark Green", "Brown"], u.team)),
        field("Team role", select("erole", ["", "Team Member", "Team Lead", "HQ", "Sniper", "Medic", "Forward Observer", "RTO", "K9"], u.teamRole)),
        field("Receives from", input("ein", (u.in || []).join(", ")), "Groups whose traffic this user receives."),
        field("Sends to", input("eout", (u.out || []).join(", ")), "Groups this user's traffic goes to."),
        field("Administrator", checkbox("eadmin", u.admin, "Can manage this server")),
        field("Disabled", checkbox("edis", u.disabled, "Cannot sign in or connect")),
        field("Note", input("enote", u.note))
      );
      modal("Edit " + u.name, f, [
        {
          label: "Delete user",
          run: () =>
            confirmAction("Delete user", "Delete " + u.name + " and revoke all of its certificates?", "Delete", async () => {
              await api("DELETE", "/api/users/" + enc(u.name));
              load().catch(fail);
            }),
        },
        {
          label: "Revoke certificates",
          run: () =>
            confirmAction("Revoke certificates", "Revoke every certificate issued to " + u.name + "? Devices using them are disconnected and must enroll again.", "Revoke", async () => {
              const r = await api("POST", "/api/users/" + enc(u.name) + "/revoke");
              toast("Revoked " + (r.revoked || 0) + " certificate(s)");
              load().catch(fail);
            }),
        },
        { label: "Cancel" },
        {
          label: "Save",
          primary: true,
          run: async () => {
            await api("PUT", "/api/users/" + enc(u.name), { callsign: val(f, "ecs"), team: val(f, "eteam"), teamRole: val(f, "erole"), in: splitList(val(f, "ein")), out: splitList(val(f, "eout")), admin: val(f, "eadmin"), disabled: val(f, "edis"), note: val(f, "enote") });
            toast("Saved");
            load().catch(fail);
          },
        },
      ]);
    };
    const setPassword = (u) => {
      const f = h("form", { class: "grid" }, field("New password", input("npw", "", { type: "password", autocomplete: "new-password" }), "At least 8 characters. Leave empty to generate one."));
      modal("Password for " + u.name, f, [
        { label: "Cancel" },
        {
          label: "Set password",
          primary: true,
          run: async () => {
            let pw = val(f, "npw");
            const generated = !pw;
            if (generated) {
              const a = "abcdefghjkmnpqrstuvwxyz23456789";
              const b = new Uint8Array(16);
              crypto.getRandomValues(b);
              pw = Array.from(b, (x, i) => (i && i % 4 === 0 ? "-" : "") + a[x % a.length]).join("");
            }
            await api("PUT", "/api/users/" + enc(u.name), { password: pw });
            if (generated) modal("New password", h("p", { class: "mono" }, h("b", null, pw)), [{ label: "Copy", run: () => (copy(pw), true) }, { label: "Done", primary: true }]);
            else toast("Password changed");
          },
        },
      ]);
    };
    await load();
  }

  async function pageGroups(main) {
    pageHead(main, "Groups", "Groups (channels) decide who sees whose traffic. Users receive from their receive groups and send to their send groups.");
    const box = h("div");
    const name = input("gname", "", { placeholder: "Group name" });
    const desc = input("gdesc", "", { placeholder: "Description" });
    const form = h("form", { class: "inline" }, name, desc, h("button", { type: "submit", class: "primary" }, icon("plus", 16), "Add group"));
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      try {
        await api("POST", "/api/groups", { name: name.value.trim(), description: desc.value.trim() });
        name.value = desc.value = "";
        load().catch(fail);
      } catch (e) {
        fail(e);
      }
    });
    main.append(h("h2", null, "Add a group"), form, h("h2", null, "Groups"), box);
    const load = async () => {
      const list = await api("GET", "/api/groups");
      clear(box).append(
        table(
          [
            { title: "Name", render: (r) => h("b", null, r.name) },
            { title: "Description", key: "description" },
            { title: "Members", key: "members" },
            { title: "Created", render: (r) => fmtDate(r.created) },
            {
              title: "",
              cls: "actions",
              render: (r) =>
                r.system
                  ? h("span", { class: "muted" }, "default")
                  : btn("Delete", () =>
                      confirmAction("Delete group", "Delete group " + r.name + "? Members lose access to it.", "Delete", async () => {
                        await api("DELETE", "/api/groups/" + enc(r.name));
                        load().catch(fail);
                      })
                    ),
            },
          ],
          list
        )
      );
    };
    await load();
  }

  async function pageLinks(main) {
    pageHead(main, "Server links", "Exchange traffic in both directions with TAK Server, OpenTAKServer, FreeTAKServer, zyrntopo-tak-server, another GolangTAK, or any software that speaks CoT over TCP, TLS, UDP or WebSocket.", btn("Add link", () => editPeer(null), "primary", "plus"));
    const box = h("div");
    const fedBox = h("div");
    main.append(h("h2", null, "Links"), box, h("h2", null, "Federation"), fedBox);
    let cfg;
    const save = async (peers) => {
      const r = await api("PUT", "/api/settings", { peers: peers });
      if (r.restartRequired) toast("Saved. Restart the server to apply.");
      else toast("Saved");
      load().catch(fail);
    };
    const load = async () => {
      cfg = await api("GET", "/api/settings");
      const status = await api("GET", "/api/peers");
      const peers = cfg.peers || [];
      clear(box).append(
        table(
          [
            { title: "Name", render: (r) => h("b", null, r.name) },
            { title: "URL", render: (r) => h("span", { class: "mono small break" }, r.url) },
            { title: "Direction", render: (r) => r.direction || "both" },
            { title: "Groups", render: (r) => joined(r.groups) },
            {
              title: "State",
              render: (r) => {
                const s = status.find((x) => x.name === r.name);
                if (!r.enabled) return h("span", { class: "pill" }, "disabled");
                return s ? h("div", null, pill(s.state), s.error ? h("div", { class: "small muted", style: "margin-top:4px" }, s.error) : null) : "-";
              },
            },
            {
              title: "",
              cls: "actions",
              render: (r) => [
                btn(r.enabled ? "Disable" : "Enable", () => save(peers.map((p) => (p.name === r.name ? Object.assign({}, p, { enabled: !p.enabled }) : p))).catch(fail)),
                btn("Edit", () => editPeer(r)),
                btn("Delete", () => confirmAction("Delete link", "Delete the link " + r.name + "?", "Delete", () => save(peers.filter((p) => p.name !== r.name)))),
              ],
            },
          ],
          peers,
          "No links. Add one to connect this server to another."
        )
      );
      const fed = await api("GET", "/api/federation");
      const f = cfg.federation || {};
      const form = h(
        "form",
        { class: "grid" },
        field("Enabled", checkbox("fen", f.enabled, "Accept TAK Server federation (v1) connections on port " + cfg.ports.federation)),
        field("Port", input("fport", cfg.ports.federation || 9000, { type: "number", min: 0, max: 65535 })),
        field("Groups", input("fgroups", (f.groups || []).join(", ")), "Traffic from these groups is shared with federates."),
        field("Trusted CAs", h("textarea", { id: "fcas" }, (f.trustedCAs || []).join("\n")), "PEM certificates of the federates' certificate authorities."),
        h("div", { class: "full" }, btn("Save federation settings", async () => {
          try {
            const pems = (val(form, "fcas").match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || []);
            const r = await api("PUT", "/api/settings", { federation: { enabled: val(form, "fen"), groups: splitList(val(form, "fgroups")), trustedCAs: pems }, ports: Object.assign({}, cfg.ports, { federation: num(form, "fport") }) });
            toast(r.restartRequired ? "Saved. Restart the server under Settings to apply." : "Saved");
          } catch (e) {
            fail(e);
          }
        }, "primary"))
      );
      clear(fedBox).append(
        h("p", null, "Federation shares traffic with TAK Server instances that connect with mutual TLS. Give the other side this server's CA certificate (", h("a", { href: "/api/ca.pem" }, "download"), ") and add theirs below. To connect out to a federation server, add a link with a fed:// URL."),
        table([{ title: "Federate", key: "name" }, { title: "Address", key: "remote" }, { title: "Since", render: (r) => fmtAgo(r.since) }], (fed && fed.federates) || [], "No federates connected."),
        form
      );
    };
    const editPeer = (p) => {
      const isNew = !p;
      p = p || { enabled: true, direction: "both", groups: [] };
      const f = h(
        "form",
        { class: "grid" },
        field("Name", input("pname", p.name, { required: true, readOnly: !isNew })),
        field("URL", input("purl", p.url, { required: true, placeholder: "tls://tak.example.org:8089" }), "tcp://, tls:// (or ssl://), ws://, wss://, udp://, fed:// (federation)."),
        field("Direction", select("pdir", [["both", "Both ways"], ["out", "Send only"], ["in", "Receive only"]], p.direction || "both")),
        field("Groups", input("pgroups", (p.groups || []).join(", ")), "Traffic from these groups is sent; received traffic goes to them. Empty means the default group."),
        field("User name", input("puser", p.username || "", { autocomplete: "off" })),
        field("Password", input("ppw", p.password || "", { type: "password", autocomplete: "new-password" })),
        field("Client certificate", input("pcert", p.certFile || ""), "Path on this server to a .p12 or PEM file."),
        field("Certificate password", input("pcertpw", p.certPassword || "", { type: "password", autocomplete: "new-password" })),
        field("Trusted CA", input("ptrust", p.trustFile || ""), "Path on this server to the other server's CA (.pem or .p12)."),
        field("Options", h("div", null, checkbox("pins", p.insecure, "Do not verify the other server's certificate"), h("br"), checkbox("pnop", p.noPresence, "Do not announce this server as a contact")))
      );
      modal(isNew ? "Add server link" : "Edit " + p.name, f, [
        { label: "Cancel" },
        {
          label: "Save",
          primary: true,
          run: async () => {
            const next = Object.assign({}, p, {
              name: val(f, "pname"),
              url: val(f, "purl"),
              direction: val(f, "pdir"),
              groups: splitList(val(f, "pgroups")),
              username: val(f, "puser") || undefined,
              password: val(f, "ppw") || undefined,
              certFile: val(f, "pcert") || undefined,
              certPassword: val(f, "pcertpw") || undefined,
              trustFile: val(f, "ptrust") || undefined,
              insecure: val(f, "pins") || undefined,
              noPresence: val(f, "pnop") || undefined,
              enabled: p.enabled !== false,
            });
            const peers = (cfg.peers || []).filter((x) => x.name !== next.name);
            peers.push(next);
            await save(peers);
          },
        },
      ]);
    };
    await load();
  }

  async function pagePlugins(main) {
    pageHead(main, "Plugins and profiles", "Publish ATAK plugins through the update server, and push settings to devices when they enroll or connect.");
    const cfg = await api("GET", "/api/connect");
    const url = "https://" + (cfg.host.includes(":") ? "[" + cfg.host + "]" : cfg.host) + ":" + cfg.ports.https + "/api/packages";
    main.append(h("h2", null, "Update server"), h("p", null, "In ATAK: Settings, Plugins (or Tool Preferences, Package Management), Update Server URL: ", h("span", { class: "mono" }, url)));
    const apk = h("input", { type: "file", accept: ".apk", id: "apk" });
    const pbox = h("div");
    main.append(
      h(
        "form",
        { class: "inline", onsubmit: (e) => e.preventDefault() },
        apk,
        btn("Upload APK", async () => {
          if (!apk.files.length) return toast("Choose an APK first", true);
          try {
            const f = apk.files[0];
            const r = await api("POST", "/api/plugins?file=" + enc(f.name), f);
            toast("Published " + r.name + " " + r.version);
            apk.value = "";
            loadPlugins().catch(fail);
          } catch (e) {
            fail(e);
          }
        }, "primary", "upload")
      ),
      pbox
    );
    const loadPlugins = async () => {
      const list = await api("GET", "/api/plugins");
      clear(pbox).append(
        table(
          [
            { title: "Name", key: "name" },
            { title: "Package", render: (r) => h("span", { class: "mono small" }, r.package) },
            { title: "Version", render: (r) => r.version + " (" + r.revision + ")" },
            { title: "Platform", key: "platform" },
            { title: "Size", render: (r) => fmtBytes(r.size) },
            { title: "Updated", render: (r) => fmtDate(r.updated) },
            {
              title: "",
              cls: "actions",
              render: (r) =>
                btn("Delete", () =>
                  confirmAction("Delete plugin", "Remove " + r.name + " from the update server?", "Delete", async () => {
                    await api("DELETE", "/api/plugins/" + enc(r.id));
                    loadPlugins().catch(fail);
                  })
                ),
            },
          ],
          list,
          "No plugins published."
        )
      );
    };
    const prbox = h("div");
    main.append(h("h2", null, "Device profile"), h("p", null, "Settings sent to devices as a data package. Choose whether each applies at enrollment, at every connection, or both."), h("div", { class: "toolbar" }, btn("Add setting", () => addPref(), "primary", "plus")), prbox);
    const loadProfiles = async () => {
      const list = await api("GET", "/api/profiles");
      clear(prbox).append(
        table(
          [
            { title: "Kind", key: "kind" },
            { title: "Setting", render: (r) => h("span", { class: "mono small" }, r.kind === "file" ? r.name : r.key) },
            { title: "Value", render: (r) => h("span", { class: "mono small break" }, r.kind === "file" ? fmtBytes(r.size || 0) : r.value) },
            { title: "Applies", render: (r) => [r.enrollment ? "enrollment" : "", r.connection ? "connection" : ""].filter(Boolean).join(", ") || "-" },
            { title: "Only for", render: (r) => r.group || r.clientUid || "everyone" },
            {
              title: "",
              cls: "actions",
              render: (r) =>
                btn("Delete", () =>
                  confirmAction("Delete setting", "Delete this profile entry?", "Delete", async () => {
                    await api("DELETE", "/api/profiles/" + enc(r.id));
                    loadProfiles().catch(fail);
                  })
                ),
            },
          ],
          list,
          "No profile settings."
        )
      );
    };
    const addPref = () => {
      const f = h(
        "form",
        { class: "grid" },
        field("Preference key", input("pkey", "", { placeholder: "locationCallsign" })),
        field("Value", input("pval", "")),
        field("Type", select("pclass", [["String", "Text"], ["Boolean", "true / false"], ["Integer", "Whole number"], ["Float", "Number"], ["Long", "Long number"]], "String")),
        field("Group", input("pgroup", ""), "Optional. Only users in this group receive it."),
        field("Applies", h("div", null, checkbox("penr", true, "At enrollment"), " ", checkbox("pcon", false, "At every connection")))
      );
      modal("Add profile setting", f, [
        { label: "Cancel" },
        {
          label: "Add",
          primary: true,
          run: async () => {
            await api("POST", "/api/profiles", { kind: "pref", key: val(f, "pkey"), value: val(f, "pval"), class: val(f, "pclass"), group: val(f, "pgroup"), enrollment: val(f, "penr"), connection: val(f, "pcon") });
            loadProfiles().catch(fail);
          },
        },
      ]);
    };
    await Promise.all([loadPlugins(), loadProfiles()]);
  }

  const SETTINGS_SECTIONS = [
    { id: "general", title: "General", keys: "name address dns bind listen map tiles log level" },
    { id: "access", title: "Access and groups", keys: "anonymous unsigned default group strict channels protobuf replay" },
    { id: "ports", title: "Ports", keys: "tcp ssl tls udp http https enrollment websocket" },
    { id: "mesh", title: "Mesh and alerts", keys: "multicast sa emergency repeater ttl" },
    { id: "meshtastic", title: "Meshtastic", keys: "lora mqtt broker radio" },
    { id: "feeds", title: "Data feeds", keys: "ads-b adsb aircraft ais ships aishub" },
    { id: "directory", title: "Directory sign-in", keys: "ldap active directory ad" },
    { id: "certs", title: "Certificates", keys: "organization validity p12 password" },
    { id: "storage", title: "Storage and limits", keys: "retention history days limits clients upload" },
    { id: "maintenance", title: "Maintenance", keys: "restart renew backup" },
    { id: "advanced", title: "Advanced (JSON)", keys: "config.json raw" },
  ];

  async function pageSettings(main, params) {
    const cfg = await api("GET", "/api/settings");
    pageHead(main, "Settings", "Changes to ports, the listen address, mesh or federation take effect after a restart, which is offered when you save.");
    const p = cfg.ports, m = cfg.mesh, c = cfg.certificates, r = cfg.retention, l = cfg.limits;
    const fa = (cfg.feeds && cfg.feeds.adsb) || {}, fs = (cfg.feeds && cfg.feeds.ais) || {}, ld = cfg.ldap || {}, mt = cfg.meshtastic || {};
    const n = (id, v) => input(id, v, { type: "number", min: 0 });
    const sub = (title) => h("h3", { class: "full", style: "margin-top:12px" }, title);
    const content = {
      general: [
        "The basics devices and people see.",
        field("Server name", input("name", cfg.name), "Shown in TAK clients and connection packages."),
        field("Public address", input("address", cfg.address), "Address devices use. Used in QR codes, packages and the server certificate."),
        field("Other names", input("extra", (cfg.extraNames || []).join(", ")), "More DNS names or IP addresses for the server certificate, comma separated."),
        field("Listen on", input("bind", cfg.bind, { placeholder: "all addresses" }), "Leave empty to accept connections on every network interface."),
        field("Map tiles", input("tile", cfg.tileUrl), "Tile URL with {z}, {x} and {y}. Point it at a local tile server for networks without internet."),
        field("Log level", select("loglevel", [["debug", "Debug (everything)"], ["info", "Info"], ["warn", "Warnings and errors"], ["error", "Errors only"]], cfg.logLevel)),
      ],
      access: [
        "Who can connect and who sees whose traffic.",
        field("Unsigned clients", checkbox("anon", cfg.allowAnonymous, "Allow plain TCP, UDP and anonymous connections")),
        field("Default group", input("anongroup", cfg.anonymousGroup), "Group for connections without an account."),
        field("Strict groups", checkbox("strict", cfg.strictGroups, "Never deliver traffic outside a client's groups")),
        field("Channels", checkbox("channels", cfg.channels, "Let devices choose their active groups")),
        field("TAK protocol", checkbox("proto", cfg.protobuf, "Offer TAK Protocol version 1 (protobuf) to clients")),
        field("Replay to new clients", select("replay", [["all", "All current items"], ["sa", "Positions only"], ["none", "Nothing"]], cfg.replay), "What a device receives when it connects."),
      ],
      ports: [
        "Set a port to 0 to turn that service off.",
        field("TAK SSL (TLS)", n("p_tls", p.tls)),
        field("TAK TCP", n("p_tcp", p.tcp)),
        field("TAK TCP second port", n("p_tcpalt", p.tcpAlt)),
        field("UDP", n("p_udp", p.udp)),
        field("Certificate enrollment", n("p_enroll", p.enroll)),
        field("HTTPS", n("p_https", p.https)),
        field("HTTP", n("p_http", p.http)),
        field("WebSocket", n("p_ws", p.websocket)),
        field("FreeTAKServer API", n("p_api", p.api)),
      ],
      mesh: [
        "Multicast situational awareness for radios and devices on the same network, and the emergency repeater.",
        sub("Multicast mesh"),
        field("Receive", checkbox("mesh", m.enabled, "Listen to multicast situational awareness")),
        field("Send", checkbox("meshsend", m.send, "Repeat server traffic to multicast")),
        field("Groups", input("meshgroups", (m.groups || []).join(", ")), "Multicast addresses as address:port, comma separated."),
        field("Interface", input("meshif", m.interface, { placeholder: "all" })),
        field("TTL", n("meshttl", m.ttl)),
        sub("Emergency repeater"),
        field("Repeat alerts", checkbox("rep", cfg.repeater.enabled, "Resend active emergencies to everyone")),
        field("Every (seconds)", n("repint", cfg.repeater.intervalSec)),
      ],
      meshtastic: [
        "Bridge Meshtastic LoRa radios and TAK in both directions through MQTT.",
        field("Enabled", checkbox("mt_on", mt.enabled, "Bridge Meshtastic nodes and TAK")),
        field("Built-in MQTT port", n("mt_port", mt.brokerPort), "Point each gateway node's MQTT setting at this server and port. 0 turns the built-in broker off."),
        field("Open broker", checkbox("mt_anon", mt.brokerAnonymous, "Accept nodes without a GolangTAK user name and password")),
        field("Upstream broker", input("mt_up", mt.upstream, { placeholder: "mqtt://user:password@mqtt.example.org:1883" }), "Optional. Also exchange traffic through another MQTT broker."),
        field("Topic root", input("mt_root", mt.root), "Must match the nodes' MQTT root topic, for example msh/US or msh/EU_868."),
        field("Channels", input("mt_ch", (mt.channels || []).map((c) => c.name + "=" + c.key).join(", ")), "name=key pairs. The default channel is LongFast=AQ==."),
        field("Send TAK traffic to the mesh", checkbox("mt_down", mt.downlink, "Positions and All Chat Rooms messages (nodes need downlink enabled)")),
        field("Downlink channel", input("mt_dch", mt.downlinkChannel, { placeholder: "first channel" })),
        field("Seconds between positions", n("mt_int", mt.intervalSec), "Per TAK user, to protect the mesh's airtime."),
        field("Group", input("mt_group", mt.group, { placeholder: "everyone" }), "Mesh traffic goes to this group, and only its traffic goes to the mesh. Empty means everyone."),
      ],
      feeds: [
        "Live aircraft and ships shown on every device's map.",
        sub("ADS-B aircraft"),
        field("Enabled", checkbox("fa_on", fa.enabled, "Show aircraft from an ADS-B exchange")),
        field("Center latitude", input("fa_lat", fa.lat)),
        field("Center longitude", input("fa_lon", fa.lon)),
        field("Radius (nautical miles)", n("fa_rad", fa.radiusNm)),
        field("Update every (seconds)", n("fa_int", fa.intervalSec)),
        field("Group", input("fa_group", fa.group, { placeholder: "everyone" }), "Only members of this group see the aircraft. Empty sends to everyone."),
        field("Source URL", input("fa_url", fa.url), "adsb.lol by default. Any service with the same /point/lat/lon/radius API works."),
        field("API key", input("fa_key", fa.apiKey, { autocomplete: "off" })),
        sub("AIS ships (AISHub)"),
        field("Enabled", checkbox("fs_on", fs.enabled, "Show ships from AISHub")),
        field("AISHub user name", input("fs_user", fs.username, { autocomplete: "off" })),
        field("South", input("fs_s", fs.south)),
        field("West", input("fs_w", fs.west)),
        field("North", input("fs_n", fs.north)),
        field("East", input("fs_e", fs.east)),
        field("MMSI list", input("fs_mmsi", fs.mmsi), "Optional, comma separated."),
        field("Update every (seconds)", n("fs_int", fs.intervalSec), "AISHub allows one request per minute."),
        field("Group", input("fs_group", fs.group, { placeholder: "everyone" })),
      ],
      directory: [
        "Let people sign in with LDAP or Active Directory accounts. Directory groups become TAK groups.",
        field("Enabled", checkbox("ld_on", ld.enabled, "Let directory users sign in with their directory password")),
        field("Server URL", input("ld_url", ld.url, { placeholder: "ldaps://dc.example.org" })),
        field("StartTLS", checkbox("ld_tls", ld.startTls, "Upgrade ldap:// connections to TLS")),
        field("Skip certificate check", checkbox("ld_ins", ld.insecure, "Do not verify the directory server certificate")),
        field("Trusted CA file", input("ld_ca", ld.trustFile), "Path on this server to the directory's CA certificate (PEM)."),
        field("Service account DN", input("ld_bind", ld.bindDn, { autocomplete: "off" })),
        field("Service account password", input("ld_bpw", ld.bindPassword, { type: "password", autocomplete: "new-password" })),
        field("Base DN", input("ld_base", ld.baseDn, { placeholder: "dc=example,dc=org" })),
        field("User filter", input("ld_filter", ld.userFilter), "{user} is replaced by the sign-in name."),
        field("User DN template", input("ld_udn", ld.userDn, { placeholder: "uid={user},ou=people,dc=example,dc=org" }), "Optional. Signs in directly without a service account."),
        field("Group filter", input("ld_gfilter", ld.groupFilter, { placeholder: "(&(objectClass=groupOfNames)(member={dn}))" }), "Optional. Without it the memberOf attribute is used."),
        field("Group base DN", input("ld_gbase", ld.groupBaseDn)),
        field("Group prefix", input("ld_gprefix", ld.groupPrefix, { placeholder: "tak_" }), "Only directory groups starting with this become TAK groups, with the prefix removed."),
        field("Administrator group", input("ld_admin", ld.adminGroup)),
        field("Callsign attribute", input("ld_cs", ld.callsignAttribute)),
        h("div", { class: "full" }, btn("Test directory sign-in", () => testLdap())),
      ],
      certs: [
        "Values used for new client certificates and connection packages.",
        field("Organization", input("corg", c.organization)),
        field("Unit", input("cunit", c.unit)),
        field("Package password", input("cpw", c.password), "Password of the .p12 files in connection packages."),
        field("Client validity (days)", n("cdays", c.clientDays)),
        field("Server validity (days)", n("sdays", c.serverDays)),
      ],
      storage: [
        "How long data is kept, and limits that protect the server.",
        sub("Keep for (days, 0 keeps forever)"),
        field("History", n("rhist", r.historyDays)),
        field("Offline chat", n("rchat", r.chatDays)),
        field("Files", n("rfile", r.fileDays)),
        field("Missions", n("rmis", r.missionDays)),
        sub("Limits"),
        field("Clients", n("lmax", l.maxClients)),
        field("Clients per address", n("lip", l.maxPerIP)),
        field("Largest message (bytes)", n("lmsg", l.maxMessageBytes)),
        field("Largest upload (MB)", n("lup", l.maxUploadMB)),
        field("Idle timeout (seconds)", n("lidle", l.idleTimeoutSec)),
        field("Items replayed", n("lrep", l.replayLimit)),
      ],
    };
    const form = h("form", { novalidate: true });
    const sectionEls = {};
    for (const s of SETTINGS_SECTIONS) {
      let el;
      if (content[s.id]) {
        const [intro, ...fields] = content[s.id];
        el = h("div", { class: "section", "data-sec": s.id }, h("h2", null, s.title), h("p", { class: "intro" }, intro), h("div", { class: "grid" }, fields));
        form.append(el);
      } else if (s.id === "maintenance") {
        const row = (title, text, action) => h("div", { class: "row" }, h("div", null, h("b", null, title), h("p", null, text)), action);
        el = h(
          "div",
          { class: "section", "data-sec": s.id },
          h("h2", null, s.title),
          h(
            "div",
            { class: "action-list" },
            row("Restart the server", "Applies changes that need a restart. Devices reconnect by themselves.", btn("Restart", () => confirmAction("Restart", "Restart the server now? Devices reconnect automatically.", "Restart", restart), "", "restart")),
            row("Renew the server certificate", "Issues a new certificate for the current address and names.", btn("Renew certificate", async () => {
              try {
                await api("POST", "/api/certs/server/renew");
                toast("Server certificate renewed");
              } catch (e) {
                fail(e);
              }
            })),
            row("Download a backup", "Settings, users, certificates, missions and the certificate authority. Keep it somewhere safe.", linkBtn("Download backup", "/api/backup", "", "download")),
            row("Download a full backup", "Everything above plus all stored files. Can be large.", linkBtn("Download with files", "/api/backup?files=1", "", "download"))
          )
        );
      } else {
        const raw = h("textarea", { id: "raw", style: "min-height:420px", "aria-label": "All settings as JSON" });
        raw.value = JSON.stringify(cfg, null, 2);
        el = h(
          "div",
          { class: "section", "data-sec": s.id },
          h("h2", null, s.title),
          h("p", { class: "intro" }, "Every option in config.json. Peer passwords are shown as ********; leave them as they are to keep them."),
          raw,
          h(
            "div",
            { class: "toolbar" },
            btn("Save JSON", async () => {
              let obj;
              try {
                obj = JSON.parse(raw.value);
              } catch (e) {
                return toast("Not valid JSON: " + e.message, true);
              }
              try {
                const res = await api("PUT", "/api/settings", obj);
                if (res.restartRequired) confirmAction("Restart required", "Restart now to apply?", "Restart", restart);
                else toast("Settings saved");
              } catch (e) {
                fail(e);
              }
            }, "primary")
          )
        );
      }
      sectionEls[s.id] = el;
    }
    const state = h("span", { class: "state" }, "No unsaved changes");
    const saveBtn = h("button", { type: "submit", class: "primary" }, "Save settings");
    const discard = btn("Discard changes", () => route());
    discard.disabled = true;
    const bar = h("div", { class: "savebar" }, state, discard, saveBtn);
    form.append(bar);
    let dirty = false;
    const setDirty = (d) => {
      dirty = d;
      bar.classList.toggle("dirty", d);
      state.textContent = d ? "Unsaved changes" : "No unsaved changes";
      discard.disabled = !d;
    };
    form.addEventListener("input", () => setDirty(true));
    form.addEventListener("change", () => setDirty(true));
    const beforeUnload = (ev) => {
      if (dirty) {
        ev.preventDefault();
        ev.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", beforeUnload);

    const nav = h("nav", { class: "subnav", "aria-label": "Settings sections" });
    const show = (id) => {
      if (!sectionEls[id]) id = "general";
      for (const [k, el] of Object.entries(sectionEls)) el.hidden = k !== id;
      bar.hidden = !content[id];
      for (const a of nav.querySelectorAll("a")) {
        a.classList.toggle("active", a.dataset.sec === id);
        if (a.dataset.sec === id) a.setAttribute("aria-current", "true");
        else a.removeAttribute("aria-current");
      }
      history.replaceState(null, "", "#/settings/" + id);
    };
    for (const s of SETTINGS_SECTIONS) {
      nav.append(
        h("a", { href: "#/settings/" + s.id, "data-sec": s.id, onclick: (ev) => (ev.preventDefault(), show(s.id), window.scrollTo(0, 0)) }, s.title)
      );
    }
    main.append(h("div", { class: "settings" }, nav, h("div", null, form, sectionEls.maintenance, sectionEls.advanced)));
    show(params[0] || "general");

    const ldapFromForm = () =>
      Object.assign({}, ld, {
        enabled: val(form, "ld_on"),
        url: val(form, "ld_url"),
        startTls: val(form, "ld_tls"),
        insecure: val(form, "ld_ins"),
        trustFile: val(form, "ld_ca"),
        bindDn: val(form, "ld_bind"),
        bindPassword: form.querySelector("#ld_bpw").value,
        baseDn: val(form, "ld_base"),
        userFilter: val(form, "ld_filter"),
        userDn: val(form, "ld_udn"),
        groupFilter: val(form, "ld_gfilter"),
        groupBaseDn: val(form, "ld_gbase"),
        groupPrefix: val(form, "ld_gprefix"),
        adminGroup: val(form, "ld_admin"),
        callsignAttribute: val(form, "ld_cs"),
      });
    const testLdap = () => {
      const f = h("form", { class: "grid" }, field("User name", input("tu", "", { autocomplete: "off" })), field("Password", input("tp", "", { type: "password", autocomplete: "off" })));
      modal("Test directory sign-in", f, [
        { label: "Cancel" },
        {
          label: "Test",
          primary: true,
          run: async () => {
            const r = await api("POST", "/api/ldap/test", { username: val(f, "tu"), password: f.querySelector("#tp").value, config: ldapFromForm() });
            toast("Signed in. Groups: " + (r.groups.join(", ") || "none") + (r.admin ? ". Administrator." : ".") + (r.callsign ? " Callsign " + r.callsign + "." : ""));
            return true;
          },
        },
      ]);
    };
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const next = {
        name: val(form, "name"),
        address: val(form, "address"),
        extraNames: splitList(val(form, "extra")),
        bind: val(form, "bind"),
        tileUrl: val(form, "tile"),
        logLevel: val(form, "loglevel"),
        allowAnonymous: val(form, "anon"),
        anonymousGroup: val(form, "anongroup"),
        strictGroups: val(form, "strict"),
        channels: val(form, "channels"),
        protobuf: val(form, "proto"),
        replay: val(form, "replay"),
        ports: Object.assign({}, p, { tcp: num(form, "p_tcp"), tcpAlt: num(form, "p_tcpalt"), tls: num(form, "p_tls"), udp: num(form, "p_udp"), http: num(form, "p_http"), https: num(form, "p_https"), enroll: num(form, "p_enroll"), websocket: num(form, "p_ws"), api: num(form, "p_api") }),
        mesh: Object.assign({}, m, { enabled: val(form, "mesh"), send: val(form, "meshsend"), groups: splitList(val(form, "meshgroups")), interface: val(form, "meshif"), ttl: num(form, "meshttl") }),
        repeater: { enabled: val(form, "rep"), intervalSec: num(form, "repint") },
        retention: { historyDays: num(form, "rhist"), chatDays: num(form, "rchat"), fileDays: num(form, "rfile"), missionDays: num(form, "rmis") },
        limits: Object.assign({}, l, { maxClients: num(form, "lmax"), maxPerIP: num(form, "lip"), maxMessageBytes: num(form, "lmsg"), maxUploadMB: num(form, "lup"), idleTimeoutSec: num(form, "lidle"), replayLimit: num(form, "lrep") }),
        certificates: Object.assign({}, c, { organization: val(form, "corg"), unit: val(form, "cunit"), password: val(form, "cpw"), clientDays: num(form, "cdays"), serverDays: num(form, "sdays") }),
        ldap: ldapFromForm(),
        meshtastic: Object.assign({}, mt, {
          enabled: val(form, "mt_on"),
          brokerPort: num(form, "mt_port"),
          brokerAnonymous: val(form, "mt_anon"),
          upstream: val(form, "mt_up"),
          root: val(form, "mt_root"),
          channels: splitList(val(form, "mt_ch")).map((p) => {
            const i = p.indexOf("=");
            return i < 0 ? { name: p, key: "AQ==" } : { name: p.slice(0, i).trim(), key: p.slice(i + 1).trim() };
          }),
          downlink: val(form, "mt_down"),
          downlinkChannel: val(form, "mt_dch"),
          intervalSec: num(form, "mt_int"),
          group: val(form, "mt_group"),
        }),
        feeds: {
          adsb: Object.assign({}, fa, { enabled: val(form, "fa_on"), lat: num(form, "fa_lat"), lon: num(form, "fa_lon"), radiusNm: num(form, "fa_rad"), intervalSec: num(form, "fa_int"), group: val(form, "fa_group"), url: val(form, "fa_url"), apiKey: val(form, "fa_key") }),
          ais: Object.assign({}, fs, { enabled: val(form, "fs_on"), username: val(form, "fs_user"), south: num(form, "fs_s"), west: num(form, "fs_w"), north: num(form, "fs_n"), east: num(form, "fs_e"), mmsi: val(form, "fs_mmsi"), intervalSec: num(form, "fs_int"), group: val(form, "fs_group") }),
        },
      };
      try {
        const res = await api("PUT", "/api/settings", next);
        setDirty(false);
        if (res.restartRequired) {
          confirmAction("Restart required", "The new settings take effect after a restart. Restart now?", "Restart", restart);
        } else {
          toast("Settings saved");
        }
      } catch (e) {
        fail(e);
      }
    });
    return () => window.removeEventListener("beforeunload", beforeUnload);
  }

  async function restart() {
    await api("POST", "/api/restart");
    toast("Restarting...");
    disconnectStream();
    const started = Date.now();
    await new Promise((r) => setTimeout(r, 1500));
    for (;;) {
      try {
        await api("GET", "/api/me");
        break;
      } catch (e) {
        if (Date.now() - started > 60000) {
          toast("The server has not come back yet. Reload the page in a moment.", true);
          return;
        }
        await new Promise((r) => setTimeout(r, 1000));
      }
    }
    toast("Server restarted");
    connectStream();
    route();
  }

  async function pageLogs(main) {
    pageHead(main, "Logs", "The server log, live. Warnings are bold and errors are highlighted.");
    const view = h("div", { class: "log-view", role: "log" });
    const filter = h("input", { type: "search", id: "lfilter", placeholder: "Filter the log", "aria-label": "Filter the log" });
    let paused = false;
    const pauseBtn = btn("Pause", () => {
      paused = !paused;
      pauseBtn.textContent = paused ? "Resume" : "Pause";
    });
    main.append(h("div", { class: "toolbar" }, filter, pauseBtn, btn("Clear", () => clear(view)), h("span", { class: "grow" })), view);
    const add = (line) => {
      const cls = / ERROR /.test(line) ? "error" : / WARN /.test(line) ? "warn" : "";
      const el = h("div", { class: cls }, line);
      const f = filter.value.trim().toLowerCase();
      if (f && !line.toLowerCase().includes(f)) el.style.display = "none";
      const atBottom = view.scrollTop + view.clientHeight >= view.scrollHeight - 30;
      view.append(el);
      while (view.childNodes.length > 3000) view.firstChild.remove();
      if (atBottom && !paused) view.scrollTop = view.scrollHeight;
    };
    filter.addEventListener("input", () => {
      const f = filter.value.trim().toLowerCase();
      for (const el of view.childNodes) el.style.display = !f || el.textContent.toLowerCase().includes(f) ? "" : "none";
    });
    const lines = await api("GET", "/api/logs?n=1000");
    (lines || []).forEach(add);
    view.scrollTop = view.scrollHeight;
    const proto = location.protocol === "https:" ? "wss://" : "ws://";
    let ws = null, closed = false, buffer = [];
    const open = () => {
      ws = new WebSocket(proto + location.host + "/api/logs/stream");
      ws.onmessage = (ev) => {
        if (paused) {
          buffer.push(ev.data);
          if (buffer.length > 3000) buffer.shift();
        } else {
          buffer.forEach(add);
          buffer = [];
          add(ev.data);
        }
      };
      ws.onclose = () => {
        if (!closed) setTimeout(open, 2000);
      };
    };
    open();
    return () => {
      closed = true;
      if (ws) ws.close();
    };
  }

  async function pageTokens(main) {
    pageHead(main, "API tokens", "Tokens let scripts and other software use the API without a password. Send them as \"Authorization: Bearer TOKEN\".", btn("New token", () => create(), "primary", "plus"));
    const box = h("div");
    main.append(box);
    const load = async () => {
      const list = await api("GET", "/api/tokens");
      clear(box).append(
        table(
          [
            { title: "Name", key: "name" },
            { title: "User", key: "user" },
            { title: "Kind", key: "kind" },
            { title: "Created", render: (r) => fmtDate(r.created) },
            { title: "Expires", render: (r) => (r.expires && new Date(r.expires).getFullYear() > 1971 ? fmtTime(r.expires) : "never") },
            { title: "Uses", render: (r) => (r.uses || 0) + (r.maxUses ? " of " + r.maxUses : "") },
            { title: "Last used", render: (r) => fmtAgo(r.lastUsed) },
            {
              title: "",
              cls: "actions",
              render: (r) =>
                btn("Delete", () =>
                  confirmAction("Delete token", "Delete this token? Software using it stops working.", "Delete", async () => {
                    await api("DELETE", "/api/tokens/" + enc(r.id));
                    load().catch(fail);
                  })
                ),
            },
          ],
          list,
          "No tokens yet."
        )
      );
    };
    const create = () => {
      const f = h("form", { class: "grid" }, field("Name", input("tname", "", { required: true })), field("Valid for (days)", input("tdays", "365", { type: "number", min: 0 }), "0 means it never expires."), S.me.admin ? field("For user", input("tuser", S.me.user)) : null);
      modal("New API token", f, [
        { label: "Cancel" },
        {
          label: "Create",
          primary: true,
          run: async () => {
            const r = await api("POST", "/api/tokens", { name: val(f, "tname"), days: num(f, "tdays"), user: S.me.admin ? val(f, "tuser") : undefined });
            load().catch(fail);
            modal("Token created", h("div", null, h("p", null, "Copy the token now. It is not shown again."), h("p", { class: "mono break" }, h("b", null, r.token))), [{ label: "Copy", run: () => (copy(r.token), true) }, { label: "Done", primary: true }]);
          },
        },
      ]);
    };
    await load();
  }

  async function pageAccount(main) {
    pageHead(main, "My account", null, btn("Sign out", signOut, "", "signout"));
    if (S.me.initialPassword) main.append(h("div", { class: "notice inv" }, "You are signed in with the generated password. Choose your own below."));
    main.append(h("h2", null, "Account"), kv([["User", S.me.user], ["Role", S.me.admin ? "administrator" : "user"], ["Groups", joined(S.me.groups)], ["Server", S.me.server + " " + (S.me.version || "")]]));
    const f = h(
      "form",
      { class: "grid" },
      h("h2", { class: "full" }, "Change password"),
      field("Current password", input("cur", "", { type: "password", autocomplete: "current-password", required: true })),
      field("New password", input("npw", "", { type: "password", autocomplete: "new-password", required: true, minlength: 8 })),
      field("Repeat new password", input("npw2", "", { type: "password", autocomplete: "new-password", required: true, minlength: 8 })),
      h("div", { class: "full" }, h("button", { type: "submit", class: "primary" }, "Change password"))
    );
    f.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      if (val(f, "npw") !== val(f, "npw2")) return toast("The new passwords do not match", true);
      try {
        await api("PUT", "/api/me/password", { current: f.querySelector("#cur").value, password: f.querySelector("#npw").value });
        S.me.initialPassword = false;
        f.reset();
        toast("Password changed");
      } catch (e) {
        fail(e);
      }
    });
    const t = theme();
    const themeSel = select("theme", [["auto", "Follow the system"], ["light", "Light"], ["dark", "Dark"]], t);
    themeSel.addEventListener("change", () => setTheme(themeSel.value));
    main.append(f, h("h2", null, "Display"), h("form", { class: "grid" }, field("Theme", themeSel)));
  }

  window.addEventListener("hashchange", route);
  boot();
})();
