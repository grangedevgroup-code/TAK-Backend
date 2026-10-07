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
    if (!rows.length) return h("p", { class: "muted" }, empty || "Nothing here yet.");
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

  function btn(label, onclick, cls) {
    return h("button", { type: "button", class: cls || "", onclick: onclick }, label);
  }

  function modal(title, body, actions) {
    const back = h("div", { class: "modal-back" });
    const close = () => {
      back.remove();
      document.removeEventListener("keydown", onKey);
    };
    const onKey = (ev) => {
      if (ev.key === "Escape") close();
    };
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
          a.primary ? "primary" : ""
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

  function field(label, input, hint) {
    return [h("label", { for: input.id || undefined }, label), h("div", null, input, hint ? h("div", { class: "muted small" }, hint) : null)];
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
      refreshEvents();
    };
    ws.onmessage = (ev) => {
      try {
        onStream(JSON.parse(ev.data));
      } catch (e) {}
    };
    ws.onclose = () => {
      S.ws = null;
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
    { id: "overview", title: "Overview", render: pageOverview },
    { id: "connect", title: "Connect a device", render: pageConnect },
    { id: "map", title: "Map", render: pageMap },
    { id: "chat", title: "Chat", render: pageChat },
    { id: "clients", title: "Connected clients", render: pageClients },
    { id: "devices", title: "Devices", render: pageDevices },
    { sep: true },
    { id: "files", title: "Files", render: pageFiles },
    { id: "missions", title: "Missions", render: pageMissions },
    { id: "video", title: "Video feeds", render: pageVideo },
    { sep: true, admin: true },
    { id: "users", title: "Users", admin: true, render: pageUsers },
    { id: "groups", title: "Groups", admin: true, render: pageGroups },
    { id: "links", title: "Server links", admin: true, render: pageLinks },
    { id: "plugins", title: "Plugins and profiles", admin: true, render: pagePlugins },
    { id: "settings", title: "Settings", admin: true, render: pageSettings },
    { id: "logs", title: "Logs", admin: true, render: pageLogs },
    { sep: true },
    { id: "tokens", title: "API tokens", render: pageTokens },
    { id: "account", title: "My account", render: pageAccount },
  ];

  let alertEl = null;

  function updateAlert() {
    if (!alertEl) return;
    const n = emergencies().length;
    alertEl.style.display = n ? "" : "none";
    alertEl.textContent = n === 1 ? "1 EMERGENCY" : n + " EMERGENCIES";
  }

  function layout() {
    clear(root);
    const side = h("nav", { class: "side", "aria-label": "Sections" });
    alertEl = h("a", { class: "alert", href: "#/map", style: "display:none" });
    const top = h(
      "header",
      { class: "top" },
      btn("Menu", () => side.classList.toggle("open"), "menu"),
      h("span", { class: "brand" }, "GolangTAK"),
      h("span", { class: "server" }, S.me.server || ""),
      h("span", { class: "spacer" }),
      alertEl,
      h("span", { class: "who" }, S.me.user + (S.me.admin ? " (admin)" : "")),
      btn("Sign out", signOut)
    );
    for (const p of PAGES) {
      if (p.admin && !S.me.admin) continue;
      if (p.sep) {
        side.append(h("div", { class: "sep" }));
        continue;
      }
      side.append(h("a", { href: "#/" + p.id, "data-page": p.id, onclick: () => side.classList.remove("open") }, p.title));
    }
    const main = h("main", { id: "main" });
    root.append(top, h("div", { class: "layout" }, side, main));
    updateAlert();
  }

  async function route() {
    if (!S.me) return;
    const hash = location.hash.replace(/^#\/?/, "");
    const [id, ...rest] = hash.split("/");
    let page = PAGES.find((p) => p.id === id && !p.sep && (!p.admin || S.me.admin));
    if (!page) {
      page = PAGES[0];
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
    if (!document.getElementById("main")) layout();
    const side = document.querySelector(".side");
    if (side) side.classList.remove("open");
    for (const a of document.querySelectorAll(".side a")) a.classList.toggle("active", a.dataset.page === page.id);
    const main = clear(document.getElementById("main"));
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
      h("h1", null, "GolangTAK"),
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
    root.append(form);
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

  async function pageOverview(main) {
    const st = await api("GET", "/api/status");
    main.append(h("h1", null, "Overview"), h("p", { class: "lead" }, st.name + " is running. Version " + st.version + ", up " + fmtDuration(st.uptimeSeconds) + "."));
    if (S.me.initialPassword) {
      main.append(h("div", { class: "notice inv" }, "You are signed in with the generated administrator password. ", h("a", { href: "#/account" }, "Change it now"), "."));
    }
    const cards = [
      ["Connected", st.clients],
      ["Users", st.users],
      ["Devices", st.devices],
      ["Missions", st.missions],
      ["Files", st.files],
      ["Events", st.events],
      ["Emergencies", st.emergencies],
      ["Memory", fmtBytes(st.memoryBytes)],
    ];
    main.append(h("div", { class: "cards" }, cards.map(([l, n]) => h("div", { class: "card" }, h("div", { class: "n" }, n), h("div", { class: "l" }, l)))));
    const kinds = Object.entries(st.clientsByKind || {}).map(([k, v]) => k + " " + v).join(", ");
    main.append(
      h("h2", null, "Server"),
      kv([
        ["Name", st.name],
        ["Address", st.address],
        ["Certificate names", joined(st.serverNames)],
        ["Host", st.hostname + " (" + st.os + "/" + st.arch + ", " + st.cpus + " CPU)"],
        ["Started", fmtTime(st.started)],
        ["Clients by type", kinds || "none"],
        ["Data directory", h("span", { class: "mono" }, st.dataDir)],
        ["Stored files", fmtBytes(st.filesBytes) + " in " + st.files + " files"],
        ["History", fmtBytes(st.historyBytes) + " over " + st.historyDays + " days"],
      ])
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
    ].filter((r) => r[1] > 0);
    main.append(h("h2", null, "Ports"), table([{ title: "Service", render: (r) => r[0] }, { title: "Port", render: (r) => h("span", { class: "mono" }, r[1]) }, { title: "Used by", render: (r) => r[2] }], portRows));
    main.append(
      h("h2", null, "Certificates"),
      kv([
        ["Certificate authority", st.caSubject],
        ["Fingerprint (SHA-256)", h("span", { class: "mono break" }, st.caFingerprint)],
        ["Authority valid until", fmtDate(st.caExpires)],
        ["Server certificate valid until", fmtDate(st.serverCertExpires)],
      ])
    );
    const feeds = (st.feeds || []).filter((f) => f.enabled);
    if (feeds.length) {
      main.append(h("h2", null, "Data feeds"), table([{ title: "Feed", render: (r) => (r.name === "adsb" ? "ADS-B aircraft" : "AIS ships") }, { title: "Items", key: "items" }, { title: "Last update", render: (r) => fmtAgo(r.lastOk) }, { title: "Problem", render: (r) => r.error || "-" }], feeds));
    }
    if (st.peers && st.peers.length) {
      main.append(h("h2", null, "Server links"), table([{ title: "Name", key: "name" }, { title: "URL", render: (r) => h("span", { class: "mono" }, r.url) }, { title: "State", render: (r) => r.state + (r.error ? " (" + r.error + ")" : "") }], st.peers));
    }
    const em = await api("GET", "/api/emergencies");
    main.append(h("h2", null, "Active emergencies"), table([{ title: "Callsign", key: "callsign" }, { title: "Type", key: "type" }, { title: "Position", render: (r) => fmtCoord(r.lat, r.lon) }, { title: "Time", render: (r) => fmtTime(r.time) }], em, "No active emergencies."));
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
    main.append(h("h1", null, "Connect a device"), h("p", { class: "lead" }, "Choose the address devices use to reach this server, then scan a QR code, download a connection package, or enter the settings by hand."));
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
        }, "primary")
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
        }, "primary")
      );
      body.append(
        h("h2", null, "QR codes"),
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
        h("h2", null, "Connection packages"),
        h("p", null, "Copy a package to the device and import it (ATAK: Import, Local SD; iTAK: Settings, Network, Servers, Upload server package; WinTAK: Import)."),
        h(
          "div",
          { class: "toolbar" },
          h("a", { class: "button primary", href: pkg("cert") }, "Certificate package for " + user),
          h("a", { class: "button", href: pkg("enroll") }, "Enrollment package (signs in with password)"),
          info.ports.tcp || info.ports.tcpAlt ? h("a", { class: "button", href: pkg("tcp") }, "TCP package (unencrypted)") : null
        )
      );
      body.append(
        h("h2", null, "Manual setup"),
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
    main.append(h("h1", null, "Map"));
    const coords = h("div", { class: "map-coords" }, "");
    const infoBox = h("div", { class: "map-info" });
    const canvas = h("canvas", { class: "gray" });
    let gray = true;
    try {
      gray = localStorage.getItem("golangtak-map-color") !== "1";
    } catch (e) {}
    canvas.classList.toggle("gray", gray);
    const wrap = h("div", { class: "map-wrap" }, canvas, infoBox, coords, h("div", { class: "map-attr" }, S.me.tileUrl && S.me.tileUrl.includes("openstreetmap") ? "Map data © OpenStreetMap contributors" : ""));
    let addMode = false;
    let showTracks = false;
    const addBtn = btn("Add marker", () => {
      addMode = !addMode;
      addBtn.classList.toggle("primary", addMode);
      addBtn.textContent = addMode ? "Click the map to place the marker" : "Add marker";
    });
    const countEl = h("span", { class: "muted" });
    main.append(
      h(
        "div",
        { class: "toolbar" },
        btn("Show all", () => fitAll(true)),
        addBtn,
        checkbox("tracks", false, "Tracks (last hour)"),
        checkbox("color", !gray, "Color map"),
        h("span", { class: "grow" }),
        countEl
      ),
      wrap
    );
    const map = new SlippyMap(canvas, { tileUrl: S.me.tileUrl, lat: 20, lon: 0, zoom: 3 });
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
        addBtn.textContent = "Add marker";
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
    main.querySelector("#color").addEventListener("change", (ev) => {
      canvas.classList.toggle("gray", !ev.target.checked);
      try {
        localStorage.setItem("golangtak-map-color", ev.target.checked ? "1" : "0");
      } catch (e) {}
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
    main.append(h("h1", null, "Chat"), h("p", { class: "lead" }, "Messages from the last 24 hours. Messages you send appear on TAK devices under the room or contact you choose."));
    const log = h("div", { class: "chat-log", "aria-live": "polite" });
    const seen = new Set();
    const add = (v) => {
      if (!v.chat || seen.has(v.uid)) return;
      seen.add(v.uid);
      const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 30;
      log.append(h("div", { class: "msg" }, h("div", { class: "meta" }, fmtTime(v.time) + "  " + (v.callsign || "?") + " to " + (v.to || "All Chat Rooms")), h("div", { class: "body" }, v.chat)));
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
    const msg = h("input", { id: "msg", placeholder: "Message", autocomplete: "off", style: "flex:1;min-width:200px" });
    const form = h("form", { class: "inline" }, h("label", { for: "to" }, "To"), to, msg, h("button", { type: "submit", class: "primary" }, "Send"));
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
    main.append(log, form);
    log.scrollTop = log.scrollHeight;
    S.listeners.add((v) => {
      if (v && v.chat) add(v);
    });
    msg.focus();
  }

  async function pageClients(main) {
    main.append(h("h1", null, "Connected clients"), h("p", { class: "lead" }, "Devices and links connected right now. Updates every 5 seconds."));
    const box = h("div");
    main.append(box);
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
          "No clients are connected."
        )
      );
    };
    await load();
    const t = setInterval(() => load().catch(() => {}), 5000);
    return () => clearInterval(t);
  }

  async function pageDevices(main) {
    main.append(h("h1", null, "Devices"), h("p", { class: "lead" }, "Every device that has connected, with its last known position."));
    const box = h("div");
    main.append(box);
    const load = async () => {
      const list = await api("GET", "/api/devices");
      list.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
      clear(box).append(
        table(
          [
            { title: "Callsign", key: "callsign" },
            { title: "Status", render: (r) => (r.lastStatus === "Connected" ? h("span", { class: "badge inv" }, "Connected") : r.lastStatus || "-") },
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
          "No devices have connected yet."
        )
      );
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
    main.append(h("h1", null, "Files"), h("p", { class: "lead" }, "Data packages and files shared with TAK devices (Data Sync and data package server)."));
    const fileInput = h("input", { type: "file", id: "upfile", multiple: true });
    const groups = input("upgroups", "", { placeholder: "Groups (optional, comma separated)" });
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
    main.append(h("form", { class: "inline", onsubmit: (e) => e.preventDefault() }, fileInput, groups, kw, btn("Upload", upload, "primary")), box);
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
    main.append(h("h1", null, "Missions"), h("p", { class: "lead" }, "Data Sync missions: shared collections of map items and files that devices subscribe to."));
    const box = h("div");
    main.append(h("div", { class: "toolbar" }, btn("New mission", () => createMission(), "primary")), box);
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
          "No missions yet.",
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
      h("p", null, h("a", { href: "#/missions" }, "Missions")),
      h("h1", null, m.name),
      h("p", { class: "lead" }, m.description || ""),
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
    main.append(h("h1", null, "Video feeds"), h("p", { class: "lead" }, "Video streams listed for TAK devices (RTSP, RTMP, SRT, UDP, HTTP)."));
    const box = h("div");
    main.append(h("div", { class: "toolbar" }, btn("Add feed", () => addFeed(), "primary")), box);
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
    main.append(h("h1", null, "Users"), h("p", { class: "lead" }, "Accounts for people and devices. Users sign in to TAK clients with their name and password, or with a certificate from a connection package."));
    const box = h("div");
    main.append(h("div", { class: "toolbar" }, btn("Add user", () => addUser(), "primary")), box);
    const load = async () => {
      const users = await api("GET", "/api/users");
      users.sort((a, b) => a.name.localeCompare(b.name));
      clear(box).append(
        table(
          [
            { title: "Name", render: (r) => h("b", null, r.name) },
            { title: "Role", render: (r) => (r.admin ? "admin" : "user") + (r.disabled ? ", disabled" : "") },
            { title: "Callsign", key: "callsign" },
            { title: "Receives from", render: (r) => joined(r.in) },
            { title: "Sends to", render: (r) => joined(r.out) },
            { title: "Certificates", render: (r) => String((r.certs || []).filter((c) => !c.revoked).length) },
            { title: "Online", key: "online" },
            { title: "Last sign-in", cls: "nowrap", render: (r) => fmtAgo(r.lastLogin) },
            {
              title: "",
              cls: "actions",
              render: (r) => [btn("QR", () => enrollQR(r.name)), h("a", { class: "button", href: "/api/package?type=cert&user=" + enc(r.name) }, "Package"), btn("Edit", () => editUser(r)), btn("Password", () => setPassword(r))],
            },
          ],
          users,
          "No users."
        )
      );
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
    main.append(h("h1", null, "Groups"), h("p", { class: "lead" }, "Groups (channels) decide who sees whose traffic. Users receive from their receive groups and send to their send groups."));
    const box = h("div");
    const name = input("gname", "", { placeholder: "Group name" });
    const desc = input("gdesc", "", { placeholder: "Description" });
    const form = h("form", { class: "inline" }, name, desc, h("button", { type: "submit", class: "primary" }, "Add group"));
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
    main.append(form, box);
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
    main.append(
      h("h1", null, "Server links"),
      h("p", { class: "lead" }, "Exchange traffic with other servers in both directions: TAK Server, OpenTAKServer, FreeTAKServer, zyrntopo-tak-server, another GolangTAK, or any software that speaks CoT over TCP, TLS, UDP or WebSocket.")
    );
    const box = h("div");
    const fedBox = h("div");
    main.append(h("div", { class: "toolbar" }, btn("Add link", () => editPeer(null), "primary")), box, h("h2", null, "Federation"), fedBox);
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
                if (!r.enabled) return "disabled";
                return s ? s.state + (s.error ? " (" + s.error + ")" : "") : "-";
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
    main.append(h("h1", null, "Plugins and profiles"), h("p", { class: "lead" }, "Publish ATAK plugins through the update server and push settings and files to devices when they enroll or connect."));
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
        }, "primary")
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
    main.append(h("h2", null, "Device profile"), h("p", null, "Settings sent to devices as a data package. Choose whether each applies at enrollment, at every connection, or both."), h("div", { class: "toolbar" }, btn("Add setting", () => addPref(), "primary")), prbox);
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

  async function pageSettings(main) {
    const cfg = await api("GET", "/api/settings");
    main.append(h("h1", null, "Settings"), h("p", { class: "lead" }, "Changes to ports, the bind address, mesh or federation need a restart; the server offers it after saving."));
    const actions = h(
      "div",
      { class: "toolbar" },
      btn("Restart server", () => confirmAction("Restart", "Restart the server now? Devices reconnect automatically.", "Restart", restart)),
      btn("Renew server certificate", async () => {
        try {
          await api("POST", "/api/certs/server/renew");
          toast("Server certificate renewed");
        } catch (e) {
          fail(e);
        }
      }),
      h("a", { class: "button", href: "/api/backup" }, "Download backup"),
      h("a", { class: "button", href: "/api/backup?files=1" }, "Backup with files")
    );
    main.append(actions);
    const p = cfg.ports, m = cfg.mesh, c = cfg.certificates, r = cfg.retention, l = cfg.limits;
    const fa = (cfg.feeds && cfg.feeds.adsb) || {}, fs = (cfg.feeds && cfg.feeds.ais) || {};
    const n = (id, v) => input(id, v, { type: "number", min: 0 });
    const form = h(
      "form",
      { class: "grid" },
      h("h2", { class: "full" }, "General"),
      field("Server name", input("name", cfg.name)),
      field("Public address", input("address", cfg.address), "Address devices use. Used in QR codes, packages and the server certificate."),
      field("Other names", input("extra", (cfg.extraNames || []).join(", ")), "More DNS names or IPs for the server certificate."),
      field("Listen on", input("bind", cfg.bind, { placeholder: "all addresses" })),
      field("Map tiles", input("tile", cfg.tileUrl), "Tile URL with {z}, {x}, {y}. Point it at a local tile server for networks without internet."),
      field("Log level", select("loglevel", ["debug", "info", "warn", "error"], cfg.logLevel)),
      h("h2", { class: "full" }, "Access"),
      field("Unsigned clients", checkbox("anon", cfg.allowAnonymous, "Allow plain TCP, UDP and anonymous connections")),
      field("Default group", input("anongroup", cfg.anonymousGroup)),
      field("Strict groups", checkbox("strict", cfg.strictGroups, "Never deliver traffic outside a client's groups")),
      field("Channels", checkbox("channels", cfg.channels, "Let devices choose active groups")),
      field("TAK protocol", checkbox("proto", cfg.protobuf, "Offer TAK Protocol version 1 (protobuf) to clients")),
      field("Replay to new clients", select("replay", [["all", "All current items"], ["sa", "Positions only"], ["none", "Nothing"]], cfg.replay)),
      h("h2", { class: "full" }, "Ports (0 disables)"),
      field("TAK TCP", n("p_tcp", p.tcp)),
      field("TAK TCP second port", n("p_tcpalt", p.tcpAlt)),
      field("TAK SSL", n("p_tls", p.tls)),
      field("UDP", n("p_udp", p.udp)),
      field("HTTP", n("p_http", p.http)),
      field("HTTPS", n("p_https", p.https)),
      field("Enrollment", n("p_enroll", p.enroll)),
      field("WebSocket", n("p_ws", p.websocket)),
      field("FreeTAKServer API", n("p_api", p.api)),
      h("h2", { class: "full" }, "Mesh (multicast SA)"),
      field("Receive", checkbox("mesh", m.enabled, "Listen to multicast situational awareness")),
      field("Send", checkbox("meshsend", m.send, "Repeat server traffic to multicast")),
      field("Groups", input("meshgroups", (m.groups || []).join(", "))),
      field("Interface", input("meshif", m.interface, { placeholder: "all" })),
      field("TTL", n("meshttl", m.ttl)),
      h("h2", { class: "full" }, "Emergency repeater"),
      field("Repeat alerts", checkbox("rep", cfg.repeater.enabled, "Resend active emergencies to everyone")),
      field("Every (seconds)", n("repint", cfg.repeater.intervalSec)),
      h("h2", { class: "full" }, "Retention (days, 0 keeps forever)"),
      field("History", n("rhist", r.historyDays)),
      field("Offline chat", n("rchat", r.chatDays)),
      field("Files", n("rfile", r.fileDays)),
      field("Missions", n("rmis", r.missionDays)),
      h("h2", { class: "full" }, "Limits"),
      field("Clients", n("lmax", l.maxClients)),
      field("Clients per address", n("lip", l.maxPerIP)),
      field("Largest message (bytes)", n("lmsg", l.maxMessageBytes)),
      field("Largest upload (MB)", n("lup", l.maxUploadMB)),
      field("Idle timeout (seconds)", n("lidle", l.idleTimeoutSec)),
      field("Items replayed", n("lrep", l.replayLimit)),
      h("h2", { class: "full" }, "ADS-B aircraft feed"),
      field("Enabled", checkbox("fa_on", fa.enabled, "Show aircraft from an ADS-B exchange on all devices")),
      field("Center latitude", input("fa_lat", fa.lat)),
      field("Center longitude", input("fa_lon", fa.lon)),
      field("Radius (nautical miles)", n("fa_rad", fa.radiusNm)),
      field("Update every (seconds)", n("fa_int", fa.intervalSec)),
      field("Group", input("fa_group", fa.group, { placeholder: "everyone" }), "Only members of this group see the aircraft. Empty sends to everyone."),
      field("Source URL", input("fa_url", fa.url), "airplanes.live, adsb.lol or any service with the same /point/lat/lon/radius API."),
      field("API key", input("fa_key", fa.apiKey, { autocomplete: "off" })),
      h("h2", { class: "full" }, "AIS ship feed (AISHub)"),
      field("Enabled", checkbox("fs_on", fs.enabled, "Show ships from AISHub on all devices")),
      field("AISHub user name", input("fs_user", fs.username, { autocomplete: "off" })),
      field("South", input("fs_s", fs.south)),
      field("West", input("fs_w", fs.west)),
      field("North", input("fs_n", fs.north)),
      field("East", input("fs_e", fs.east)),
      field("MMSI list", input("fs_mmsi", fs.mmsi), "Optional, comma separated."),
      field("Update every (seconds)", n("fs_int", fs.intervalSec), "AISHub allows one request per minute."),
      field("Group", input("fs_group", fs.group, { placeholder: "everyone" })),
      h("h2", { class: "full" }, "Certificates"),
      field("Organization", input("corg", c.organization)),
      field("Unit", input("cunit", c.unit)),
      field("Package password", input("cpw", c.password), "Password of the .p12 files in connection packages."),
      field("Client validity (days)", n("cdays", c.clientDays)),
      field("Server validity (days)", n("sdays", c.serverDays)),
      h("div", { class: "full" }, h("button", { type: "submit", class: "primary" }, "Save settings"))
    );
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
        feeds: {
          adsb: Object.assign({}, fa, { enabled: val(form, "fa_on"), lat: num(form, "fa_lat"), lon: num(form, "fa_lon"), radiusNm: num(form, "fa_rad"), intervalSec: num(form, "fa_int"), group: val(form, "fa_group"), url: val(form, "fa_url"), apiKey: val(form, "fa_key") }),
          ais: Object.assign({}, fs, { enabled: val(form, "fs_on"), username: val(form, "fs_user"), south: num(form, "fs_s"), west: num(form, "fs_w"), north: num(form, "fs_n"), east: num(form, "fs_e"), mmsi: val(form, "fs_mmsi"), intervalSec: num(form, "fs_int"), group: val(form, "fs_group") }),
        },
      };
      try {
        const res = await api("PUT", "/api/settings", next);
        if (res.restartRequired) {
          confirmAction("Restart required", "The new settings take effect after a restart. Restart now?", "Restart", restart);
        } else {
          toast("Settings saved");
        }
      } catch (e) {
        fail(e);
      }
    });
    main.append(form);
    const raw = h("textarea", { id: "raw", style: "min-height:320px" });
    raw.value = JSON.stringify(cfg, null, 2);
    main.append(
      h("h2", null, "Advanced: all settings as JSON"),
      h("p", { class: "muted" }, "Every option in config.json. Peer passwords are shown as ********; leave them as they are to keep them."),
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
    main.append(h("h1", null, "Logs"));
    const view = h("div", { class: "log-view", role: "log" });
    const filter = input("lfilter", "", { placeholder: "Filter" });
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
    main.append(h("h1", null, "API tokens"), h("p", { class: "lead" }, "Tokens let scripts and other software use the API without a password: send them as \"Authorization: Bearer TOKEN\"."));
    const box = h("div");
    main.append(h("div", { class: "toolbar" }, btn("New token", () => create(), "primary")), box);
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
          "No tokens."
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
    main.append(h("h1", null, "My account"), kv([["User", S.me.user], ["Role", S.me.admin ? "administrator" : "user"], ["Groups", joined(S.me.groups)], ["Server", S.me.server + " " + (S.me.version || "")]]));
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
    main.append(f, h("h2", null, "Display"), h("form", { class: "grid" }, field("Theme", themeSel)), h("h2", null, "Session"), h("div", { class: "toolbar" }, btn("Sign out", signOut)));
  }

  window.addEventListener("hashchange", route);
  boot();
})();
