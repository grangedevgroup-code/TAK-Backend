"use strict";
(function () {
  const list = document.getElementById("list");
  const search = document.getElementById("search");
  const meta = document.getElementById("meta");
  let ops = [];

  function el(tag, attrs, children) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else n.setAttribute(k, v);
    }
    for (const c of children || []) n.append(c);
    return n;
  }

  function methodClass(m) {
    return ["get", "post", "put", "delete"].includes(m) ? "m-" + m : "m-other";
  }

  function detail(op) {
    const box = el("div", { class: "detail" });
    const inputs = {};
    for (const p of op.params) {
      const id = "p-" + op.key + "-" + p;
      box.append(el("label", { for: id, text: p }));
      const inp = el("input", { type: "text", id: id, autocomplete: "off" });
      inputs[p] = inp;
      box.append(inp);
    }
    const qid = "q-" + op.key;
    box.append(el("label", { for: qid, text: "Query string" }));
    const query = el("input", { type: "text", id: qid, placeholder: "name=value&other=value", autocomplete: "off" });
    box.append(query);
    let body = null;
    if (["post", "put", "patch", "delete"].includes(op.method)) {
      const bid = "b-" + op.key;
      box.append(el("label", { for: bid, text: "Request body" }));
      body = el("textarea", { id: bid, spellcheck: "false" });
      box.append(body);
    }
    const send = el("button", { class: "send", type: "button", text: "Send request" });
    const status = el("div", { class: "status" });
    const out = el("pre", { hidden: "" });
    send.addEventListener("click", async () => {
      let path = op.path;
      for (const p of op.params) path = path.replace("{" + p + "}", encodeURIComponent(inputs[p].value));
      const q = query.value.trim().replace(/^\?/, "");
      const url = path + (q ? "?" + q : "");
      const init = { method: op.method.toUpperCase(), credentials: "same-origin", headers: {} };
      if (body && body.value.trim()) {
        init.body = body.value;
        const t = body.value.trim();
        init.headers["Content-Type"] = t.startsWith("{") || t.startsWith("[") ? "application/json" : t.startsWith("<") ? "application/xml" : "text/plain";
      }
      send.disabled = true;
      status.textContent = init.method + " " + url + " …";
      try {
        const r = await fetch(url, init);
        const type = r.headers.get("Content-Type") || "";
        let text;
        if (/json/.test(type)) {
          try { text = JSON.stringify(await r.json(), null, 2); } catch (e) { text = ""; }
        } else if (/^(text|application\/(xml|yaml|javascript))/.test(type) || type === "") {
          text = await r.text();
        } else {
          const b = await r.blob();
          text = "(" + type + ", " + b.size + " bytes)";
        }
        status.textContent = r.status + " " + r.statusText + "  " + init.method + " " + url;
        out.textContent = text.length > 200000 ? text.slice(0, 200000) + "\n…" : text;
        out.hidden = false;
      } catch (e) {
        status.textContent = "Request failed: " + e.message;
        out.hidden = true;
      } finally {
        send.disabled = false;
      }
    });
    box.append(send, status, out);
    return box;
  }

  function render() {
    const f = search.value.trim().toLowerCase();
    const groups = new Map();
    for (const op of ops) {
      if (f && !(op.path.toLowerCase().includes(f) || op.tag.toLowerCase().includes(f) || op.summary.toLowerCase().includes(f) || op.method.includes(f))) continue;
      if (!groups.has(op.tag)) groups.set(op.tag, []);
      groups.get(op.tag).push(op);
    }
    list.replaceChildren();
    if (groups.size === 0) {
      list.append(el("p", { class: "empty", text: "No endpoints match." }));
      return;
    }
    for (const tag of [...groups.keys()].sort((a, b) => a.localeCompare(b))) {
      const sec = el("section", {}, [el("h2", { text: tag })]);
      for (const op of groups.get(tag)) {
        const card = el("div", { class: "op" });
        const head = el("button", { type: "button", "aria-expanded": "false" }, [
          el("span", { class: "method " + methodClass(op.method), text: op.method.toUpperCase() }),
          el("span", { class: "path", text: op.path }),
          el("span", { class: "summary", text: op.summary }),
        ]);
        if (op.access) head.append(el("span", { class: "badge", text: op.access }));
        let built = false;
        head.addEventListener("click", () => {
          if (!built) { card.append(detail(op)); built = true; }
          const open = card.classList.toggle("open");
          head.setAttribute("aria-expanded", String(open));
        });
        card.append(head);
        sec.append(card);
      }
      list.append(sec);
    }
  }

  async function load() {
    try {
      const r = await fetch("/v3/api-docs", { credentials: "same-origin" });
      if (r.status === 401) {
        list.replaceChildren(el("p", { class: "empty", text: "Sign in to the dashboard first, then reload this page." }));
        return;
      }
      const doc = await r.json();
      let n = 0;
      for (const [path, item] of Object.entries(doc.paths || {})) {
        for (const [method, op] of Object.entries(item)) {
          const params = (op.parameters || []).filter((p) => p.in === "path").map((p) => p.name);
          ops.push({ key: n++, path, method, params, tag: (op.tags || ["other"])[0], summary: op.summary || "", access: op["x-access"] || "" });
        }
      }
      ops.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
      meta.textContent = (doc.info && doc.info.title ? doc.info.title + " " + (doc.info.version || "") + " · " : "") + ops.length + " operations";
      render();
    } catch (e) {
      list.replaceChildren(el("p", { class: "empty", text: "Could not load the API description: " + e.message }));
    }
  }

  search.addEventListener("input", render);
  load();
})();
