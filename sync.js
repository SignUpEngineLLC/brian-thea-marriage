// Saves the page's checkboxes and text boxes, and shares them between everyone who has the password.
// build.py inlines this into each page before encrypting it, filling in {{SYNC_URL}}.
//
// Each checkbox and textarea needs a data-id. Every change is stamped with its time, so two
// people editing at once both keep their changes: the newer stamp wins per item. The state is
// encrypted here with the key from the password page before it leaves the device; it is also
// kept on the device, so changes made offline sync once the phone is back online.
(function () {
  "use strict";
  var API = "{{SYNC_URL}}";
  var KEY_NAME = "btm-key";
  var CACHE_NAME = "btm-state:" + location.pathname;
  var POLL_MS = 20000;

  function storage(kind) { try { return window[kind]; } catch (e) { return null; } }
  function get(s, k) { try { return s ? s.getItem(k) : null; } catch (e) { return null; } }
  function set(s, k, v) { try { if (s) s.setItem(k, v); } catch (e) {} }
  function b64(bytes) { var s = ""; for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); }
  function unb64(s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); }

  var local = storage("localStorage"), session = storage("sessionStorage");
  var rawKey = get(local, KEY_NAME) || get(session, KEY_NAME);
  // Cache next to the key: "Remember on this device" off means nothing stays after the tab closes.
  var cache = get(local, KEY_NAME) ? local : session;
  var boxes = [].slice.call(document.querySelectorAll("input[type=checkbox][data-id]"));
  var areas = [].slice.call(document.querySelectorAll("textarea[data-id]"));

  var css = document.createElement("style");
  css.textContent =
    "#sync-status{position:fixed;left:50%;bottom:14px;transform:translateX(-50%);z-index:10;max-width:calc(100% - 32px);" +
    "padding:7px 14px;border-radius:999px;font:600 14px/1.3 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;" +
    "background:var(--card,#fff);color:var(--muted,#5b6370);border:1px solid var(--line,#e4e0da);box-shadow:0 2px 10px rgba(0,0,0,.12);text-align:center}" +
    "#sync-status.ok{color:var(--accent,#0f6e6e)}#sync-status.warn{color:var(--warn,#8a5a00);background:var(--warn-soft,#fff4e0)}" +
    "main{padding-bottom:90px !important}@media print{#sync-status{display:none}}";
  document.head.appendChild(css);
  var pill = document.createElement("div");
  pill.id = "sync-status";
  pill.setAttribute("role", "status");
  document.body.appendChild(pill);
  function status(text, kind) { pill.textContent = text; pill.className = kind || ""; }

  // State: {c: {<data-id>: {v, t}}}; v is true/false for a checkbox, text for a textarea.
  function empty() { return { c: {} }; }
  function clean(s) {
    s = s && typeof s === "object" ? s : {};
    var c = s.c && typeof s.c === "object" ? s.c : {};
    // The first version kept the notes box apart, in s.n.
    if (s.n && typeof s.n.v === "string" && s.n.t && !(c.notes && c.notes.t >= s.n.t)) c.notes = s.n;
    return { c: c };
  }
  // Newer stamp wins, item by item.
  function merge(a, b) {
    var out = { c: {} };
    [a.c, b.c].forEach(function (src) {
      Object.keys(src).forEach(function (id) { if (!out.c[id] || src[id].t > out.c[id].t) out.c[id] = src[id]; });
    });
    return out;
  }
  // Does a hold anything b hasn't seen?
  function ahead(a, b) {
    return Object.keys(a.c).some(function (id) { return !b.c[id] || a.c[id].t > b.c[id].t; });
  }

  var saved = null;
  try { saved = JSON.parse(get(cache, CACHE_NAME) || "null"); } catch (e) {}
  var state = clean(saved && saved.s);
  var version = (saved && saved.v) || 0;
  function persist() { set(cache, CACHE_NAME, JSON.stringify({ s: state, v: version })); }

  function render() {
    boxes.forEach(function (b) { var e = state.c[b.dataset.id]; b.checked = !!(e && e.v); });
    areas.forEach(function (a) {
      var e = state.c[a.dataset.id], v = e && typeof e.v === "string" ? e.v : "";
      // Never replace text someone is in the middle of typing.
      if (document.activeElement !== a && a.value !== v) a.value = v;
    });
  }

  var timer = null;
  function changed(delay) {
    persist();
    status("Saving…");
    clearTimeout(timer);
    timer = setTimeout(sync, delay);
  }
  boxes.forEach(function (b) {
    b.addEventListener("change", function () {
      state.c[b.dataset.id] = { v: b.checked, t: Date.now() };
      changed(300);
    });
  });
  areas.forEach(function (a) {
    a.addEventListener("input", function () { state.c[a.dataset.id] = { v: a.value, t: Date.now() }; changed(1200); });
    a.addEventListener("blur", function () { clearTimeout(timer); sync(); });
  });
  render();

  if (!rawKey || !window.crypto || !crypto.subtle || !window.fetch) {
    status("Saved on this device only. Reopen the page and enter the password to share.", "warn");
    return;
  }

  var keyP = crypto.subtle.importKey("raw", unb64(rawKey), "AES-GCM", false, ["encrypt", "decrypt"]);
  var tokenP = (function () {
    var prefix = new TextEncoder().encode("btm-sync|"), key = unb64(rawKey);
    var buf = new Uint8Array(prefix.length + key.length);
    buf.set(prefix); buf.set(key, prefix.length);
    return crypto.subtle.digest("SHA-256", buf).then(function (d) {
      return [].map.call(new Uint8Array(d), function (x) { return ("0" + x.toString(16)).slice(-2); }).join("");
    });
  })();

  async function seal(obj) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, await keyP, new TextEncoder().encode(JSON.stringify(obj)));
    return { i: b64(iv), d: b64(new Uint8Array(ct)) };
  }
  async function unseal(blob) {
    var pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(blob.i) }, await keyP, unb64(blob.d));
    return clean(JSON.parse(new TextDecoder().decode(pt)));
  }
  async function call(method, body) {
    var res = await fetch(API, {
      method: method,
      cache: "no-store",
      headers: { Authorization: "Bearer " + (await tokenP), "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    var data = null;
    try { data = await res.json(); } catch (e) {}
    return { status: res.status, body: data };
  }

  function Problem(message) { this.message = message; }
  var busy = false, again = false;
  async function sync() {
    if (busy) { again = true; return; }
    busy = true;
    try {
      var res = await call("GET");
      for (var tries = 0; ; tries++) {
        if (res.status === 401) throw new Problem("Can't share changes: the password has changed. Reload and enter the new one.");
        if (res.status !== 200 && res.status !== 409) throw new Error("HTTP " + res.status);
        var remote;
        try { remote = res.body.blob ? await unseal(res.body.blob) : empty(); }
        catch (e) { throw new Problem("Can't read the shared checklist. Reload and enter the password again."); }
        version = res.body.v;
        var mine = ahead(state, remote);
        state = merge(state, remote);
        render();
        persist();
        if (!mine) break;
        if (tries >= 5) throw new Error("too many conflicts");
        res = await call("PUT", { v: version, blob: await seal(state) });
        if (res.status === 200) { version = res.body.v; persist(); break; }
        // 409: someone else saved first. Their state comes back; merge it and try again.
      }
      status("✓ Saved for both of you", "ok");
    } catch (e) {
      if (e instanceof Problem) status(e.message, "warn");
      else status(navigator.onLine === false
        ? "Offline. Saved on this phone; it will share when you're back online."
        : "Couldn't reach the server. Saved on this phone; it will keep trying.", "warn");
    } finally {
      busy = false;
      if (again) { again = false; sync(); }
    }
  }

  status("Loading saved checks…");
  sync();
  setInterval(function () { if (document.visibilityState === "visible") sync(); }, POLL_MS);
  document.addEventListener("visibilitychange", function () { if (document.visibilityState === "visible") sync(); });
  window.addEventListener("online", sync);
})();
