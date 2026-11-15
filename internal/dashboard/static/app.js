// mancar dashboard: a dependency-free single-page app. Every value from the
// server is inserted as text (never as HTML), so data cannot inject markup.
"use strict";

const API = "/api/v1/admin";
const REFRESH_MS = 5000;

const state = { user: null, view: "overview", data: {}, timer: null };

// ---- DOM helpers -----------------------------------------------------------

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const LOGO = () => {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 32 32");
  svg.setAttribute("aria-hidden", "true");
  const p = document.createElementNS(ns, "path");
  p.setAttribute("d", "M5 24V8l11 9 11-9v16");
  p.setAttribute("fill", "none");
  p.setAttribute("stroke", "white");
  p.setAttribute("stroke-width", "3.5");
  p.setAttribute("stroke-linecap", "round");
  p.setAttribute("stroke-linejoin", "round");
  svg.append(p);
  return h("span", { class: "logo" }, svg);
};

function toast(msg) {
  let t = document.querySelector(".toast");
  if (!t) document.body.append((t = h("div", { class: "toast", role: "status" })));
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.remove("show"), 2600);
}

function ago(iso) {
  if (!iso) return "never";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 0) return "in " + dur(-s);
  if (s < 10) return "just now";
  return dur(s) + " ago";
}

function dur(s) {
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m";
  if (s < 86400) return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
  return Math.floor(s / 86400) + "d " + Math.floor((s % 86400) / 3600) + "h";
}

const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString() : "");

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied to clipboard");
  } catch {
    toast("Copy failed: select the text and copy it manually");
  }
}

// ---- API -------------------------------------------------------------------

class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function api(method, path, body) {
  const opts = { method, headers: { Accept: "application/json" }, credentials: "same-origin" };
  if (method !== "GET") opts.headers["X-Mancar-CSRF"] = "1";
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(API + path, opts);
  if (res.status === 204) return null;
  let json = null;
  try {
    json = await res.json();
  } catch {
    /* non-JSON error page */
  }
  if (!res.ok) {
    const e = (json && json.error) || {};
    if (res.status === 401 && path !== "/login" && path !== "/session") {
      state.user = null;
      stopRefresh();
      renderLogin(e.message);
    }
    throw new ApiError(res.status, e.code || "http_" + res.status, e.message || res.statusText);
  }
  return json;
}

// ---- views -----------------------------------------------------------------

const VIEWS = {
  overview: { title: "Overview", load: loadOverview, render: renderOverview },
  agents: { title: "Agents & tunnels", load: () => api("GET", "/agents"), render: renderAgents },
  tokens: { title: "Tokens", load: () => api("GET", "/tokens"), render: renderTokens },
  users: { title: "Users", load: () => api("GET", "/users"), render: renderUsers },
  domains: { title: "Domains", load: () => api("GET", "/domains"), render: renderDomains },
};

async function loadOverview() {
  const [o, a] = await Promise.all([api("GET", "/overview"), api("GET", "/agents")]);
  return { ...o, agents: a.agents };
}

function renderLogin(message) {
  const err = h("div", { class: "error", role: "alert", hidden: !message }, message || "");
  const user = h("input", { name: "username", autocomplete: "username", required: true, autofocus: true });
  const pass = h("input", { name: "password", type: "password", autocomplete: "current-password", required: true });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Log in");
  const form = h(
    "form",
    {
      class: "form",
      onsubmit: async (ev) => {
        ev.preventDefault();
        btn.disabled = true;
        err.hidden = true;
        try {
          const r = await api("POST", "/login", { username: user.value, password: pass.value });
          state.user = r.username;
          renderShell();
        } catch (e) {
          err.textContent = e.message;
          err.hidden = false;
          pass.value = "";
          pass.focus();
        } finally {
          btn.disabled = false;
        }
      },
    },
    err,
    h("label", {}, "Username", user),
    h("label", {}, "Password", pass),
    btn,
  );
  const app = document.getElementById("app");
  app.replaceChildren(
    h(
      "div",
      { class: "login" },
      h(
        "div",
        { class: "login-card" },
        h("div", { class: "brand" }, LOGO(), "mancar"),
        h("p", { class: "muted small" }, "Sign in to manage your tunnel gateway."),
        form,
        h("p", { class: "muted small" }, "No account? On the server run ", h("code", {}, "mancard admin set --user NAME"), "."),
      ),
    ),
  );
  user.focus();
}

function renderShell() {
  const nav = h(
    "nav",
    { class: "nav", "aria-label": "Sections" },
    Object.entries(VIEWS).map(([key, v]) =>
      h(
        "button",
        { "data-view": key, onclick: () => go(key), "aria-current": state.view === key ? "page" : null },
        h("span", {}, v.title),
        h("span", { class: "count", "data-count": key, hidden: true }),
      ),
    ),
  );
  const side = h(
    "aside",
    { class: "side" },
    h("div", { class: "brand" }, LOGO(), "mancar"),
    nav,
    h(
      "div",
      { class: "side-foot" },
      h("span", { class: "muted small" }, "Signed in as ", h("strong", {}, state.user)),
      h("button", { class: "btn sm", onclick: logout }, "Log out"),
    ),
  );
  document.getElementById("app").replaceChildren(h("div", { class: "shell" }, side, h("main", { id: "main" })));
  go(location.hash.slice(1) in VIEWS ? location.hash.slice(1) : state.view);
}

async function logout() {
  try {
    await api("POST", "/logout");
  } catch {
    /* the cookie is cleared either way */
  }
  state.user = null;
  stopRefresh();
  renderLogin();
}

function go(view) {
  state.view = view;
  if (location.hash !== "#" + view) history.replaceState(null, "", "#" + view);
  document.querySelectorAll(".nav button").forEach((b) => {
    if (b.dataset.view === view) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  document.getElementById("main").replaceChildren(head(VIEWS[view].title), h("p", { class: "muted" }, "Loading…"));
  refresh(true);
}

function stopRefresh() {
  clearTimeout(state.timer);
  state.timer = null;
}

async function refresh(first) {
  stopRefresh();
  const view = state.view;
  try {
    const data = await VIEWS[view].load();
    if (state.view !== view || !state.user) return;
    state.data[view] = data;
    // Don't redraw underneath an open dialog or while the user is typing.
    if (first || !document.querySelector("dialog[open]")) draw();
  } catch (e) {
    if (e.status === 401) return;
    if (first) document.getElementById("main").replaceChildren(head(VIEWS[view].title), h("div", { class: "error" }, e.message));
  }
  if (state.user) state.timer = setTimeout(refresh, REFRESH_MS);
}

function draw() {
  const v = VIEWS[state.view];
  const main = document.getElementById("main");
  if (!main) return;
  main.replaceChildren(...[].concat(v.render(state.data[state.view])));
  updateCounts();
}

function updateCounts() {
  const d = state.data;
  const set = (k, n) => {
    const el = document.querySelector(`[data-count="${k}"]`);
    if (!el) return;
    el.hidden = n == null;
    if (n != null) el.textContent = n;
  };
  const agents = (d.agents && d.agents.agents) || (d.overview && d.overview.agents);
  if (agents) set("agents", agents.length);
  if (d.tokens) set("tokens", d.tokens.tokens.filter((t) => !t.revoked_at).length);
  if (d.users) set("users", d.users.users.length);
  if (d.domains) set("domains", d.domains.domains.length);
}

function head(title, sub, ...actions) {
  return h("div", { class: "head" }, h("div", {}, h("h1", {}, title), sub && h("p", { class: "muted" }, sub)), actions.length ? h("div", { class: "row" }, actions) : null);
}

function table(cols, rows, empty) {
  if (!rows.length) return h("div", { class: "empty" }, empty);
  return h(
    "div",
    { class: "table-wrap" },
    h("table", {}, h("thead", {}, h("tr", {}, cols.map((c) => h("th", { scope: "col" }, c)))), h("tbody", {}, rows)),
  );
}

function confirmThen(message, fn) {
  return async () => {
    if (!confirm(message)) return;
    try {
      await fn();
      refresh();
    } catch (e) {
      toast(e.message);
    }
  };
}

function tunnelLink(t) {
  const url = t.public_url;
  const proto = h("span", { class: "badge" }, t.proto.toUpperCase());
  const link = t.proto === "http" ? h("a", { href: url, target: "_blank", rel: "noopener noreferrer", class: "mono" }, url) : h("span", { class: "mono" }, url);
  return h(
    "div",
    { class: "tunnel" },
    proto,
    link,
    h("button", { class: "btn sm", title: "Copy URL", onclick: () => copy(url) }, "Copy"),
    t.active_connections ? h("span", { class: "muted small" }, t.active_connections + " open") : null,
  );
}

// overview
function renderOverview(o) {
  const tunnels = o.agents.flatMap((a) => a.tunnels.map((t) => ({ ...t, username: a.username })));
  const db = o.database === "ok" ? h("span", { class: "badge ok" }, h("span", { class: "dot" }), "healthy") : h("span", { class: "badge danger" }, h("span", { class: "dot" }), o.database);
  return [
    head("Overview", "Gateway for " + o.base_domain),
    h(
      "div",
      { class: "grid" },
      stat("Connected agents", o.gateway.sessions),
      stat("Live tunnels", o.gateway.tunnels),
      stat("Users", o.users),
      stat("Active tokens", o.active_tokens),
      stat("Reserved domains", o.reserved_domains),
    ),
    h(
      "section",
      { class: "panel" },
      h("div", { class: "panel-head" }, h("h2", {}, "Live tunnels"), h("button", { class: "btn sm", onclick: () => go("agents") }, "Manage agents")),
      table(
        ["URL", "User", "Since"],
        tunnels.map((t) => h("tr", {}, h("td", {}, tunnelLink(t)), h("td", {}, t.username || "?"), h("td", { title: fmtDate(t.created_at) }, ago(t.created_at)))),
        "No tunnels are online. Start one with: mancar http 3000",
      ),
    ),
    h(
      "section",
      { class: "panel" },
      h("div", { class: "panel-head" }, h("h2", {}, "Server")),
      h(
        "div",
        { class: "panel-body" },
        h(
          "dl",
          { class: "kv" },
          h("dt", {}, "Version"),
          h("dd", { class: "mono" }, o.version),
          h("dt", {}, "Base domain"),
          h("dd", { class: "mono" }, o.base_domain),
          h("dt", {}, "Agent server URL"),
          h("dd", { class: "mono" }, location.origin),
          h("dt", {}, "TCP port range"),
          h("dd", { class: "mono" }, o.tcp_ports),
          h("dt", {}, "Database"),
          h("dd", {}, db),
          h("dt", {}, "Uptime"),
          h("dd", {}, dur(o.uptime_seconds)),
        ),
      ),
    ),
  ];
}

const stat = (label, value) => h("div", { class: "stat" }, h("div", { class: "label" }, label), h("div", { class: "value" }, value));

// agents
function renderAgents(d) {
  const rows = d.agents.map((a) =>
    h(
      "tr",
      {},
      h("td", {}, h("strong", {}, a.username || "?"), h("div", { class: "muted small" }, "token: " + (a.token_name || a.token_id.slice(0, 8)))),
      h("td", {}, a.tunnels.length ? h("div", { class: "tunnels" }, a.tunnels.map(tunnelLink)) : h("span", { class: "muted" }, "no tunnels")),
      h("td", { class: "mono" }, a.client || ""),
      h("td", { class: "mono small" }, a.agent_version || "?"),
      h("td", { title: fmtDate(a.connected_at) }, ago(a.connected_at)),
      h(
        "td",
        { class: "actions" },
        h(
          "button",
          {
            class: "btn sm danger",
            onclick: confirmThen(`Disconnect ${a.username}'s agent? Its tunnels go offline; the agent reconnects unless its token is revoked.`, () =>
              api("POST", `/agents/${encodeURIComponent(a.id)}/disconnect`),
            ),
          },
          "Disconnect",
        ),
      ),
    ),
  );
  return [
    head("Agents & tunnels", "Every connected mancar client and the tunnels it serves."),
    h("section", { class: "panel" }, table(["User", "Tunnels", "Client address", "Agent", "Connected", ""], rows, "No agents are connected.")),
  ];
}

// tokens
function renderTokens(d) {
  const rows = d.tokens.map((t) => {
    const status = t.revoked_at
      ? h("span", { class: "badge danger" }, "revoked")
      : t.connected_agents
        ? h("span", { class: "badge ok" }, h("span", { class: "dot" }), "online")
        : h("span", { class: "badge" }, "active");
    return h(
      "tr",
      {},
      h("td", {}, h("strong", {}, t.name), h("div", { class: "muted small mono" }, t.id)),
      h("td", {}, t.username),
      h("td", {}, status),
      h("td", { title: fmtDate(t.created_at) }, ago(t.created_at)),
      h("td", { title: fmtDate(t.last_used_at) }, ago(t.last_used_at)),
      h(
        "td",
        { class: "actions" },
        t.revoked_at
          ? null
          : h(
              "button",
              {
                class: "btn sm danger",
                onclick: confirmThen(`Revoke token "${t.name}" of ${t.username}? Agents using it are disconnected now and cannot reconnect.`, async () => {
                  const r = await api("POST", `/tokens/${encodeURIComponent(t.id)}/revoke`);
                  toast(`Token revoked${r.disconnected_agents ? `, ${r.disconnected_agents} agent(s) disconnected` : ""}`);
                }),
              },
              "Revoke",
            ),
      ),
    );
  });
  return [
    head("Tokens", "Agent tokens let a mancar client connect. A secret is shown only once.", h("button", { class: "btn primary", onclick: () => newTokenDialog() }, "New token")),
    h("section", { class: "panel" }, table(["Name", "User", "Status", "Created", "Last used", ""], rows, "No tokens yet. Create one to connect your first client.")),
  ];
}

function newTokenDialog(presetUser) {
  const err = h("div", { class: "error", role: "alert", hidden: true });
  const user = h("input", { name: "user", required: true, autocomplete: "off", spellcheck: "false", value: presetUser || "", pattern: "[a-z0-9][a-z0-9._\\-]{0,63}" });
  const name = h("input", { name: "name", autocomplete: "off", placeholder: "laptop" });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Create token");
  const dlg = h("dialog", { "aria-label": "New token" });
  const close = () => {
    dlg.close();
    dlg.remove();
    refresh();
  };
  const form = h(
    "form",
    {
      class: "dialog-body",
      onsubmit: async (ev) => {
        ev.preventDefault();
        btn.disabled = true;
        try {
          const r = await api("POST", "/tokens", { user: user.value.trim().toLowerCase(), name: name.value.trim() });
          dlg.replaceChildren(tokenCreated(r, close));
        } catch (e) {
          err.textContent = e.message;
          err.hidden = false;
          btn.disabled = false;
        }
      },
    },
    h("h2", {}, "New agent token"),
    err,
    h("label", {}, "User", user, h("span", { class: "hint" }, "Lower-case letters, digits, '.', '_' or '-'. A new user is created if needed.")),
    h("label", {}, "Label", name, h("span", { class: "hint" }, "Where the token is used, for example the machine name.")),
    h("div", { class: "row" }, h("button", { class: "btn", type: "button", onclick: close }, "Cancel"), btn),
  );
  dlg.append(form);
  dlg.addEventListener("cancel", (e) => {
    e.preventDefault();
    close();
  });
  document.body.append(dlg);
  dlg.showModal();
  (presetUser ? name : user).focus();
}

function tokenCreated(r, close) {
  const cmds = `mancar config set server ${location.origin}\nmancar config set token -   # paste the token, then Ctrl+D\nmancar http 3000`;
  return h(
    "div",
    { class: "dialog-body" },
    h("h2", {}, "Token created"),
    h("div", { class: "notice" }, "Copy it now. It is not stored and will never be shown again."),
    h("div", { class: "secret" }, h("code", {}, r.token), h("button", { class: "btn", onclick: () => copy(r.token) }, "Copy")),
    h("p", { class: "muted small" }, `For user ${r.user} (${r.name}). Set up the client with:`),
    h("pre", {}, cmds),
    h("div", { class: "row" }, h("button", { class: "btn", onclick: () => copy(cmds) }, "Copy commands"), h("button", { class: "btn primary", onclick: close }, "Done")),
  );
}

// users
function renderUsers(d) {
  const rows = d.users.map((u) =>
    h(
      "tr",
      {},
      h("td", {}, h("strong", {}, u.username)),
      h("td", {}, u.connected_agents ? h("span", { class: "badge ok" }, h("span", { class: "dot" }), u.connected_agents + " online") : h("span", { class: "muted" }, "offline")),
      h("td", {}, u.active_tokens),
      h("td", {}, u.domains),
      h("td", { title: fmtDate(u.created_at) }, ago(u.created_at)),
      h(
        "td",
        { class: "actions" },
        h("button", { class: "btn sm", onclick: () => newTokenDialog(u.username) }, "New token"),
        " ",
        h(
          "button",
          {
            class: "btn sm danger",
            onclick: confirmThen(`Delete user ${u.username}? All their tokens and reserved names are deleted and their agents disconnected. This cannot be undone.`, () =>
              api("DELETE", `/users/${encodeURIComponent(u.id)}`),
            ),
          },
          "Delete",
        ),
      ),
    ),
  );
  return [
    head("Users", "People or services that own agent tokens and hostnames.", h("button", { class: "btn primary", onclick: () => newTokenDialog() }, "New user")),
    h("section", { class: "panel" }, table(["User", "Agents", "Active tokens", "Domains", "Created", ""], rows, "No users yet. Creating a token creates its user.")),
  ];
}

// domains
function renderDomains(d) {
  const rows = d.domains.map((x) =>
    h(
      "tr",
      {},
      h("td", { class: "mono" }, x.hostname),
      h("td", {}, x.username),
      h("td", {}, h("span", { class: "badge" }, x.kind)),
      h("td", {}, x.online ? h("span", { class: "badge ok" }, h("span", { class: "dot" }), "online") : h("span", { class: "badge warn", title: fmtDate(x.hold_until) }, "held, frees " + ago(x.hold_until))),
      h(
        "td",
        { class: "actions" },
        x.online
          ? null
          : h(
              "button",
              {
                class: "btn sm danger",
                onclick: confirmThen(`Release ${x.hostname}? Anyone can claim it afterwards.`, () => api("DELETE", `/domains/${encodeURIComponent(x.hostname)}`)),
              },
              "Release",
            ),
      ),
    ),
  );
  return [
    head("Domains", "Hostnames in use or held for their owner after a disconnect."),
    h("section", { class: "panel" }, table(["Hostname", "User", "Kind", "Status", ""], rows, "No hostnames are reserved.")),
  ];
}

// ---- start -----------------------------------------------------------------

window.addEventListener("hashchange", () => {
  const v = location.hash.slice(1);
  if (state.user && v in VIEWS && v !== state.view) go(v);
});

document.addEventListener("visibilitychange", () => {
  if (state.user && document.visibilityState === "visible") refresh();
});

(async function start() {
  try {
    const s = await api("GET", "/session");
    state.user = s.username;
    renderShell();
  } catch (e) {
    renderLogin(e.status === 401 ? undefined : e.message);
  }
})();
