// mancar dashboard: a dependency-free single-page app. Every value from the
// server is inserted as text (never as HTML), so data cannot inject markup.
"use strict";

// Two roles share this app. An admin manages the whole gateway through
// /api/v1/admin; a user sees only their own tunnels, tokens and requests
// through /api/v1/me. Sign in, sign up and email links are /api/v1/auth.
const API = "/api/v1/admin";
const ME_API = "/api/v1/me";
const AUTH_API = "/api/v1/auth";
const AUTH_PATHS = new Set(["/login", "/logout", "/session", "/options", "/setup", "/signup", "/signup/verify", "/signup/resend", "/password/forgot", "/password/reset"]);
const MIN_PASSWORD = 12; // the server's MinPasswordLength
const REFRESH_MS = 5000;
const OVERVIEW_TUNNELS = 6; // the overview lists the busiest few; the Agents page has them all
// Page sizes. Lists come whole from the API and are paged here; requests are
// the newest REQUESTS_LOADED (the API caps a list at 500).
const AGENTS_PER_PAGE = 10;
const REQUESTS_PER_PAGE = 25;
const REQUESTS_LOADED = 500;
const ROWS_PER_PAGE = 15; // users, tokens, domains

const state = {
  user: null, role: "admin", view: "overview", data: {}, timer: null, reqHost: "",
  agentQuery: "", agentShow: "all", // agents page: search and filter
  userShow: "all", // users page: role / status filter
  pages: {}, // current page per paginated list
  pendingDevice: null, // a "mancar login" code from #device=, shown after sign in
  pendingAccess: null, // "host/path" of a private tunnel from #ref=, opened after sign in
  freshLogin: false, // signed in on this page just now (not an older session)
  search: {}, // search text per list page (tokens, users, domains)
};

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

// the mancar mark: logo.webp in a circle next to the name. The image is set in
// style.css so its path resolves next to the stylesheet (also in the preview).
const LOGO = () => h("span", { class: "mark", "aria-hidden": "true" });

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

// copy(text, quiet): quiet skips the success toast for callers that show
// their own confirmation; a failure is always reported.
async function copy(text, quiet = false) {
  try {
    await navigator.clipboard.writeText(text);
    if (!quiet) toast("Copied to clipboard");
    return true;
  } catch {
    toast("Copy failed: select the text and copy it manually");
    return false;
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
  // a full /api/... path is used as is (an admin's own account lives under /me)
  const base = path.startsWith("/api/") ? "" : AUTH_PATHS.has(path) ? AUTH_API : state.role === "user" ? ME_API : API;
  const res = await fetch(base + path, opts);
  if (res.status === 204) return null;
  let json = null;
  try {
    json = await res.json();
  } catch {
    /* non-JSON error page */
  }
  if (!res.ok) {
    const e = (json && json.error) || {};
    if (res.status === 401 && !AUTH_PATHS.has(path)) {
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
  overview: { title: "Overview", icon: "home", load: loadOverview, render: renderOverview },
  agents: { title: "Agents & tunnels", icon: "agents", load: () => api("GET", "/agents"), render: renderAgents },
  requests: { title: "Requests", icon: "activity", load: loadRequests, render: renderRequests },
  tokens: { title: "Tokens", icon: "tokens", load: () => api("GET", "/tokens"), render: renderTokens },
  users: { title: "Users", icon: "user", load: () => api("GET", "/users"), render: renderUsers },
  domains: { title: "Domains", icon: "domains", load: () => api("GET", "/domains"), render: renderDomains },
  activity: { title: "Activity", icon: "clock", load: () => api("GET", "/audit"), render: renderActivity },
  account: { title: "Account", icon: "shield", load: () => api("GET", own("/account")), render: renderAccount, static: true },
};

// own(path): an endpoint of the signed-in account itself, for either role.
const own = (path) => (state.role === "user" ? path : ME_API + path);

// What a signed-in user (not an admin) sees: only their own things. The
// paths resolve under /api/v1/me (see api()).
const USER_VIEWS = {
  overview: { title: "Overview", icon: "home", load: () => api("GET", "/overview"), render: renderMyOverview },
  tunnels: { title: "Tunnels", icon: "link", load: () => api("GET", "/overview"), render: renderMyTunnels },
  requests: { title: "Requests", icon: "activity", load: loadRequests, render: renderRequests },
  tokens: { title: "Tokens", icon: "tokens", load: () => api("GET", "/tokens"), render: renderTokens },
  // static: no auto-refresh, so a half-typed password is never wiped
  account: { title: "Account", icon: "shield", load: () => api("GET", own("/account")), render: renderAccount, static: true },
};

const views = () => (state.role === "user" ? USER_VIEWS : VIEWS);

// signIn(session): store who is signed in and open the app on a view that
// exists for their role.
function signIn(s) {
  state.user = s.username;
  state.role = s.role === "user" ? "user" : "admin";
  state.data = {};
  if (!(state.view in views())) state.view = "overview";
  if (state.pendingAccess) return openAccess(); // leaves for the tunnel
  renderShell();
  if (state.pendingDevice) deviceDialog();
}

// openAccess: a private tunnel's Restricted page sent the browser to sign
// in with #ref=HOST/PATH. Once signed in it goes back: with a one-time
// ticket if this account owns the tunnel, otherwise to the Restricted page.
async function openAccess() {
  const target = state.pendingAccess;
  const fresh = state.freshLogin;
  state.pendingAccess = null;
  state.freshLogin = false;
  const host = target.split(/[/?]/)[0];
  try {
    const r = await api("POST", own("/access"), { target });
    if (r.allowed) accessGranted(host, r.url);
    else if (fresh) location.replace(r.url); // just logged in, still no access: the Restricted page again
    else {
      // came signed in with an account that has no access: let them switch
      state.pendingAccess = target;
      renderLogin(`You are signed in as ${state.user}, which has no access to ${host}. Log in with another account.`);
    }
  } catch (e) {
    // not a tunnel of this server: just the dashboard
    history.replaceState(null, "", location.pathname);
    signIn({ username: state.user, role: state.role });
    toast(e.message);
  }
}

// accessGranted: the owner is let in; the tunnel opens after a short
// countdown, or at once with the button. (The ticket in url lasts a minute.)
function accessGranted(host, url) {
  let left = 5;
  const note = h("p", { class: "auth-note" });
  const tick = () => {
    note.replaceChildren(left > 0 ? `Opening ${host} in ${left} s…` : `Opening ${host}…`);
    if (left-- <= 0) {
      clearInterval(timer);
      location.replace(url);
    }
  };
  const timer = setInterval(tick, 1000);
  authPage(
    "Private tunnel",
    h("div", { class: "check-email" }, h("span", { class: "check-icon ok", "aria-hidden": "true" }, icon("check")), h("h1", { class: "check-title" }, "Access granted"), note),
    h("div", { class: "form" }, button("Open now", () => {
      clearInterval(timer);
      location.replace(url);
    }, { kind: "primary" })),
  );
  tick();
}

// deviceDialog: "mancar login" in a terminal waits for this. It shows the
// device name and code so the person can check they match their terminal.
async function deviceDialog() {
  const code = state.pendingDevice;
  state.pendingDevice = null;
  let dev;
  try {
    dev = await api("GET", own(`/device/${encodeURIComponent(code)}`));
  } catch (e) {
    toast(e.message);
    return;
  }
  sheet("Sign in a device", (close) => [
    group(null, h(
      "div",
      { class: "card profile" },
      avatar(icon("terminal")),
      h("div", { class: "cell-text" }, h("span", { class: "profile-title" }, dev.name), h("span", { class: "cell-subtitle" }, `wants to use mancar as ${state.user}`)),
    )),
    group("Code in your terminal", h("div", { class: "card device-code" }, dev.user_code), "Allow only if this matches the code mancar login printed. Allowing creates a token for this device; revoke it any time under Tokens."),
    group(null, actions(
      button("Deny", async () => {
        await api("POST", own(`/device/${encodeURIComponent(dev.user_code)}/deny`)).catch(() => {});
        close();
        toast("Denied");
      }, { icon: "ban" }),
      button("Allow", confirmThen({ title: `Allow ${dev.name}?`, message: "It can open tunnels as you until you revoke its token.", action: "Allow", danger: false }, async () => {
        await api("POST", own(`/device/${encodeURIComponent(dev.user_code)}/approve`));
        close();
        toast("Allowed. Go back to your terminal.");
      }), { kind: "primary", icon: "check" }),
    )),
  ]);
}

async function loadOverview() {
  const [o, a] = await Promise.all([api("GET", "/overview"), api("GET", "/agents")]);
  return { ...o, agents: a.agents };
}

// authPage(sub, ...content): the centered card used by sign in, sign up and
// "check your email".
function authPage(sub, ...content) {
  document.getElementById("app").replaceChildren(
    h(
      "div",
      { class: "login" },
      h(
        "div",
        { class: "login-card" },
        h("div", { class: "brand" }, LOGO(), h("span", { class: "brand-text" }, h("span", { class: "brand-name" }, "mancar"), h("span", { class: "brand-sub" }, sub))),
        content,
      ),
    ),
  );
}

// authOptions: what the gateway offers on the sign in page (sign up open,
// "forgot password" available). Older gateways answer 404: neither.
async function authOptions() {
  try {
    return await api("GET", "/options");
  } catch {
    return { signup: false, password_reset: false };
  }
}

// busyForm(fields, label, submit): a sign-in style form whose button shows
// a spinner while submit runs; a thrown error is shown above the fields.
function busyForm(fields, label, submit) {
  const err = h("div", { class: "error", role: "alert", hidden: true });
  const btn = h("button", { class: "btn primary", type: "submit" }, label);
  const form = h(
    "form",
    {
      class: "form",
      onsubmit: async (ev) => {
        ev.preventDefault();
        btn.disabled = true;
        btn.setAttribute("aria-busy", "true");
        err.hidden = true;
        try {
          await submit();
        } catch (e) {
          err.textContent = e.message;
          err.hidden = false;
        } finally {
          btn.disabled = false;
          btn.removeAttribute("aria-busy");
        }
      },
    },
    err,
    fields,
    btn,
  );
  return form;
}

const passwordInput = (name = "password") =>
  h("input", { name, type: "password", autocomplete: name === "password" ? "current-password" : "new-password", required: true, minlength: name === "password" ? null : MIN_PASSWORD });

const passwordLabel = (text, input) => h("label", {}, h("span", {}, text + " ", h("span", { class: "label-hint" }, `· at least ${MIN_PASSWORD} characters`)), input);

const switchLink = (text, label, onclick) => h("p", { class: "auth-switch" }, text, h("button", { class: "link-btn strong", type: "button", onclick }, label));

function renderLogin(message) {
  const user = h("input", { name: "username", autocomplete: "username", required: true, autofocus: true });
  const pass = passwordInput();
  const form = busyForm([h("label", {}, "Email or username", user), h("label", {}, "Password", pass)], "Log in", async () => {
    try {
      const s = await api("POST", "/login", { username: user.value, password: pass.value });
      state.freshLogin = true;
      signIn(s);
    } catch (e) {
      pass.value = "";
      pass.focus();
      throw e;
    }
  });
  if (message) {
    const err = form.querySelector(".error");
    err.textContent = message;
    err.hidden = false;
  }
  // filled once the gateway says what it offers
  const forgot = h("div", { class: "auth-forgot" });
  const footer = h("div", { class: "auth-footer" });
  authPage("Sign in to the tunnel dashboard", form, forgot, footer);
  user.focus();
  authOptions().then((o) => {
    if (o.setup) {
      state.setupVersion = o.version || ""; // shown in the wizard's panel
      return renderSetup(); // a fresh server: no admin yet
    }
    if (o.password_reset) forgot.replaceChildren(h("button", { class: "link-btn", type: "button", onclick: () => renderForgot() }, "Forgot password?"));
    footer.replaceChildren(
      ...(o.signup
        ? [switchLink("No account yet? ", "Create one", () => renderSignup())]
        : [h("p", { class: "muted small login-hint" }, "No account? Ask the admin, or on the server run:"), codeBlock("mancard user create NAME")]),
    );
  });
}

// ---- first-run setup wizard --------------------------------------------------
//
// A fresh gateway has no admin; whoever opens it first creates one (the
// server closes setup as soon as an admin exists). Three steps:
//   1 Welcome  2 Admin account (username, email, password; signs in)  3 Done

const SETUP_STEPS = [
  ["Welcome", "What this is"],
  ["Admin account", "Username, email and password"],
  ["Done", "Open the dashboard"],
];

// setupPage(step, ...content): one wide card in two parts: a blue panel on
// the left with the logo and the steps, the current step on the right. On
// phones the panel becomes a header with the steps in a row.
function setupPage(step, ...content) {
  const steps = h(
    "ol",
    { class: "steps", "aria-label": `Step ${step + 1} of ${SETUP_STEPS.length}` },
    SETUP_STEPS.map(([label, hint], i) =>
      h(
        "li",
        { class: i < step ? "done" : i === step ? "current" : "", "aria-current": i === step ? "step" : null },
        h("span", { class: "step-dot", "aria-hidden": "true" }, i < step ? icon("check") : String(i + 1)),
        h("span", { class: "step-text" }, h("span", { class: "step-label" }, label), h("span", { class: "step-hint" }, hint)),
      ),
    ),
  );
  document.getElementById("app").replaceChildren(
    h(
      "div",
      { class: "setup" },
      h(
        "div",
        { class: "setup-card" },
        h(
          "aside",
          { class: "setup-panel" },
          h("div", { class: "brand" }, LOGO(), h("span", { class: "brand-text" }, h("span", { class: "brand-name" }, "mancar"), h("span", { class: "brand-sub" }, "Set up your tunnel server"))),
          steps,
          state.setupVersion ? h("p", { class: "setup-host" }, "mancar " + state.setupVersion) : null,
        ),
        // flat(): content may hold nested arrays, and h() flattens one level only
        h("main", { class: "setup-body" }, ...content.flat(Infinity)),
      ),
    ),
  );
}

const stepHead = (ic, title, note) =>
  h("div", { class: "check-email" }, h("span", { class: "check-icon", "aria-hidden": "true" }, icon(ic)), h("h1", { class: "check-title" }, title), note ? h("p", { class: "auth-note" }, note) : null);

function renderSetup() {
  setupPage(
    0,
    h(
      "div",
      { class: "check-email" },
      h("span", { class: "mark mark-lg", "aria-hidden": "true" }),
      h("h1", { class: "check-title" }, "Welcome to mancar"),
      h("p", { class: "auth-note" }, "Create the admin account to get started."),
    ),
    h("div", { class: "form" }, button("Start", () => renderSetupAccount(), { kind: "primary", icon: "arrow" })),
  );
}

function renderSetupAccount() {
  const user = h("input", { name: "username", autocomplete: "username", required: true, spellcheck: "false", placeholder: "admin", pattern: "[a-z0-9][a-z0-9._\\-]{0,63}" });
  const email = h("input", { name: "email", type: "email", autocomplete: "email", required: true, placeholder: "you@example.com" });
  const pass = passwordInput("new-password");
  // username and email side by side (stacked on narrow screens)
  const form = busyForm([h("div", { class: "field-pair" }, h("label", {}, "Username", user), h("label", {}, "Email", email)), passwordLabel("Password", pass)], "Create admin", async () => {
    const s = await api("POST", "/setup", { username: user.value.trim().toLowerCase(), email: email.value.trim(), password: pass.value });
    renderSetupDone(s);
  });
  // Back and the submit button share one row at the bottom
  const submit = form.querySelector('button[type="submit"]');
  const row = h("div", { class: "step-actions" }, button("Back", () => renderSetup(), { icon: "back" }));
  submit.replaceWith(row); // first take its place, then move it into the row
  row.append(submit);
  setupPage(1, stepHead("user", "Create the admin account", "This account manages everything on this tunnel server. Sign in later with the username or the email."), form);
  user.focus();
}

function renderSetupDone(session) {
  setupPage(
    2,
    stepHead("check", "All set", `You are signed in as ${session.username}. Next: Tokens → Create token, then connect a client.`),
    h("div", { class: "form" }, button("Open the dashboard", () => signIn(session), { kind: "primary", icon: "arrow" })),
  );
}

// renderSignup: email, username and password. The next screen asks to
// confirm the address; it looks the same whether or not the address
// already had an account.
function renderSignup() {
  const email = h("input", { name: "email", type: "email", autocomplete: "email", required: true, placeholder: "you@example.com" });
  const user = h("input", {
    name: "username", autocomplete: "username", required: true, spellcheck: "false", placeholder: "tino",
    pattern: "[a-z0-9][a-z0-9._\\-]{0,63}", title: "Lowercase letters, digits, dot, dash or underscore",
  });
  const pass = passwordInput("new-password");
  const form = busyForm([h("label", {}, "Email", email), h("label", {}, "Username", user), passwordLabel("Password", pass)], "Create account", async () => {
    await api("POST", "/signup", { email: email.value.trim(), username: user.value.trim().toLowerCase(), password: pass.value });
    renderCheckEmail(email.value.trim());
  });
  authPage(
    "Create your account",
    h("p", { class: "auth-note" }, "We'll send a link to confirm your email before you can create tokens."),
    form,
    switchLink("Already have an account? ", "Sign in", () => renderLogin()),
  );
  email.focus();
}

function renderCheckEmail(address, reset = false) {
  const resend = button("Send the link again", async () => {
    resend.disabled = true;
    try {
      await api("POST", reset ? "/password/forgot" : "/signup/resend", { email: address });
      toast("Sent. Check your inbox and spam folder.");
    } catch (e) {
      toast(e.message);
    }
    setTimeout(() => (resend.disabled = false), 30000); // the server rate-limits too
  }, { icon: "replay" });
  authPage(
    reset ? "Reset your password" : "Confirm your email",
    h(
      "div",
      { class: "check-email" },
      h("span", { class: "check-icon", "aria-hidden": "true" }, icon("mail")),
      h("h1", { class: "check-title" }, "Check your inbox"),
      h(
        "p",
        { class: "auth-note" },
        reset
          ? ["If ", h("strong", {}, address), " has an account, we sent it a link to choose a new password. It works for 1 hour."]
          : ["We sent a confirmation link to ", h("strong", {}, address), ". It works for 24 hours."],
      ),
    ),
    h("div", { class: "form" }, resend, button("Back to sign in", () => renderLogin(), { kind: "primary" })),
  );
}

function renderForgot() {
  const email = h("input", { name: "email", type: "email", autocomplete: "email", required: true, placeholder: "you@example.com" });
  const form = busyForm([h("label", {}, "Email", email)], "Send reset link", async () => {
    await api("POST", "/password/forgot", { email: email.value.trim() });
    renderCheckEmail(email.value.trim(), true);
  });
  authPage(
    "Reset your password",
    h("p", { class: "auth-note" }, "Enter the email of your account. We'll send a link to choose a new password."),
    form,
    switchLink("Remembered it? ", "Sign in", () => renderLogin()),
  );
  email.focus();
}

// renderReset(secret): the page a reset link opens.
function renderReset(secret) {
  const pass = passwordInput("new-password");
  const again = passwordInput("new-password");
  const form = busyForm([passwordLabel("New password", pass), h("label", {}, "New password again", again)], "Set new password", async () => {
    if (pass.value !== again.value) throw new Error("The two passwords differ.");
    await api("POST", "/password/reset", { token: secret, password: pass.value });
    renderLogin();
    toast("Password changed. Sign in with the new one.");
  });
  authPage("Choose a new password", form, switchLink("", "Back to sign in", () => renderLogin()));
  pass.focus();
}

// openLink: a "#verify=…" or "#reset=…" link from an email. The secret is
// removed from the address bar at once so it does not stay in history.
async function openLink() {
  // a private tunnel opens #ref=HOST/PATH: the usual sign in page, then on
  // to the tunnel. The ref stays in the address bar until then.
  const acc = location.hash.match(/^#ref=(.{3,2000})$/);
  if (acc) {
    let target = "";
    try {
      target = decodeURIComponent(acc[1]);
    } catch {}
    if (!/^[a-z0-9.-]+(?:[/?].*)?$/i.test(target)) {
      history.replaceState(null, "", location.pathname);
      return false;
    }
    state.pendingAccess = target;
    if (state.user) openAccess();
    return state.user ? "access" : false; // signed out: start() signs in first
  }
  // "mancar login" opens #device=CODE: ask to allow it once signed in
  const dev = location.hash.match(/^#device=([A-Za-z0-9-]{8,9})$/);
  if (dev) {
    state.pendingDevice = dev[1];
    history.replaceState(null, "", location.pathname);
    if (state.user) deviceDialog();
    return state.user ? "device" : false; // signed out: start() signs in first
  }
  const m = location.hash.match(/^#(verify|reset)=([A-Za-z0-9_-]{16,128})$/);
  if (!m) return false;
  history.replaceState(null, "", location.pathname);
  if (m[1] === "reset") {
    renderReset(m[2]);
    return true;
  }
  try {
    await api("POST", "/signup/verify", { token: m[2] });
    authPage(
      "Email confirmed",
      h(
        "div",
        { class: "check-email" },
        h("span", { class: "check-icon ok", "aria-hidden": "true" }, icon("check")),
        h("h1", { class: "check-title" }, "Email confirmed"),
        h("p", { class: "auth-note" }, "Your account is ready. Sign in to create a token and open tunnels."),
      ),
      h("div", { class: "form" }, button("Continue", () => start(), { kind: "primary" })),
    );
  } catch (e) {
    renderLogin(e.message);
  }
  return true;
}

function renderShell() {
  const nav = h(
    "nav",
    { class: "nav", "aria-label": "Sections" },
    Object.entries(views()).map(([key, v]) =>
      h(
        "button",
        { "data-view": key, onclick: () => go(key), "aria-current": state.view === key ? "page" : null },
        icon(v.icon),
        v.title,
        h("span", { class: "count", "data-count": key, hidden: true }),
      ),
    ),
  );
  // light or dark; until one is picked the page follows the system, and the
  // switch shows whichever of the two is in effect
  const themes = [["light", "sun", "Light"], ["dark", "moon", "Dark"]];
  const switcher = h(
    "div",
    { class: "segmented", role: "group", "aria-label": "Theme" },
    themes.map(([value, ic, label]) =>
      h(
        "button",
        {
          type: "button", title: label, "aria-label": label + " theme", "data-theme-choice": value,
          "aria-pressed": String(document.documentElement.dataset.theme === value),
          onclick: () => window.mancarTheme.set(value),
        },
        icon(ic),
      ),
    ),
  );
  const topbar = h(
    "header",
    { class: "topbar" },
    h("div", { class: "brand" }, LOGO(), h("span", { class: "brand-text" }, h("span", { class: "brand-name" }, "mancar"), h("span", { class: "brand-sub" }, "Tunnel dashboard"))),
    h(
      "div",
      { class: "bar-actions row" },
      h("button", { class: "text-link", type: "button", onclick: clientSheet }, icon("book"), h("span", {}, "Connect a client")),
      switcher,
      h("button", { class: "text-link", type: "button", onclick: logout, "aria-label": "Sign out " + state.user }, icon("logout"), h("span", {}, "Sign out")),
    ),
  );
  const page = h(
    "div",
    { class: "page" },
    h("div", { class: "eyebrow-row" }, h("span", { class: "eyebrow" }, state.user)),
    nav,
    h("main", { id: "main" }),
  );
  document.getElementById("app").replaceChildren(h("div", { class: "shell" }, h("div", { class: "frame" }, topbar, page)));
  go(location.hash.slice(1) in views() ? location.hash.slice(1) : state.view);
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
  document.getElementById("main").replaceChildren(head(views()[view].title), h("p", { class: "muted" }, "Loading…"));
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
    const data = await views()[view].load();
    if (state.view !== view || !state.user) return;
    state.data[view] = data;
    // Don't redraw underneath an open dialog or while the user is typing.
    const typing = document.activeElement && document.activeElement.matches("main input");
    if (first || (!document.querySelector("dialog[open]") && !typing)) draw();
  } catch (e) {
    if (e.status === 401) return;
    if (first) document.getElementById("main").replaceChildren(head(views()[view].title), h("div", { class: "error" }, e.message));
  }
  if (state.user && !views()[view].static) state.timer = setTimeout(refresh, REFRESH_MS);
}

function draw() {
  const v = views()[state.view];
  const main = document.getElementById("main");
  if (!main) return;
  // A field marked data-keep keeps focus and caret through the re-render that
  // runs every few seconds and on each keystroke of a live filter.
  const act = document.activeElement;
  const keep = act && act.dataset && act.dataset.keep;
  const caret = keep ? [act.selectionStart, act.selectionEnd] : null;
  // Views may return null/false for optional parts; never render them as text.
  main.replaceChildren(...[].concat(v.render(state.data[state.view])).filter((n) => n != null && n !== false));
  if (keep) {
    const el = main.querySelector(`[data-keep="${keep}"]`);
    if (el) {
      el.focus();
      if (caret[0] != null) el.setSelectionRange(caret[0], caret[1]);
    }
  }
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

// ---- building blocks --------------------------------------------------------
//
// Layout: a floating header bar, then an eyebrow line, segmented section tabs,
// a large title, and content in white rounded cards: stat cards for numbers
// and lists for things. Lists have avatar discs, no separators, a status
// badge and an arrow when the row opens a detail sheet.

const SVG_NS = "http://www.w3.org/2000/svg";

// One icon set: outline glyphs on a 24px grid, 2px rounded strokes.
const ICONS = {
  agents: "M4 5h16v11H4zM2 20h20",
  tokens: "M15 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0zM11 11v10M11 15h4M11 18h3",
  domains: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3c3.5 4 3.5 14 0 18M12 3c-3.5 4-3.5 14 0 18",
  link: "M10 14a4 4 0 0 0 6 0l3-3a4 4 0 0 0-6-6l-1 1M14 10a4 4 0 0 0-6 0l-3 3a4 4 0 0 0 6 6l1-1",
  terminal: "M4 6l6 6-6 6M12 18h8",
  server: "M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01",
  database: "M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3",
  eye: "M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
  clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2",
  tag: "M3 12V3h9l9 9-9 9zM7.5 7.5h.01",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0",
  arrow: "M7 17L17 7M8 7h9v9",
  search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM20 20l-4-4",
  sun: "M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4",
  moon: "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z",
  monitor: "M3 4h18v12H3zM8 21h8M12 16v5",
  logout: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9",
  book: "M2 4h7a3 3 0 0 1 3 3v14a2 2 0 0 0-2-2H2zM22 4h-7a3 3 0 0 0-3 3v14a2 2 0 0 1 2-2h8z",
  plus: "M12 5v14M5 12h14",
  trash: "M3 6h18M8 6V4h8v2M6 6l1 15h10l1-15",
  ban: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM5.6 5.6l12.8 12.8",
  copy: "M9 9h11v11H9zM5 15H4V4h11v1",
  check: "M5 12l5 5 9-10",
  replay: "M3 12a9 9 0 1 0 2.6-6.4L3 8M3 3v5h5",
  activity: "M3 12h4l3-8 4 16 3-8h4",
  alert: "M12 9v4M12 17h.01M10.3 3.9L2 18a2 2 0 0 0 1.7 3h16.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
  chart: "M3 3v18h18M8 17v-5M13 17V8M18 17v-9",
  home: "M3 11l9-8 9 8M5 9.5V20h5v-6h4v6h5V9.5",
  back: "M19 12H5M11 18l-6-6 6-6",
  mail: "M3 5h18v14H3zM3 6l9 7 9-7",
  shield: "M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z",
  left: "M15 18l-6-6 6-6",
  right: "M9 18l6-6-6-6",
  lock: "M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4",
};

function icon(name) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  const p = document.createElementNS(SVG_NS, "path");
  p.setAttribute("d", ICONS[name]);
  p.setAttribute("fill", "none");
  p.setAttribute("stroke", "currentColor");
  p.setAttribute("stroke-width", "2");
  p.setAttribute("stroke-linecap", "round");
  p.setAttribute("stroke-linejoin", "round");
  svg.append(p);
  return svg;
}

const initials = (s) => String(s || "?").replace(/[^a-z0-9]/gi, "").slice(0, 2).toUpperCase() || "?";
const avatar = (content) => h("span", { class: "avatar", "aria-hidden": "true" }, typeof content === "string" ? content : content);
const pad2 = (n) => String(n).padStart(2, "0");

function head(title, sub, ...actions) {
  return h(
    "header",
    { class: "head" },
    // sub: a sentence, or an array of nodes shown on one line (slug + badge)
    h("div", {}, h("h1", {}, title), sub ? (Array.isArray(sub) ? h("div", { class: "meta-line" }, sub) : h("p", {}, sub)) : null),
    actions.length ? h("div", { class: "row" }, actions) : null,
  );
}

// group(header, content, footer, meta): an uppercase section header with an
// optional count on the right, then a card (list rows) or stat grid.
function group(header, rows, footer, meta) {
  const all = [].concat(rows).filter(Boolean);
  const is = (el, c) => el.classList && el.classList.contains(c);
  // a button row or a pager sits below the card, never inside it
  const below = (el) => is(el, "actions") || is(el, "pager");
  const content = all.filter((el) => !below(el));
  const acts = all.filter(below);
  // stat grids and cards bring their own surface; rows go into a list card
  const standalone = content.length === 1 && (is(content[0], "stats") || is(content[0], "card"));
  return h(
    "section",
    { class: "group" },
    header || meta ? h("div", { class: "group-head" }, h("h2", { class: "group-header" }, header || ""), meta ? h("span", { class: "group-meta" }, meta) : null) : null,
    standalone ? content : content.length ? h("div", { class: "list" }, content) : null,
    acts,
    footer ? h("p", { class: "group-footer" }, footer) : null,
  );
}

// paginate(key, items, size): the slice for the current page of list `key`
// plus a pager. The page is kept in state.pages and clamped when the list
// shrinks (a filter, a disconnect), so it never points past the end.
function paginate(key, items, size) {
  const pages = Math.max(1, Math.ceil(items.length / size));
  const page = Math.min(Math.max(1, state.pages[key] || 1), pages);
  state.pages[key] = page;
  const from = (page - 1) * size;
  const slice = items.slice(from, from + size);
  if (pages === 1) return { slice, pager: null };
  // after a page change, bring the list's own section back into view (a page
  // can hold two paged lists, e.g. Active and Revoked tokens)
  const to = (p) => (e) => {
    const sections = () => [...document.querySelectorAll("#main .group")];
    const i = sections().indexOf(e.currentTarget.closest(".group"));
    state.pages[key] = p;
    draw();
    const g = sections()[i];
    if (g && g.getBoundingClientRect().top < 80) g.scrollIntoView({ block: "start", behavior: "smooth" });
  };
  const num = (p) =>
    h("button", { class: "page-btn", type: "button", onclick: to(p), "aria-label": "Page " + p, "aria-current": p === page ? "page" : null }, p);
  const arrow = (p, ic, label, off) =>
    h("button", { class: "page-btn", type: "button", onclick: to(p), disabled: off, "aria-label": label }, icon(ic));
  const pager = h(
    "nav",
    { class: "pager", "aria-label": "Pages" },
    h("span", { class: "pager-info" }, `Showing ${from + 1}–${from + slice.length} of ${items.length}`),
    h(
      "div",
      { class: "pager-pages" },
      arrow(page - 1, "left", "Previous page", page === 1),
      pageList(page, pages).map((p) => (p === "…" ? h("span", { class: "page-gap", "aria-hidden": "true" }, "…") : num(p))),
      arrow(page + 1, "right", "Next page", page === pages),
    ),
  );
  return { slice, pager };
}

// searchBox(key, placeholder): a live search field for list `key`. The text
// is kept in state.search[key]; typing filters at once, resets the list to
// page 1 and keeps the caret (data-keep) through re-renders.
function searchBox(key, placeholder) {
  const input = h("input", {
    type: "search",
    placeholder,
    "aria-label": placeholder,
    value: state.search[key] || "",
    "data-keep": "search-" + key,
    oninput: (e) => {
      state.search[key] = e.target.value.trim().toLowerCase();
      for (const k of Object.keys(state.pages)) if (k === key || k.startsWith(key + "-")) state.pages[k] = 1;
      draw();
    },
  });
  return h("label", { class: "pill-input" }, icon("search"), input);
}

// matches(key, ...fields): whether a row passes the search of list `key`.
const matches = (key, ...fields) => {
  const q = state.search[key];
  return !q || fields.filter(Boolean).join(" ").toLowerCase().includes(q);
};

// paged(key, items, row, emptyText): group content for a paged list: the
// rows of the current page plus its pager, or the empty line.
function paged(key, items, row, emptyText, size = ROWS_PER_PAGE) {
  if (!items.length) return empty(emptyText);
  const { slice, pager } = paginate(key, items, size);
  return [...slice.map(row), pager];
}

// pageList(5, 12) → [1, "…", 4, 5, 6, "…", 12]: the first, the last and the
// neighbours of the current page; a gap that would hide one page shows it.
function pageList(page, pages) {
  const want = new Set([1, pages, page - 1, page, page + 1].filter((p) => p >= 1 && p <= pages));
  const sorted = [...want].sort((a, b) => a - b);
  const out = [];
  sorted.forEach((p, i) => {
    const prev = sorted[i - 1];
    if (prev != null && p - prev === 2) out.push(prev + 1);
    else if (prev != null && p - prev > 2) out.push("…");
    out.push(p);
  });
  return out;
}

// actions(...buttons): a row of real buttons that share the width.
// button(label, onclick, {kind, icon, disabled, hint}): kind is "primary",
// "danger" or "" (gray).
const actions = (...btns) => h("div", { class: "actions" }, btns);
const button = (label, onclick, o = {}) =>
  h(
    "button",
    { class: "btn" + (o.kind ? " " + o.kind : ""), type: "button", onclick, disabled: !!o.disabled, title: o.hint },
    o.icon ? icon(o.icon) : null,
    label,
  );

// the card count picks the columns (.n3: three across), see style.css
const stats = (...cards) => h("div", { class: "stats n" + cards.length }, cards);
// stat(label, value, {onclick, tone, icon}): icon is an ICONS name shown in a
// neutral gray disc on the right of the label.
const stat = (label, value, opts = {}) =>
  h(
    opts.onclick ? "button" : "div",
    { class: "stat" + (opts.onclick ? " clickable" : ""), type: opts.onclick ? "button" : null, onclick: opts.onclick },
    h(
      "div",
      { class: "stat-top" },
      h("div", { class: "stat-label" }, label),
      opts.icon ? h("span", { class: "stat-icon", "aria-hidden": "true" }, icon(opts.icon)) : null,
    ),
    h("div", { class: "stat-value" + (opts.tone ? " " + opts.tone : "") }, value),
  );

// cell(opts): one list row.
//   avatar: "AB" | icon name   title, subtitle (monoSub)   value   trailing
//   onclick → arrow            tone: "action" | "destructive" | "disabled"
function cell(o) {
  const clickable = typeof o.onclick === "function";
  let lead = null;
  if (o.avatar) lead = avatar(ICONS[o.avatar] ? icon(o.avatar) : o.avatar);
  return h(
    clickable ? "button" : "div",
    { class: ["cell", o.tone, clickable && "clickable"].filter(Boolean).join(" "), type: clickable ? "button" : null, onclick: o.onclick, title: o.hint },
    lead,
    h(
      "span",
      { class: "cell-text" },
      h("span", { class: "cell-title" + (o.mono ? " mono" : "") }, o.title),
      o.subtitle ? h("span", { class: "cell-subtitle" + (o.monoSub ? " mono" : "") }, o.subtitle) : null,
    ),
    o.value != null ? h("span", { class: "cell-value" + (o.monoValue ? " mono" : "") }, o.value) : null,
    o.trailing || null,
    clickable && !o.tone ? h("span", { class: "go" }, icon("arrow")) : null,
  );
}

const empty = (text) => h("div", { class: "cell empty" }, h("span", { class: "cell-text" }, h("span", { class: "cell-subtitle" }, text)));

// sheet(title, build): a detail sheet with a Done button; a centered card on
// wide screens and a bottom sheet on phones (CSS).
function sheet(title, build, opts = {}) {
  // tabindex -1: initial focus goes to the sheet itself, not to its first
  // button, so no focus ring shows until the keyboard is used.
  const dlg = h("dialog", { class: "sheet" + (opts.wide ? " wide" : ""), "aria-label": title, tabindex: "-1" });
  const close = () => {
    dlg.close();
    dlg.remove();
    if (opts.onClose) opts.onClose();
  };
  dlg.append(
    h(
      "div",
      { class: "sheet-bar" },
      h("span", {}),
      h("h2", { class: "sheet-title" }, title),
      h("button", { class: "link-btn strong", type: "button", onclick: close }, "Done"),
    ),
    h("div", { class: "sheet-body" }, build(close)),
  );
  dlg.addEventListener("cancel", (e) => {
    e.preventDefault();
    close();
  });
  document.body.append(dlg);
  dlg.showModal();
  dlg.focus();
  return { dlg, close };
}

// confirmDialog({title, message, action, danger, password}, run): a small
// centered alert with Cancel and an action button, used instead of the
// browser's confirm(). With password set it also asks for the signed-in
// account's password and passes it to run. The action runs inside the
// dialog: the button shows a spinner, the dialog closes on success, and an
// error stays visible in the dialog.
function confirmDialog(o, run) {
  const dlg = h("dialog", { class: "alert", role: "alertdialog", "aria-label": o.title, tabindex: "-1" });
  const err = h("div", { class: "error", role: "alert", hidden: true });
  const pw = o.password ? h("input", { type: "password", autocomplete: "current-password", "aria-label": "Your password", placeholder: "Your password" }) : null;
  const cancel = h("button", { class: "btn", type: "button" }, "Cancel");
  const ok = h("button", { class: "btn " + (o.danger === false ? "primary" : "danger"), type: "button" }, o.action || "OK");
  const busy = (on) => {
    ok.disabled = cancel.disabled = on;
    if (on) ok.setAttribute("aria-busy", "true");
    else ok.removeAttribute("aria-busy");
  };
  const done = () => {
    dlg.close();
    dlg.remove();
  };
  cancel.addEventListener("click", done);
  dlg.addEventListener("cancel", (e) => {
    e.preventDefault();
    if (!ok.disabled) done();
  });
  ok.addEventListener("click", async () => {
    busy(true);
    err.hidden = true;
    try {
      await run(pw ? pw.value : undefined);
      done();
    } catch (e) {
      err.textContent = e.message;
      err.hidden = false;
      busy(false);
    }
  });
  if (pw) pw.addEventListener("keydown", (e) => e.key === "Enter" && ok.click());
  dlg.append(
    h("div", { class: "alert-body" }, h("h2", { class: "alert-title" }, o.title), o.message ? h("p", { class: "alert-message" }, o.message) : null, pw, err),
    h("div", { class: "alert-actions" }, cancel, ok),
  );
  document.body.append(dlg);
  dlg.showModal();
  if (pw) pw.focus();
  else dlg.focus();
}

// confirmThen(opts, fn): a click handler that asks first, runs fn, then
// reloads the current view.
const confirmThen = (o, fn) => () =>
  confirmDialog(o, async (value) => {
    await fn(value);
    refresh();
  });

const copyButton = (text, label = "Copy") =>
  h(
    "button",
    {
      class: "btn sm",
      type: "button",
      onclick: (e) => {
        e.stopPropagation();
        copy(text);
      },
    },
    label,
  );

// codeBlock(text, {label, copy, body}): monospace text in a filled box with
// its own Copy button. label is a line above it; copy is what the button
// copies (text by default, false hides the button); body caps the height for
// long payloads.
function codeBlock(text, o = {}) {
  const value = o.copy === undefined ? text : o.copy;
  const btn = value === false ? null : codeBlockCopy(value, o.label);
  return h(
    "div",
    { class: "snippet" },
    o.label ? h("div", { class: "snippet-label" }, o.label) : null,
    h("div", { class: "codeblock" + (btn ? " has-copy" : "") }, h("pre", { class: o.body ? "body" : null }, text), btn),
  );
}

// The small Copy chip used by code blocks; flips to "Copied" for a moment.
function codeBlockCopy(value, label) {
  const btn = h("button", {
    class: "code-copy",
    type: "button",
    "aria-label": label ? "Copy: " + label : "Copy",
    onclick: async (e) => {
      e.stopPropagation();
      if (!(await copy(value, true))) return;
      show("check", "Copied");
      clearTimeout(btn._h);
      btn._h = setTimeout(() => show("copy", "Copy"), 1600);
    },
  });
  const show = (name, text) => btn.replaceChildren(icon(name), h("span", {}, text));
  show("copy", "Copy");
  return btn;
}

// The three client commands, one block each: pasting them together would feed
// the third line into the token prompt of the second.
const clientSetup = () => [
  codeBlock(`mancar config set server ${location.origin}`, { label: "Point the client at this server" }),
  codeBlock("mancar config set token -", { label: "Save the token: paste it, press Enter, then Ctrl+D" }),
  codeBlock("mancar http 3000", { label: "Open a tunnel to localhost:3000" }),
];

const fmtNum = (n) => Number(n || 0).toLocaleString();
const fmtBytes = (n) => (n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB");
const plural = (n, one, many = one + "s") => `${fmtNum(n)} ${n === 1 ? one : many}`;
const total = (n) => `${pad2(n)} total`;

function statusBadge(code) {
  const cls = code >= 500 ? "danger" : code >= 400 ? "warn" : code >= 200 && code < 400 ? "ok" : "";
  return h("span", { class: "badge " + cls }, code || "—");
}

const onlineBadge = (label = "online") => h("span", { class: "badge ok" }, h("span", { class: "dot" }), label);

// client setup, opened from the header bar
function clientSheet() {
  sheet("Connect a client", (close) => [
    group("1 · Install", codeBlock("https://github.com/tinoimammp/mancar/releases/latest", { label: "Download mancar from the latest release" })),
    group("2 · Sign in", codeBlock(`mancar login ${location.origin}`, { label: "Opens this dashboard to allow your computer; the token is saved for you" })),
    group("3 · Open a tunnel", codeBlock("mancar http 3000", { label: "localhost:3000 gets a public address" })),
    group("No browser on that machine?", actions(button("Create a token by hand", () => (close(), newTokenDialog()), { icon: "tokens" })), "Then use mancar config set server and mancar config set token -."),
  ]);
}

// ---- overview ------------------------------------------------------------------

function renderOverview(o) {
  const tunnels = o.agents.flatMap((a) => a.tunnels.map((t) => ({ ...t, username: a.username })));
  return [
    head("Overview", [
      h("span", { class: "mono muted" }, o.base_domain),
      o.database === "ok" ? onlineBadge("healthy") : h("span", { class: "badge danger" }, "database " + o.database),
    ]),
    group("Live", stats(
      stat("Agents", fmtNum(o.gateway.sessions), { onclick: () => go("agents"), icon: "agents" }),
      stat("Tunnels", fmtNum(o.gateway.tunnels), { onclick: () => go("agents"), icon: "link" }),
      stat("Users", fmtNum(o.users), { onclick: () => go("users"), icon: "user" }),
      stat("Active tokens", fmtNum(o.active_tokens), { onclick: () => go("tokens"), icon: "tokens" }),
    )),
    group(
      "Traffic",
      stats(
        stat("Requests", fmtNum(o.traffic_24h.requests), { onclick: () => go("requests"), icon: "activity" }),
        stat("Server errors", fmtNum(o.traffic_24h.errors), { tone: o.traffic_24h.errors ? "danger" : null, icon: "alert" }),
        stat("All time", fmtNum(o.traffic_total.requests), { icon: "chart" }),
        stat("Domains", fmtNum(o.reserved_domains), { onclick: () => go("domains"), icon: "domains" }),
      ),
      "Server errors are 5xx responses and requests the local app never answered.",
      "last 24 hours",
    ),
    group(
      "Busiest tunnels",
      tunnels.length
        ? [
            ...tunnels
              .sort((x, y) => (y.active_connections || 0) - (x.active_connections || 0))
              .slice(0, OVERVIEW_TUNNELS)
              .map((t) => tunnelCell(t, `${t.username} · since ${ago(t.created_at).replace(" ago", "")}`)),
            tunnels.length > OVERVIEW_TUNNELS ? actions(button(`See all ${tunnels.length} tunnels`, () => go("agents"), { icon: "arrow" })) : null,
          ]
        : empty("No tunnels are online. Start one with: mancar http 3000"),
      null,
      total(tunnels.length),
    ),
    o.top_hosts.length
      ? group(
          "Busiest hostnames",
          o.top_hosts.map((x) =>
            cell({
              avatar: initials(x.hostname),
              title: x.hostname.split(".")[0],
              subtitle: x.hostname,
              monoSub: true,
              value: plural(x.usage.day.requests, "request"),
            }),
          ),
          null,
          "last 24 hours",
        )
      : null,
    group("Server", [
      cell({ avatar: "tag", title: "Version", value: o.version, monoValue: true }),
      cell({ avatar: "server", title: "Agent server URL", value: location.origin, monoValue: true, trailing: copyButton(location.origin) }),
      cell({ avatar: "terminal", title: "TCP ports", value: o.tcp_ports, monoValue: true }),
      cell({ avatar: "eye", title: "Request inspector", value: o.inspector }),
      cell({ avatar: "clock", title: "Uptime", value: dur(o.uptime_seconds) }),
    ]),
  ];
}

function tunnelCell(t, subtitle) {
  const isHTTP = t.proto === "http";
  return cell({
    avatar: t.private ? "lock" : isHTTP ? "link" : "terminal",
    title: t.public_url.replace(/^https?:\/\//, ""),
    mono: true,
    subtitle: [t.proto.toUpperCase(), t.private ? (t.shared_with ? `Private, with ${t.shared_with.join(", ")}` : "Private") : null, subtitle, t.active_connections ? `${t.active_connections} open` : null].filter(Boolean).join(" · "),
    trailing: h(
      "span",
      { class: "row" },
      isHTTP ? h("a", { class: "btn sm", href: t.public_url, target: "_blank", rel: "noopener noreferrer", onclick: (e) => e.stopPropagation() }, "Open") : null,
      copyButton(t.public_url),
    ),
  });
}

// ---- agents --------------------------------------------------------------------

// Agents scale to many: a search box and an All / Active / Idle filter on
// top, then one row per agent, busiest first, a page at a time. A row opens
// the agent's sheet with its tunnels and the Disconnect button.
const openConns = (a) => a.tunnels.reduce((n, t) => n + (t.active_connections || 0), 0);

function renderAgents(d) {
  const all = d.agents;
  const tunnelCount = all.reduce((n, a) => n + a.tunnels.length, 0);
  const connCount = all.reduce((n, a) => n + openConns(a), 0);
  const title = head("Agents & tunnels", `${plural(all.length, "agent")} · ${plural(tunnelCount, "tunnel")} · ${plural(connCount, "open connection")}`);
  if (!all.length) return [title, group(null, empty("No agents are connected. Start one with: mancar http 3000"))];

  const q = state.agentQuery;
  const haystack = (a) => [a.username, a.token_name, a.client, a.agent_version, ...a.tunnels.map((t) => t.public_url)].join(" ").toLowerCase();
  const byShow = { all: () => true, active: (a) => openConns(a) > 0, idle: (a) => openConns(a) === 0 };
  const inScope = all.filter((a) => !q || haystack(a).includes(q));
  const shown = inScope
    .filter(byShow[state.agentShow])
    .sort((x, y) => openConns(y) - openConns(x) || String(x.username).localeCompare(String(y.username)));

  const search = h("input", {
    type: "search",
    placeholder: "Search user, token, hostname or IP",
    "aria-label": "Search agents",
    value: q,
    "data-keep": "agent-search", // draw() keeps focus here across refreshes
    oninput: (e) => {
      state.agentQuery = e.target.value.trim().toLowerCase();
      state.pages.agents = 1;
      draw();
    },
  });
  const chip = (key, label) =>
    h(
      "button",
      {
        type: "button",
        class: "chip",
        "aria-pressed": String(state.agentShow === key),
        onclick: () => {
          state.agentShow = key;
          state.pages.agents = 1;
          draw();
        },
      },
      label,
      h("span", { class: "chip-count" }, inScope.filter(byShow[key]).length),
    );

  const { slice, pager } = paginate("agents", shown, AGENTS_PER_PAGE);

  return [
    title,
    group(
      null,
      h(
        "div",
        { class: "card toolbar" },
        h("label", { class: "pill-input" }, icon("search"), search),
        h("div", { class: "chips", role: "group", "aria-label": "Show" }, chip("all", "All"), chip("active", "Active"), chip("idle", "Idle")),
      ),
    ),
    group(
      state.agentShow === "active" ? "Active agents" : state.agentShow === "idle" ? "Idle agents" : "Agents",
      shown.length ? [...slice.map(agentRow), pager] : empty(q ? `No agent matches “${q}”.` : "No agent in this filter."),
      "Active means at least one open connection through its tunnels right now.",
      shown.length === all.length ? total(all.length) : `${shown.length} of ${all.length}`,
    ),
  ];
}

// tunnelNames: the public names of an agent's tunnels, short ("shop-api",
// ":20042"), the first two and then "+3 more".
function tunnelNames(a) {
  const names = a.tunnels.map((t) => (t.proto === "http" ? t.hostname.split(".")[0] : ":" + t.port));
  if (!names.length) return "no tunnels";
  return names.length > 2 ? `${names.slice(0, 2).join(", ")} +${names.length - 2} more` : names.join(", ");
}

// agentRow: one line per agent, like Users and Tokens; details open in a sheet.
function agentRow(a) {
  const n = openConns(a);
  return cell({
    avatar: initials(a.username),
    title: `${a.username || "?"} · ${a.token_name || a.token_id.slice(0, 8)}`,
    subtitle: `${tunnelNames(a)} · since ${ago(a.connected_at).replace(" ago", "")}`,
    trailing: n ? h("span", { class: "badge ok" }, h("span", { class: "dot" }), `${n} open`) : h("span", { class: "badge" }, "idle"),
    onclick: () => agentSheet(a),
  });
}

function agentSheet(a) {
  const n = openConns(a);
  sheet(`${a.username} · ${a.token_name || a.token_id.slice(0, 8)}`, (close) => [
    group(null, stats(
      stat("Tunnels", fmtNum(a.tunnels.length)),
      stat("Open now", fmtNum(n)),
      stat("Connected", ago(a.connected_at).replace(" ago", "")),
    )),
    group(
      "Tunnels",
      a.tunnels.length ? a.tunnels.map((t) => tunnelCell(t, "since " + ago(t.created_at).replace(" ago", ""))) : empty("No tunnels open on this agent."),
      null,
      total(a.tunnels.length),
    ),
    group("Agent", [
      cell({ title: "User", value: a.username }),
      cell({ title: "Token", value: a.token_name || a.token_id }),
      cell({ title: "Client IP", value: a.client || "unknown", monoValue: true }),
      cell({ title: "mancar version", value: a.agent_version || "?", monoValue: true }),
      cell({ title: "Connected", value: ago(a.connected_at), hint: fmtDate(a.connected_at) }),
    ]),
    group(null, actions(
      button("Disconnect agent", confirmThen({
        title: `Disconnect ${a.username}'s agent?`,
        message: "Its tunnels go offline. The agent reconnects on its own unless its token is revoked.",
        action: "Disconnect",
      }, async () => {
        await api("POST", `/agents/${encodeURIComponent(a.id)}/disconnect`);
        close();
      }), { kind: "danger", icon: "ban" }),
    ), "The agent reconnects on its own unless its token is revoked."),
  ]);
}

// ---- tokens --------------------------------------------------------------------

function tokenStatus(t) {
  if (t.revoked_at) return h("span", { class: "badge danger" }, "revoked");
  if (t.connected_agents) return onlineBadge();
  return h("span", { class: "badge" }, "active");
}

function renderTokens(d) {
  const hit = (t) => matches("tokens", t.name, t.username, t.id);
  const active = d.tokens.filter((t) => !t.revoked_at && hit(t));
  const revoked = d.tokens.filter((t) => t.revoked_at && hit(t));
  const q = state.search.tokens;
  const row = (t) =>
    cell({
      avatar: initials(t.username),
      title: t.name,
      subtitle: `${t.username} · last used ${ago(t.last_used_at)}`,
      trailing: tokenStatus(t),
      onclick: () => tokenSheet(t),
    });
  const activeCount = d.tokens.filter((t) => !t.revoked_at).length;
  // a user has a token limit and must confirm their email first
  const own = state.role === "user";
  const blocked = own && (!d.email_verified ? "Confirm your email to create tokens." : d.limit != null && activeCount >= d.limit ? `You have ${d.limit} active tokens, the most allowed. Revoke one first.` : "");
  return [
    head(
      "Tokens",
      own ? (d.limit == null ? plural(activeCount, "active token") : `${activeCount} of ${d.limit} active tokens used`) : `${activeCount} active of ${d.tokens.length} tokens`,
      button("Create token", () => newTokenDialog(), { kind: "primary", icon: "plus", disabled: !!blocked, hint: blocked || null }),
    ),
    blocked ? h("div", { class: "notice" }, blocked) : null,
    own ? null : group(null, h("div", { class: "card toolbar" }, searchBox("tokens", "Search token, user or ID"))),
    group("Active", paged("tokens-active", active, row, q ? `No active token matches “${q}”.` : "No active tokens yet."), null, total(active.length)),
    revoked.length ? group("Revoked", paged("tokens-revoked", revoked, row, ""), null, total(revoked.length)) : null,
  ];
}

// tokenForm(presetUser, onCreated): the new-token form (user, label, create),
// shown in the New token sheet; onCreated gets the API reply with the secret.
function tokenForm(presetUser, onCreated) {
  const err = h("div", { class: "error", role: "alert", hidden: true });
  const user = h("input", {
    name: "user", required: true, autocomplete: "off", spellcheck: "false", value: presetUser || "",
    placeholder: "alice", pattern: "[a-z0-9][a-z0-9._\\-]{0,63}",
  });
  const name = h("input", { name: "name", autocomplete: "off", placeholder: "macbook" });
  const btn = h("button", { class: "btn primary", type: "submit" }, icon("plus"), "Create token");
  const form = h(
    "form",
    {
      class: "card form stacked",
      onsubmit: async (ev) => {
        ev.preventDefault();
        btn.disabled = true;
        btn.setAttribute("aria-busy", "true");
        err.hidden = true;
        try {
          const r = await api("POST", "/tokens", { user: user.value.trim().toLowerCase(), name: name.value.trim() });
          onCreated(r);
        } catch (e) {
          err.textContent = e.message;
          err.hidden = false;
        } finally {
          btn.disabled = false;
          btn.removeAttribute("aria-busy");
        }
      },
    },
    err,
    h(
      "div",
      { class: "field-row" },
      // a user creates tokens for themselves only: no user field
      state.role === "user" ? null : h("label", { class: "field" }, "User", h("span", { class: "pill-input" }, icon("user"), user)),
      h("label", { class: "field" }, "Label", h("span", { class: "pill-input" }, icon("agents"), name)),
      btn,
    ),
  );
  return form;
}

// newTokenDialog(presetUser): the "New token" sheet. On success it is
// replaced by the "Token created" sheet that shows the secret once.
function newTokenDialog(presetUser) {
  const own = state.role === "user";
  if (own) presetUser = state.user;
  const { dlg, close } = sheet(presetUser && !own ? "New token for " + presetUser : "New token", () => [
    group(null, tokenForm(presetUser, (r) => {
      close();
      sheet("Token created", () => tokenCreated(r), { onClose: () => refresh() });
    }), "The secret is shown once, right after it is created."),
  ]);
  // start typing at once: the user field, or the label when the user is set
  dlg.querySelector(presetUser ? 'input[name="name"]' : 'input[name="user"]').focus();
}

function tokenSheet(t) {
  sheet(t.name, (close) => [
    // who and what at a glance: owner, label, status
    group(null, h(
      "div",
      { class: "card profile" },
      avatar(icon("tokens")),
      h("div", { class: "cell-text" }, h("span", { class: "profile-title" }, t.name), h("span", { class: "cell-subtitle" }, `Token of ${t.username}`)),
      tokenStatus(t),
    )),
    group(null, stats(
      stat("Agents now", fmtNum(t.connected_agents)),
      stat("Last used", t.last_used_at ? ago(t.last_used_at).replace(" ago", "") : "never"),
      stat("Age", ago(t.created_at).replace(" ago", "")),
    )),
    group("Details", [
      cell({ avatar: "user", title: "User", value: t.username }),
      cell({ avatar: "clock", title: "Created", value: fmtDate(t.created_at) }),
      cell({ avatar: "activity", title: "Last used", value: t.last_used_at ? fmtDate(t.last_used_at) : "never" }),
      t.revoked_at ? cell({ avatar: "ban", title: "Revoked", value: fmtDate(t.revoked_at), tone: "destructive" }) : null,
    ]),
    group("Token ID", codeBlock(t.id), "The ID identifies the token in logs. It is not the secret, which is never stored."),
    t.revoked_at
      ? null
      : group(
          null,
          actions(button("Revoke token", confirmThen({
              title: `Revoke token “${t.name}”?`,
              message: `Agents of ${t.username} using it are disconnected now and cannot reconnect.`,
              action: "Revoke",
            }, async () => {
              const r = await api("POST", `/tokens/${encodeURIComponent(t.id)}/revoke`);
              close();
              toast(`Token revoked${r.disconnected_agents ? `, ${r.disconnected_agents} agent(s) disconnected` : ""}`);
            }), { kind: "danger", icon: "ban" })),
          "Agents using it are disconnected at once and cannot reconnect.",
        ),
  ]);
}

function tokenCreated(r) {
  return [
    h("div", { class: "notice" }, "Copy it now. It is not stored and will never be shown again."),
    group(`Token for ${r.user} · ${r.name}`, codeBlock(r.token)),
    group("Set up the client", clientSetup(), "Run them one at a time, in this order."),
  ];
}

// ---- users ---------------------------------------------------------------------

// Accounts: role, status and what they own. Filters: role or status.
const USER_FILTERS = {
  all: ["All", () => true],
  admin: ["Admins", (u) => u.role === "admin"],
  user: ["Users", (u) => u.role === "user"],
  unverified: ["Unconfirmed", (u) => u.status === "unverified"],
  disabled: ["Disabled", (u) => u.status === "disabled"],
};

function userStatus(u) {
  if (u.status === "disabled") return h("span", { class: "badge danger" }, "disabled");
  if (u.status === "unverified") return h("span", { class: "badge warn" }, "unconfirmed");
  if (u.connected_agents) return onlineBadge(`${u.connected_agents} online`);
  return h("span", { class: "badge" }, "offline");
}

function renderUsers(d) {
  state.userShow = state.userShow || "all";
  const inScope = d.users.filter((u) => matches("users", u.username, u.email));
  const users = inScope.filter(USER_FILTERS[state.userShow][1]);
  const chip = (key) =>
    h(
      "button",
      {
        type: "button", class: "chip", "aria-pressed": String(state.userShow === key),
        onclick: () => {
          state.userShow = key;
          state.pages.users = 1;
          draw();
        },
      },
      USER_FILTERS[key][0],
      h("span", { class: "chip-count" }, inScope.filter(USER_FILTERS[key][1]).length),
    );
  const online = d.users.filter((u) => u.connected_agents).length;
  return [
    head(
      "Users",
      `${online} online of ${plural(d.users.length, "account")} · ${plural(d.users.filter((u) => u.role === "admin").length, "admin")}`,
      button("Add user", () => createUserDialog(), { kind: "primary", icon: "plus" }),
    ),
    group(
      null,
      h("div", { class: "card toolbar" }, searchBox("users", "Search username or email"), h("div", { class: "chips", role: "group", "aria-label": "Show" }, Object.keys(USER_FILTERS).map(chip))),
    ),
    group(
      USER_FILTERS[state.userShow][0],
      paged(
        "users",
        users,
        (u) =>
          cell({
            avatar: initials(u.username),
            title: u.role === "admin" ? [u.username, h("span", { class: "role-tag" }, "admin")] : u.username,
            subtitle: [u.email || "no email", plural(u.active_tokens, "token"), `${fmtNum(u.usage.day.requests)} requests today`].join(" · "),
            trailing: userStatus(u),
            onclick: () => userSheet(u, d),
          }),
        state.search.users ? `No account matches “${state.search.users}”.` : "No account in this filter.",
      ),
      "Admins manage the whole server; users see only their own tunnels, tokens and requests.",
      users.length === d.users.length ? total(d.users.length) : `${users.length} of ${d.users.length}`,
    ),
  ];
}

const limitLabel = (n) => (n == null ? "No limit" : fmtNum(n));

// userSheet(u, d): one account, with every admin action. Actions that
// change it reload the list and close the sheet.
function userSheet(u, d) {
  const self = u.username === state.user;
  const patch = (body) => api("PATCH", `/users/${encodeURIComponent(u.id)}`, body);
  sheet(u.username, (close) => {
    const after = (msg) => () => {
      close();
      if (msg) toast(msg);
    };
    const run = (o, fn, msg) => confirmThen(o, async (v) => {
      await fn(v);
      after(msg)();
    });
    return [
      group(null, h(
        "div",
        { class: "card profile" },
        avatar(initials(u.username)),
        h("div", { class: "cell-text" }, h("span", { class: "profile-title" }, u.username), h("span", { class: "cell-subtitle" }, u.email || "No email address")),
        h("span", { class: "badge" + (u.role === "admin" ? " ok" : "") }, u.role),
      )),
      group("Traffic", stats(stat("24 hours", fmtNum(u.usage.day.requests)), stat("7 days", fmtNum(u.usage.week.requests)), stat("All time", fmtNum(u.usage.total.requests)))),
      group("Account", [
        cell({ avatar: "eye", title: "Status", trailing: userStatus(u) }),
        cell({ avatar: "mail", title: "Email", value: u.email ? (u.email_verified ? "confirmed" : "not confirmed") : "none" }),
        cell({ avatar: "clock", title: "Last sign in", value: u.last_login_at ? ago(u.last_login_at) : "never", hint: fmtDate(u.last_login_at) }),
        cell({ avatar: "user", title: "Joined", value: ago(u.created_at) + (u.signed_up ? " · signed up" : ""), hint: fmtDate(u.created_at) }),
        u.has_password ? null : cell({ avatar: "ban", title: "Cannot sign in", value: "no password yet", tone: "disabled" }),
      ]),
      group("Owns", [
        cell({ avatar: "agents", title: "Connected agents", value: fmtNum(u.connected_agents) }),
        cell({ avatar: "tokens", title: "Active tokens", value: `${fmtNum(u.active_tokens)} / ${limitLabel(u.max_tokens)}` }),
        cell({ avatar: "tag", title: "Custom subdomains", value: `${fmtNum(u.custom_domains)} / ${limitLabel(u.max_custom_domains)}` }),
      ], u.role === "admin" ? "Limits do not apply to admins." : null),
      group("Manage", actions(
        button("New token", () => (close(), newTokenDialog(u.username)), { icon: "plus" }),
        button("Limits", () => (close(), limitsDialog(u)), { icon: "tag" }),
        button("Reset password", () => (close(), resetPasswordDialog(u, d.email_enabled)), { icon: "shield" }),
        u.email && !u.email_verified
          ? button("Mark email confirmed", run({ title: `Confirm ${u.email}?`, message: "Only do this if you know the address belongs to them.", action: "Confirm", danger: false },
              () => patch({ email_verified: true }), "Email confirmed"), { icon: "check" })
          : null,
        u.email && !u.email_verified && d.email_enabled
          ? button("Send confirmation again", run({ title: `Email ${u.email} a new link?`, action: "Send", danger: false },
              () => api("POST", `/users/${encodeURIComponent(u.id)}/resend-verification`), "Link sent"), { icon: "mail" })
          : null,
      )),
      self
        ? group(null, null, "This is your account: change your own role or status from another admin's account.")
        : group("Access", actions(
            u.role === "admin"
              ? button("Make user", run({ title: `Make ${u.username} a user?`, message: "They keep their tokens and tunnels but lose access to the whole server at once.", action: "Make user" },
                  () => patch({ role: "user" }), `${u.username} is now a user`), { icon: "user" })
              : button("Make admin", run({ title: `Make ${u.username} an admin?`, message: "They will see and manage everything on this server. Enter your password to confirm.", action: "Make admin", danger: false, password: true },
                  (pw) => patch({ role: "admin", confirm_password: pw }), `${u.username} is now an admin`), { kind: "primary", icon: "shield" }),
            u.status === "disabled"
              ? button("Enable", run({ title: `Enable ${u.username}?`, message: "They can sign in again and their tokens work again.", action: "Enable", danger: false },
                  () => patch({ disabled: false }), "Enabled"), { icon: "check" })
              : button("Disable", run({ title: `Disable ${u.username}?`, message: "They are signed out, their tokens are refused and their agents disconnected. Nothing is deleted; enable them to undo.", action: "Disable" },
                  () => patch({ disabled: true }), "Disabled"), { kind: "danger", icon: "ban" }),
            button("Revoke all tokens", run({ title: `Revoke every token of ${u.username}?`, message: "Their agents disconnect and cannot reconnect with these tokens. This cannot be undone.", action: "Revoke all" },
              async () => {
                const r = await api("POST", `/users/${encodeURIComponent(u.id)}/revoke-tokens`);
                toast(`${plural(r.revoked, "token")} revoked`);
              }), { kind: "danger", icon: "tokens" }),
            button("Delete account", run({
              title: `Delete ${u.username}?`,
              message: "Their tokens, reserved names, captured requests and statistics are deleted and their agents disconnected. This cannot be undone.",
              action: "Delete account",
            }, () => api("DELETE", `/users/${encodeURIComponent(u.id)}`), "Account deleted"), { kind: "danger", icon: "trash" }),
          ), "The server always keeps at least one active admin."),
    ];
  });
}

// formSheet(title, fields, label, submit): a sheet with a stacked form.
function formSheet(title, note, fields, label, submit) {
  const { dlg, close } = sheet(title, (close) => [
    group(null, (() => {
      const f = busyForm(fields, label, () => submit(close));
      f.classList.add("card");
      return f;
    })(), note),
  ]);
  const first = dlg.querySelector("input, select");
  if (first) first.focus();
}

function createUserDialog() {
  const user = h("input", { name: "username", required: true, autocomplete: "off", spellcheck: "false", pattern: "[a-z0-9][a-z0-9._\\-]{0,63}", placeholder: "rina" });
  const email = h("input", { name: "email", type: "email", autocomplete: "off", placeholder: "rina@example.com (optional)" });
  const pass = passwordInput("new-password");
  const role = h("select", { name: "role" }, h("option", { value: "user" }, "User: their own tunnels only"), h("option", { value: "admin" }, "Admin: the whole server"));
  formSheet(
    "Add user",
    "The email is treated as confirmed. Share the password with them safely; they can change it under Account.",
    [h("label", {}, "Username", user), h("label", {}, "Email", email), passwordLabel("Password", pass), h("label", {}, "Role", role)],
    "Add user",
    async (close) => {
      await api("POST", "/users", { username: user.value.trim().toLowerCase(), email: email.value.trim(), password: pass.value, role: role.value });
      close();
      toast(`${user.value.trim().toLowerCase()} added`);
      refresh();
    },
  );
}

function limitsDialog(u) {
  const field = (name, value) => h("input", { name, type: "number", min: 0, max: 10000, step: 1, inputmode: "numeric", value: value == null ? "" : String(value), placeholder: "No limit" });
  const tok = field("max_tokens", u.max_tokens);
  const dom = field("max_custom_domains", u.max_custom_domains);
  const val = (i) => (i.value.trim() === "" ? null : Number(i.value));
  formSheet(
    `Limits for ${u.username}`,
    "Leave a field empty for no limit. Random subdomains are never limited; admins ignore these limits.",
    [h("label", {}, "Active tokens", tok), h("label", {}, "Custom subdomains", dom)],
    "Save limits",
    async (close) => {
      await api("PATCH", `/users/${encodeURIComponent(u.id)}`, { max_tokens: val(tok), max_custom_domains: val(dom) });
      close();
      toast("Limits saved");
      refresh();
    },
  );
}

function resetPasswordDialog(u, emailEnabled) {
  const viaEmail = emailEnabled && u.email;
  sheet(`Reset password of ${u.username}`, (close) => [
    viaEmail
      ? group("By email", actions(button("Email a reset link", confirmThen({ title: `Email a reset link to ${u.email}?`, message: "They choose a new password themselves. The link works for 1 hour.", action: "Send", danger: false },
          async () => {
            await api("POST", `/users/${encodeURIComponent(u.id)}/reset-password`, { mode: "email" });
            close();
            toast("Reset link sent");
          }), { kind: "primary", icon: "mail" })), "Recommended: you never see their password.")
      : null,
    group("Temporary password", actions(button("Set a temporary password", confirmThen({ title: `Replace the password of ${u.username}?`, message: "Their sessions end at once. You will see the new password once.", action: "Replace" },
      async () => {
        const r = await api("POST", `/users/${encodeURIComponent(u.id)}/reset-password`, { mode: "temporary" });
        close();
        sheet("Temporary password", () => [
          h("div", { class: "notice" }, "Copy it now. It is not stored and will never be shown again."),
          group(`New password for ${u.username}`, codeBlock(r.password), "Ask them to change it under Account after signing in."),
        ]);
      }), { icon: "shield" })), viaEmail ? null : "This account has no email, or the server cannot send email (SMTP_URL)."),
  ]);
}

// ---- activity (audit log) -------------------------------------------------

const AUDIT_LABELS = {
  "user.create": "added account", "user.role": "changed role", "user.disable": "disabled", "user.enable": "enabled",
  "user.delete": "deleted account", "user.email": "changed email", "user.verify": "confirmed email", "user.limits": "changed limits",
  "user.reset_password": "reset password", "user.revoke_tokens": "revoked all tokens", "user.resend_verification": "sent confirmation",
  "token.create": "created token", "token.revoke": "revoked token", "agent.disconnect": "disconnected agent",
  "domain.release": "released hostname", "request.replay": "replayed request", "requests.clear": "cleared requests",
  "account.password": "changed own password", "account.delete": "deleted own account",
};

function renderActivity(d) {
  const hit = (e) => matches("activity", e.actor, e.action, e.target, e.detail);
  const list = d.entries.filter(hit);
  return [
    head("Activity", "What was done on this server, newest first. Kept for a year."),
    group(null, h("div", { class: "card toolbar" }, searchBox("activity", "Search who, what or target"))),
    group(
      "Recent",
      paged(
        "activity",
        list,
        (e) =>
          cell({
            avatar: initials(e.actor),
            title: [h("strong", {}, e.actor), " " + (AUDIT_LABELS[e.action] || e.action), ...(e.target ? [" · ", h("span", { class: "mono" }, e.target)] : [])],
            subtitle: [new Date(e.at).toLocaleString(), e.detail].filter(Boolean).join(" · "),
          }),
        state.search.activity ? `Nothing matches “${state.search.activity}”.` : "Nothing yet.",
        25,
      ),
      null,
      total(list.length),
    ),
  ];
}

// ---- domains -------------------------------------------------------------------

function renderDomains(d) {
  const hit = (x) => matches("domains", x.hostname, x.username, x.kind);
  const online = d.domains.filter((x) => x.online && hit(x));
  const held = d.domains.filter((x) => !x.online && hit(x));
  const q = state.search.domains;
  const row = (x) =>
    cell({
      avatar: initials(x.hostname),
      title: x.hostname.split(".")[0],
      subtitle: `${x.hostname} · ${x.username} · ${x.kind}`,
      trailing: x.online ? onlineBadge() : h("span", { class: "badge warn", title: fmtDate(x.hold_until) }, "frees " + ago(x.hold_until)),
      onclick: x.online ? undefined : () => domainSheet(x),
    });
  return [
    head("Domains", `${d.domains.filter((x) => x.online).length} in use of ${plural(d.domains.length, "reserved name")}`),
    group(null, h("div", { class: "card toolbar" }, searchBox("domains", "Search hostname or owner"))),
    group("In use", paged("domains-online", online, row, q ? `No hostname in use matches “${q}”.` : "No hostname is in use."), null, total(online.length)),
    group("Held", paged("domains-held", held, row, q ? `No held hostname matches “${q}”.` : "No hostname is held."), "A disconnected name stays reserved for its owner: 24 hours for custom names, 5 minutes for random ones.", total(held.length)),
  ];
}

function domainSheet(x) {
  sheet(x.hostname, (close) => [
    group(null, [
      cell({ title: "Owner", value: x.username }),
      cell({ title: "Kind", value: x.kind }),
      cell({ title: "Held until", value: fmtDate(x.hold_until) }),
      cell({ title: "Requests, all time", value: fmtNum(x.usage.total.requests) }),
    ]),
    group(
      null,
      actions(button("Release hostname", confirmThen({
        title: `Release ${x.hostname.split(".")[0]}?`,
        message: `${x.hostname} is no longer held for ${x.username}. Anyone can claim it afterwards.`,
        action: "Release",
      }, async () => {
        await api("DELETE", `/domains/${encodeURIComponent(x.hostname)}`);
        close();
      }), { kind: "danger", icon: "trash" })),
      "Anyone can claim the name afterwards.",
    ),
  ]);
}

// ---- requests (inspector) ----------------------------------------------------

async function loadRequests() {
  try {
    const q = new URLSearchParams({ limit: String(REQUESTS_LOADED) });
    if (state.reqHost) q.set("host", state.reqHost);
    return await api("GET", "/requests?" + q);
  } catch (e) {
    if (e.code === "inspector_disabled") return { disabled: e.message };
    throw e;
  }
}

function renderRequests(d) {
  if (d.disabled) {
    return [head("Requests"), group(null, empty(d.disabled), "Set INSPECT=on and ENCRYPTION_KEY in .env, then restart mancard.")];
  }
  const filter = h("input", {
    type: "search",
    placeholder: "Filter by hostname",
    value: state.reqHost,
    "aria-label": "Filter by hostname",
    onchange: (e) => {
      state.reqHost = e.target.value.trim().toLowerCase();
      state.pages.requests = 1;
      refresh(true);
    },
  });
  const { slice, pager } = paginate("requests", d.requests, REQUESTS_PER_PAGE);
  return [
    head(
      "Requests",
      `Stored encrypted, deleted after ${dur(d.retention_seconds)}.`,
      h(
        "button",
        {
          class: "btn outline",
          onclick: confirmThen({
            title: state.reqHost ? "Clear requests for this host?" : "Clear all captured requests?",
            message: state.reqHost
              ? `Every captured request for ${state.reqHost} is deleted. Usage statistics are kept.`
              : "Every captured request is deleted. Usage statistics are kept.",
            action: "Clear",
          }, () =>
            api("DELETE", "/requests" + (state.reqHost ? "?host=" + encodeURIComponent(state.reqHost) : "")),
          ),
        },
        icon("trash"),
        "Clear",
      ),
    ),
    group(null, h("label", { class: "card form" }, h("span", { class: "pill-input" }, icon("search"), filter))),
    d.undecryptable ? h("div", { class: "notice" }, `${d.undecryptable} request(s) cannot be decrypted (ENCRYPTION_KEY changed?) and are hidden.`) : null,
    group(
      "Latest",
      d.requests.length
        ? [
            ...slice.map((r) =>
              cell({
                avatar: r.method.slice(0, 4),
                title: r.uri,
                mono: true,
                subtitle: `${r.hostname} · ${new Date(r.time).toLocaleTimeString()} · ${r.duration_ms} ms · ${fmtBytes(r.response_size)}${r.replay ? " · replay" : ""}`,
                trailing: statusBadge(r.status),
                onclick: () => requestDialog(r.id),
              }),
            ),
            pager,
          ]
        : empty("No requests captured yet. Open one of your tunnel URLs."),
      d.requests.length >= REQUESTS_LOADED ? `Showing the latest ${REQUESTS_LOADED}. Filter by hostname to look further back.` : null,
      total(d.requests.length),
    ),
  ];
}

function shellQuote(s) {
  return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

const SKIP_CURL = new Set(["host", "content-length", "connection", "accept-encoding", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-real-ip"]);

function toCurl(r) {
  const parts = ["curl", "-X", r.method, shellQuote("https://" + r.hostname + r.uri)];
  for (const [k, vs] of Object.entries(r.request_headers || {})) {
    if (SKIP_CURL.has(k.toLowerCase())) continue;
    for (const v of vs) parts.push("-H", shellQuote(k + ": " + v));
  }
  const b = r.request_body;
  if (b && b.size > 0 && b.text != null && !b.truncated) parts.push("--data-binary", shellQuote(b.text));
  return parts.join(" ");
}

// Headers as a compact two-column table (name, value), like browser dev
// tools: one short line per header instead of a tall list row each.
function headerTable(hdrs) {
  const entries = Object.entries(hdrs || {}).sort(([a], [b]) => a.localeCompare(b));
  if (!entries.length) return empty("No headers.");
  const pairs = entries.flatMap(([k, vs]) => vs.map((v) => [k, v]));
  return h(
    "div",
    { class: "card headers" },
    h("div", { class: "headers-bar" }, h("span", { class: "group-meta" }, plural(pairs.length, "header")), codeBlockCopy(pairs.map(([k, v]) => `${k}: ${v}`).join("\n"))),
    h("dl", { class: "kv" }, pairs.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])),
  );
}

function bodyGroup(title, b) {
  if (!b || b.size === 0) return group(title, empty("Empty body."));
  let text = b.text;
  if (text != null) {
    try {
      text = JSON.stringify(JSON.parse(text), null, 2);
    } catch {
      /* not JSON: show as is */
    }
  }
  const notes = [fmtBytes(b.size)];
  if (b.decoded) notes.push("decoded from " + b.decoded);
  if (b.truncated) notes.push(`only the first ${fmtBytes(b.kept)} were kept`);
  return group(title, text != null ? codeBlock(text, { body: true }) : h("div", { class: "cell" }, h("span", { class: "cell-subtitle" }, "Binary content, not shown.")), notes.join(" · "));
}

async function requestDialog(id) {
  let r;
  try {
    r = await api("GET", "/requests/" + encodeURIComponent(id));
  } catch (e) {
    toast(e.message);
    return;
  }
  sheet(
    `${r.method} ${r.uri}`,
    (close) => [
      group(null, [
        cell({ title: "Status", trailing: statusBadge(r.status) }),
        cell({ title: "Host", value: r.hostname, monoValue: true }),
        cell({ title: "Time", value: fmtDate(r.time) }),
        cell({ title: "Duration", value: r.duration_ms + " ms" }),
        cell({ title: "Client", value: r.client, monoValue: true }),
        r.replay ? cell({ title: "Replayed from the dashboard", value: "yes" }) : null,
      ]),
      group(
        null,
        actions(
          button("Replay request", r.replayable
            ? confirmThen({
                title: `Replay ${r.method} ${r.uri}?`,
                message: `The request is sent to ${r.hostname} again and the application processes it a second time.`,
                action: "Replay",
                danger: false,
              }, async () => {
                const res = await api("POST", `/requests/${encodeURIComponent(r.id)}/replay`);
                toast(`Replayed: ${res.status} in ${res.duration_ms} ms`);
                close();
              })
            : undefined, { kind: "primary", icon: "replay", disabled: !r.replayable, hint: r.replay_blocker || "Send this request to the tunnel again" }),
        ),
        r.replay_blocker ? "Cannot replay: " + r.replay_blocker : "Replay sends the request again: the application processes it a second time.",
      ),
      group("As curl", codeBlock(toCurl(r), { body: true })),
      group("Request headers", headerTable(r.request_headers)),
      bodyGroup("Request body", r.request_body),
      group("Response headers", headerTable(r.response_headers)),
      bodyGroup("Response body", r.response_body),
    ],
    { wide: true },
  );
}

// ---- user pages (role "user") --------------------------------------------
//
// A self-registered user sees their own tunnels, subdomains, tokens and
// requests, plus their account. Data comes from /api/v1/me.

// verifyBanner: shown until the email address is confirmed; tokens cannot be
// created before that.
function verifyBanner(email) {
  const resend = button("Send again", async () => {
    resend.disabled = true;
    try {
      await api("POST", own("/account/verify/resend"));
      toast("Sent. Check your inbox and spam folder.");
    } catch (e) {
      toast(e.message);
    }
    setTimeout(() => (resend.disabled = false), 30000);
  }, { kind: "sm" });
  return h(
    "div",
    { class: "banner" },
    h("span", { class: "banner-icon", "aria-hidden": "true" }, icon("mail")),
    h("div", { class: "cell-text" }, h("span", { class: "cell-title" }, "Confirm your email"), h("span", { class: "cell-subtitle" }, `We sent a link to ${email}. You can create tokens once it is confirmed.`)),
    resend,
  );
}

// "2 / 3", or just "2" when there is no limit (null)
const limitText = (used, max) => (max == null ? fmtNum(used) : `${fmtNum(used)} / ${fmtNum(max)}`);

function renderMyOverview(o) {
  const live = o.tunnels.slice().sort((x, y) => (y.active_connections || 0) - (x.active_connections || 0));
  return [
    head(`Hi, ${state.user}`, [h("span", { class: "mono muted" }, o.base_domain), live.length ? onlineBadge(`${live.length} online`) : h("span", { class: "badge" }, "offline")]),
    o.email_verified ? null : verifyBanner(o.email),
    group("Today", stats(
      stat("Tunnels online", limitText(live.length, o.limits.tunnels), { icon: "link", onclick: () => go("tunnels") }),
      stat("Requests", fmtNum(o.usage.day.requests), { icon: "activity", onclick: () => go("requests") }),
      stat("Server errors", fmtNum(o.usage.day.errors), { icon: "alert", tone: o.usage.day.errors ? "danger" : null }),
      stat("All time", fmtNum(o.usage.total.requests), { icon: "chart" }),
    ), "Server errors are 5xx responses and requests your app never answered.", "last 24 hours"),
    live.length
      ? group(
          "Online now",
          [
            ...live.slice(0, OVERVIEW_TUNNELS).map((t) => tunnelCell(t, "since " + ago(t.created_at).replace(" ago", ""))),
            live.length > OVERVIEW_TUNNELS ? actions(button(`See all ${live.length}`, () => go("tunnels"), { icon: "arrow" })) : null,
          ],
          null,
          total(live.length),
        )
      : group("Start a tunnel", clientSetup(), "Install mancar first: the Connect a client button at the top has the download link."),
  ];
}

function renderMyTunnels(o) {
  const custom = o.domains.filter((x) => x.kind === "custom").length;
  const hit = (x) => matches("my-domains", x.hostname, x.kind);
  const domains = o.domains.filter(hit).sort((x, y) => Number(y.online) - Number(x.online) || x.hostname.localeCompare(y.hostname));
  const q = state.search["my-domains"];
  const row = (x) =>
    cell({
      avatar: x.kind === "custom" ? "tag" : "link",
      title: x.hostname.split(".")[0],
      subtitle: `${x.hostname} · ${x.kind} · ${plural(x.usage.day.requests, "request")} today`,
      monoSub: false,
      trailing: x.online ? onlineBadge() : h("span", { class: "badge warn", title: fmtDate(x.hold_until) }, "frees " + ago(x.hold_until)),
      onclick: () => mySubdomainSheet(x),
    });
  return [
    head("Tunnels", `${o.tunnels.length} of ${o.limits.tunnels} online · ${o.limits.custom_domains == null ? plural(custom, "custom subdomain") : `${custom} of ${o.limits.custom_domains} custom subdomains`}`),
    group(
      "Online",
      o.tunnels.length ? o.tunnels.map((t) => tunnelCell(t, "since " + ago(t.created_at).replace(" ago", ""))) : empty("No tunnel is online. Start one with: mancar http 3000"),
      "With --private, visitors must log in first and only you get in.",
      total(o.tunnels.length),
    ),
    group(null, h("div", { class: "card toolbar" }, searchBox("my-domains", "Search your subdomains"))),
    group(
      "Your subdomains",
      paged("my-domains", domains, row, q ? `No subdomain matches “${q}”.` : "None yet. A subdomain is reserved the first time you open a tunnel with it."),
      "A name stays yours while a tunnel uses it, then for 24 hours (custom) or 5 minutes (random) after it disconnects.",
      domains.length === o.domains.length ? total(o.domains.length) : `${domains.length} of ${o.domains.length}`,
    ),
  ];
}

function mySubdomainSheet(x) {
  sheet(x.hostname, (close) => [
    group(null, stats(
      stat("Today", fmtNum(x.usage.day.requests)),
      stat("7 days", fmtNum(x.usage.week.requests)),
      stat("All time", fmtNum(x.usage.total.requests)),
    )),
    group(null, [
      cell({ avatar: x.kind === "custom" ? "tag" : "link", title: "Kind", value: x.kind }),
      cell({ avatar: "eye", title: "Status", trailing: x.online ? onlineBadge() : h("span", { class: "badge warn" }, "held") }),
      x.online ? null : cell({ avatar: "clock", title: "Held until", value: fmtDate(x.hold_until) }),
    ]),
    group("Public URL", codeBlock("https://" + x.hostname)),
    x.online
      ? null
      : group(null, actions(button("Release subdomain", confirmThen({
          title: `Release ${x.hostname.split(".")[0]}?`,
          message: "Anyone can claim it afterwards, and it counts no more against your limit.",
          action: "Release",
        }, async () => {
          await api("DELETE", `/domains/${encodeURIComponent(x.hostname)}`);
          close();
        }), { kind: "danger", icon: "trash" })), "Release a name you no longer need to free a custom slot."),
  ]);
}

function renderAccount(a) {
  const err = h("div", { class: "error", role: "alert", hidden: true });
  const current = h("input", { name: "current", type: "password", autocomplete: "current-password", required: true });
  const next = passwordInput("new-password");
  const save = h("button", { class: "btn primary", type: "submit" }, "Change password");
  const pwForm = h(
    "form",
    {
      class: "card form",
      onsubmit: async (ev) => {
        ev.preventDefault();
        save.disabled = true;
        err.hidden = true;
        try {
          await api("POST", own("/account/password"), { current: current.value, new: next.value });
          current.value = next.value = "";
          toast("Password changed. Other sessions are signed out.");
        } catch (e) {
          err.textContent = e.message;
          err.hidden = false;
        } finally {
          save.disabled = false;
        }
      },
    },
    err,
    h("label", {}, "Current password", current),
    passwordLabel("New password", next),
    save,
  );
  return [
    head("Account", `Member since ${new Date(a.created_at).toLocaleDateString()}`),
    group(null, h(
      "div",
      { class: "card profile" },
      avatar(initials(a.username)),
      h("div", { class: "cell-text" }, h("span", { class: "profile-title" }, a.username), h("span", { class: "cell-subtitle" }, a.email)),
      a.email_verified ? h("span", { class: "badge ok" }, icon("check"), "verified") : h("span", { class: "badge warn" }, "not confirmed"),
    )),
    a.email_verified ? null : verifyBanner(a.email),
    group("Your limits", [
      cell({ avatar: "link", title: "Tunnels at once", value: fmtNum(a.limits.tunnels) }),
      cell({ avatar: "tokens", title: "Active tokens", value: limitLabel(a.limits.tokens) }),
      cell({ avatar: "tag", title: "Custom subdomains", value: limitLabel(a.limits.custom_domains) }),
    ], a.role === "admin" ? "Admins have no token or subdomain limits." : "Set by the server admin."),
    group("Password", pwForm, "Changing it signs you out everywhere else. Your tokens keep working."),
    group("Delete account", actions(button("Delete my account", confirmThen({
      title: "Delete your account?",
      message: "Your tokens, subdomains, captured requests and statistics are deleted and your agents disconnected. This cannot be undone.",
      action: "Delete account",
    }, async () => {
      await api("DELETE", own("/account"));
      state.user = null;
      stopRefresh();
      renderLogin();
    }), { kind: "danger", icon: "trash" })), "Deleting is immediate and cannot be undone."),
  ];
}

// ---- start -----------------------------------------------------------------

window.addEventListener("hashchange", async () => {
  // an email link opened in a tab that already shows the dashboard
  const link = await openLink();
  if (link) {
    if (link !== "device") stopRefresh(); // verify/reset/access replace the page; a device sheet does not
    return;
  }
  const v = location.hash.slice(1);
  if (state.user && v in views() && v !== state.view) go(v);
});

document.addEventListener("visibilitychange", () => {
  if (state.user && document.visibilityState === "visible" && !views()[state.view].static) refresh();
});

async function start() {
  try {
    signIn(await api("GET", "/session"));
  } catch (e) {
    renderLogin(e.status === 401 ? undefined : e.message);
  }
}

openLink().then((handled) => handled || start());
