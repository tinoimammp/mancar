// Fake API for the dashboard preview (see index.html). Replaces fetch for
// /api/v1/admin/*; everything else (the stylesheet) goes to the real fetch.
(() => {
  const realFetch = window.fetch.bind(window);
  const now = Date.now();
  const at = (minutesAgo) => new Date(now - minutesAgo * 60000).toISOString();
  const usage = (day, week, total) => ({
    day: { requests: day, errors: Math.round(day * 0.02), bytes_in: day * 900, bytes_out: day * 42000 },
    week: { requests: week, errors: Math.round(week * 0.02), bytes_in: week * 900, bytes_out: week * 42000 },
    total: { requests: total, errors: Math.round(total * 0.01), bytes_in: total * 900, bytes_out: total * 40000 },
  });
  const host = "labsdigitalside.my.id";

  const agents = [
    { id: "s1", user_id: "u1", username: "tino", token_name: "macbook", token_id: "t1", client: "182.253.12.9",
      agent_version: "v0.3.2", connected_at: at(95), tunnels: [
        { id: "a", proto: "http", hostname: `lunar-panther.${host}`, public_url: `https://lunar-panther.${host}`, created_at: at(90), active_connections: 3, private: true, shared_with: ["ana", "budi"] },
        { id: "b", proto: "tcp", port: 20042, public_url: `tcp://${host}:20042`, created_at: at(40), active_connections: 0 },
      ] },
    { id: "s2", user_id: "u2", username: "rina", token_name: "office-pc", token_id: "t2", client: "36.71.4.120",
      agent_version: "v0.3.1", connected_at: at(12), tunnels: [
        { id: "c", proto: "http", hostname: `shop-api.${host}`, public_url: `https://shop-api.${host}`, created_at: at(12), active_connections: 0 },
      ] },
  ];
  // a busy gateway: a dozen more agents, some serving traffic, some idle,
  // one with no tunnel left open
  const people = [
    ["budi", "thinkpad", "v0.3.2", "103.47.132.8", [["kasir-pos", 7], ["kasir-ws", 2]]],
    ["sari", "imac-studio", "v0.3.2", "180.252.88.41", [["portfolio-sari", 1]]],
    ["dimas", "dev-server", "v0.3.0", "139.0.12.77", [["staging-api", 12], ["staging-web", 4], ["tcp", 1]]],
    ["ayu", "macbook-air", "v0.3.2", "36.68.201.15", [["undangan-ayu", 0]]],
    ["fajar", "ci-runner", "v0.3.1", "34.101.88.2", [["pr-482-preview", 0], ["pr-483-preview", 3]]],
    ["nadia", "laptop-kantor", "v0.3.2", "114.5.210.93", [["webhook-midtrans", 1]]],
    ["rizky", "raspberry-pi", "v0.2.4", "182.1.44.160", [["tcp", 0]]],
    ["tino", "pc-rumah", "v0.3.2", "182.253.12.9", [["grafana-home", 0], ["n8n-home", 2]]],
    ["putri", "windows-pc", "v0.3.2", "110.138.90.4", []],
    ["agus", "vps-jkt", "v0.3.2", "43.252.137.10", [["bot-telegram", 0]]],
    ["lina", "macbook-pro", "v0.3.2", "125.164.20.55", [["figma-plugin-dev", 5]]],
    ["yoga", "ubuntu-desktop", "v0.3.1", "202.80.216.3", [["minecraft-map", 0], ["tcp", 0]]],
  ];
  let port = 20050;
  people.forEach(([username, token_name, agent_version, client, tuns], i) => {
    agents.push({
      id: "s" + (i + 3), user_id: "u" + (i + 3), username, token_name, token_id: "t" + (i + 3), client, agent_version,
      connected_at: at(5 + i * 37),
      tunnels: tuns.map(([name, conns], j) =>
        name === "tcp"
          ? { id: `x${i}-${j}`, proto: "tcp", port: ++port, public_url: `tcp://${host}:${port}`, created_at: at(4 + i * 30), active_connections: conns }
          : { id: `x${i}-${j}`, proto: "http", hostname: `${name}.${host}`, public_url: `https://${name}.${host}`, created_at: at(4 + i * 30), active_connections: conns }),
    });
  });

  // ---- requests: each one carries its own realistic headers and bodies ----
  const lunar = `lunar-panther.${host}`;
  const shop = `shop-api.${host}`;
  const chrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
  const iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1";
  const fwd = (hostname, ip) => ({
    "X-Forwarded-For": [ip], "X-Forwarded-Host": [hostname], "X-Forwarded-Proto": ["https"], "X-Real-Ip": [ip],
  });
  const body = (text, extra = {}) => {
    const size = extra.size ?? new TextEncoder().encode(text).length;
    return { size, kept: Math.min(size, 65536), truncated: size > 65536, text, ...extra };
  };
  const none = { size: 0, kept: 0, truncated: false };
  const json2 = (v) => JSON.stringify(v);

  const browserReq = (hostname, ip, extra = {}) => ({
    Accept: ["text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"],
    "Accept-Encoding": ["gzip, deflate, br, zstd"],
    "Accept-Language": ["id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"],
    "Sec-Ch-Ua": ['"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'],
    "Sec-Ch-Ua-Mobile": ["?0"],
    "Sec-Ch-Ua-Platform": ['"macOS"'],
    "Sec-Fetch-Dest": ["document"],
    "Sec-Fetch-Mode": ["navigate"],
    "Sec-Fetch-Site": ["none"],
    "Upgrade-Insecure-Requests": ["1"],
    "User-Agent": [chrome],
    ...fwd(hostname, ip),
    ...extra,
  });
  const apiReq = (hostname, ip, ua, extra = {}) => ({
    Accept: ["application/json"],
    "Accept-Encoding": ["gzip, br"],
    "User-Agent": [ua],
    ...fwd(hostname, ip),
    ...extra,
  });
  const jsonRes = (extra = {}) => ({
    "Content-Type": ["application/json; charset=utf-8"],
    Date: [new Date(now).toUTCString()],
    Vary: ["Accept-Encoding"],
    ...extra,
  });

  const requests = [
    {
      id: "r01", time: at(0.2), hostname: shop, method: "POST", uri: "/v1/orders", status: 201, duration_ms: 286, client: "36.71.4.120",
      request_headers: apiReq(shop, "36.71.4.120", "okhttp/4.12.0", {
        Authorization: ["Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1XzgyMSJ9.Qm9ndXMtc2lnbmF0dXJl"],
        "Content-Type": ["application/json"],
        "Idempotency-Key": ["7f3c2a10-5e8b-4d1a-9c44-2b6e0f9a8d31"],
      }),
      request_body: body(json2({ customer_id: "u_821", items: [{ sku: "KOPI-SUSU-L", qty: 2 }, { sku: "ROTI-BAKAR", qty: 1 }], payment: "qris", note: "less sugar" })),
      response_headers: jsonRes({ Location: ["/v1/orders/ord_9KX2"], "X-Request-Id": ["req_01JD4M8Z7T3V"] }),
      response_body: body(json2({ id: "ord_9KX2", status: "pending_payment", total: 58000, currency: "IDR", qris_url: "https://pay.example.id/q/ord_9KX2", expires_at: at(-15) })),
    },
    {
      id: "r02", time: at(0.5), hostname: lunar, method: "GET", uri: "/", status: 200, duration_ms: 431, client: "182.253.12.9",
      request_headers: browserReq(lunar, "182.253.12.9", { Cookie: ["theme=dark; _ga=GA1.1.1873390112.1731800000"] }),
      request_body: none,
      response_headers: {
        "Cache-Control": ["private, no-cache, no-store, max-age=0, must-revalidate"],
        "Content-Encoding": ["gzip"],
        "Content-Type": ["text/html; charset=utf-8"],
        Date: [new Date(now).toUTCString()],
        Vary: ["RSC, Next-Router-State-Tree, Next-Router-Prefetch, Accept-Encoding"],
        "X-Powered-By": ["Next.js"],
      },
      response_body: body('<!DOCTYPE html><html lang="id"><head><meta charSet="utf-8"/><title>Lunar Panther · Dashboard</title><link rel="stylesheet" href="/_next/static/css/app.css"/></head><body><main id="__next"><h1>Halo, Tino</h1><p>3 proyek aktif</p></main><script src="/_next/static/chunks/main-app.js" async></script></body></html>', { decoded: "gzip", size: 18213 }),
    },
    {
      id: "r03", time: at(0.9), hostname: lunar, method: "POST", uri: "/api/auth/login", status: 401, duration_ms: 152, client: "182.253.12.9",
      request_headers: apiReq(lunar, "182.253.12.9", chrome, {
        "Content-Type": ["application/json"], Origin: [`https://${lunar}`], Referer: [`https://${lunar}/login`],
      }),
      request_body: body(json2({ email: "tino@example.com", password: "••••••••", remember: true })),
      response_headers: jsonRes({ "Cache-Control": ["no-store"], "Www-Authenticate": ['Bearer error="invalid_credentials"'] }),
      response_body: body(json2({ error: { code: "invalid_credentials", message: "Email atau kata sandi salah." } })),
    },
    {
      id: "r04", time: at(1.4), hostname: shop, method: "GET", uri: "/v1/products?page=2&limit=3", status: 200, duration_ms: 488, client: "114.124.236.18", replay: true,
      request_headers: apiReq(shop, "114.124.236.18", iphone, { "If-None-Match": ['W/"5c1-1Hq9"'] }),
      request_body: none,
      response_headers: jsonRes({ "Cache-Control": ["public, max-age=60"], Etag: ['W/"5c1-8Zp2"'], "X-Total-Count": ["42"] }),
      response_body: body(json2({
        page: 2, limit: 3, total: 42,
        items: [
          { id: 4, sku: "KOPI-SUSU-L", name: "Kopi susu gula aren (L)", price: 24000, stock: 31 },
          { id: 5, sku: "TEH-TARIK", name: "Teh tarik", price: 18000, stock: 12 },
          { id: 6, sku: "ROTI-BAKAR", name: "Roti bakar cokelat keju", price: 22000, stock: 0 },
        ],
      })),
    },
    {
      id: "r05", time: at(2.1), hostname: shop, method: "POST", uri: "/v1/uploads/receipt", status: 502, duration_ms: 30004, client: "36.71.4.120",
      request_headers: apiReq(shop, "36.71.4.120", "okhttp/4.12.0", {
        "Content-Type": ["multipart/form-data; boundary=----mancarBoundary7MA4YWxk"], "Content-Length": ["2412880"],
      }),
      request_body: { size: 2412880, kept: 65536, truncated: true, text: null },
      response_headers: { "Content-Type": ["text/plain; charset=utf-8"], "X-Mancar-Error": ["local_service_timeout"] },
      response_body: body("mancar: the local service at localhost:8080 did not answer within 30s"),
      replayable: false,
      replay_blocker: "the request body was larger than INSPECT_MAX_BODY_BYTES, so it was not stored completely",
    },
    {
      id: "r06", time: at(3.5), hostname: lunar, method: "PATCH", uri: "/api/projects/prj_42", status: 200, duration_ms: 97, client: "182.253.12.9",
      request_headers: apiReq(lunar, "182.253.12.9", chrome, { "Content-Type": ["application/json"], Cookie: ["session=s%3AJ8x2…; theme=dark"] }),
      request_body: body(json2({ name: "Landing page v2", visibility: "team" })),
      response_headers: jsonRes(),
      response_body: body(json2({ id: "prj_42", name: "Landing page v2", visibility: "team", updated_at: at(3.5) })),
    },
    {
      id: "r07", time: at(5), hostname: shop, method: "POST", uri: "/webhooks/payment", status: 200, duration_ms: 64, client: "103.10.128.5",
      request_headers: apiReq(shop, "103.10.128.5", "Payment-Webhook/2.1", {
        "Content-Type": ["application/json"], "X-Callback-Signature": ["sha256=9f2c1b7e4d0a6c3e8b5f1a2d7c9e0b4f6a8d3c1e"],
      }),
      request_body: body(json2({ event: "payment.paid", order_id: "ord_9KX0", amount: 46000, currency: "IDR", paid_at: at(5) })),
      response_headers: jsonRes(),
      response_body: body(json2({ received: true })),
    },
    {
      id: "r08", time: at(7), hostname: lunar, method: "GET", uri: "/api/projects?sort=updated", status: 500, duration_ms: 812, client: "182.253.12.9",
      request_headers: apiReq(lunar, "182.253.12.9", chrome, { Cookie: ["session=s%3AJ8x2…; theme=dark"] }),
      request_body: none,
      response_headers: jsonRes({ "Cache-Control": ["no-store"] }),
      response_body: body(json2({ error: { code: "internal", message: "relation \"projects_v2\" does not exist", trace_id: "c0ffee42" } })),
    },
    {
      id: "r09", time: at(11), hostname: shop, method: "DELETE", uri: "/v1/cart/items/ROTI-BAKAR", status: 204, duration_ms: 41, client: "114.124.236.18",
      request_headers: apiReq(shop, "114.124.236.18", iphone, { Authorization: ["Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1XzMwMiJ9.c2lnbg"] }),
      request_body: none,
      response_headers: { Date: [new Date(now).toUTCString()] },
      response_body: none,
    },
    {
      id: "r10", time: at(16), hostname: lunar, method: "GET", uri: "/logo.png", status: 200, duration_ms: 23, client: "182.253.12.9",
      request_headers: browserReq(lunar, "182.253.12.9", { Accept: ["image/avif,image/webp,image/apng,*/*;q=0.8"], "Sec-Fetch-Dest": ["image"] }),
      request_body: none,
      response_headers: { "Cache-Control": ["public, max-age=31536000, immutable"], "Content-Type": ["image/png"], "Content-Length": ["24518"] },
      response_body: { size: 24518, kept: 24518, truncated: false, text: null },
    },
  ].map((r) => ({
    ...r,
    request_size: r.request_body.size,
    response_size: r.response_body.size,
  }));

  const detail = (r) => ({
    proto: "HTTP/1.1", tunnel_id: r.hostname === lunar ? "a" : "c", replayable: true, replay_blocker: "", ...r,
  });

  // ---- enough rows to page through: built from the agents above ----
  // Older traffic: copies of the detailed requests at earlier times, so the
  // Requests list has several pages and every row still opens a full detail.
  const paths = ["/", "/api/me", "/v1/products", "/v1/cart", "/_next/data/build/index.json", "/api/projects", "/v1/orders/ord_9KX0", "/health"];
  const older = Array.from({ length: 64 }, (_, i) => {
    const base = requests[i % requests.length];
    return { ...base, id: "o" + i, time: at(18 + i * 7), uri: base.method === "GET" ? paths[i % paths.length] : base.uri, replay: false };
  });
  const allRequests = [...requests, ...older];

  const names = [...new Set(agents.map((a) => a.username))];
  const extraUsers = ["andi", "bayu", "citra", "dewi", "eko", "gilang", "hana", "indra", "joko", "kiki"];
  const users = [...names, ...extraUsers].map((username, i) => {
    const mine = agents.filter((a) => a.username === username);
    const reqs = mine.reduce((n, a) => n + a.tunnels.reduce((m, t) => m + (t.active_connections || 0), 0), 0) * 900 + (i * 137) % 600;
    const status = i % 7 === 5 ? "disabled" : i % 5 === 4 ? "unverified" : "active";
    const signedUp = i % 3 !== 0;
    return {
      id: "u" + (i + 1), username, email: i % 6 === 2 ? "" : `${username}@example.com`,
      role: username === "tino" || username === "rina" ? "admin" : "user",
      status, email_verified: status !== "unverified", has_password: i % 6 !== 2, signed_up: signedUp,
      created_at: at(3000 + i * 1440), last_login_at: i % 4 === 3 ? null : at(30 + i * 97),
      active_tokens: Math.max(mine.length, i % 3 === 0 ? 0 : 1), domains: mine.reduce((n, a) => n + a.tunnels.length, 0),
      custom_domains: Math.min(3, mine.reduce((n, a) => n + a.tunnels.length, 0)),
      connected_agents: status === "disabled" ? 0 : mine.length,
      max_tokens: signedUp ? 3 : null, max_custom_domains: signedUp ? 3 : null,
      usage: usage(reqs, reqs * 6, reqs * 40 + 1200),
    };
  });
  const audit = [
    ["preview", "user.role", "rina", "user → admin"], ["preview", "user.disable", "gilang", "1 agent(s) disconnected"],
    ["tino", "token.create", "tino", "pc-rumah"], ["preview", "user.limits", "budi", "tokens 5, custom subdomains 3"],
    ["preview", "user.reset_password", "andi", "link emailed"], ["budi", "token.revoke", "t4", "1 agent(s) disconnected"],
    ["preview", "domain.release", `old-shop.${host}`, ""], ["preview", "user.create", "rina", "role user"],
    ["sari", "account.password", "sari", ""], ["preview", "request.replay", `shop-api.${host}`, "POST /v1/orders → 201"],
  ].map(([actor, action, target, detail], i) => ({ at: at(3 + i * 41), actor, action, target, detail }));

  const tokens = [
    ...agents.map((a, i) => ({
      id: a.token_id, username: a.username, name: a.token_name, created_at: at(2000 + i * 900), last_used_at: a.connected_at, revoked_at: null, connected_agents: 1,
    })),
    ...extraUsers.map((username, i) => ({
      id: "tx" + i, username, name: ["laptop", "desktop", "ci", "server"][i % 4], created_at: at(9000 + i * 600),
      last_used_at: at(1500 + i * 400), revoked_at: i % 3 === 0 ? at(800 + i * 60) : null, connected_agents: 0,
    })),
  ];

  const domains = [
    ...agents.flatMap((a) => a.tunnels.filter((t) => t.proto === "http").map((t, j) => ({
      hostname: t.hostname, username: a.username, kind: j % 2 ? "random" : "custom", online: true, usage: usage(900, 5400, 40000),
    }))),
    ...["demo", "old-shop", "promo-1111", "beta-app", "undangan-budi", "test-webhook"].map((name, i) => ({
      hostname: `${name}.${host}`, username: names[i % names.length], kind: i % 2 ? "random" : "custom", online: false,
      hold_until: new Date(now + (i + 1) * 3.6e6).toISOString(), usage: usage(0, 420, 5200),
    })),
  ];

  const get = {
    "/session": { username: "preview" },
    "/overview": {
      version: "v0.3.2", base_domain: host, tcp_ports: "20000-20099", database: "ok", uptime_seconds: 302400,
      gateway: { sessions: agents.length, tunnels: agents.reduce((n, a) => n + a.tunnels.length, 0) }, users: 24, active_tokens: 20, reserved_domains: 26, inspector: "on, kept 24h0m0s",
      traffic_24h: { requests: 18432, errors: 37, bytes_in: 0, bytes_out: 0 }, traffic_total: { requests: 912345 },
      top_hosts: [
        { hostname: `lunar-panther.${host}`, usage: usage(12040, 60100, 400000) },
        { hostname: `shop-api.${host}`, usage: usage(6392, 30200, 98000) },
      ],
    },
    "/agents": { agents },
    "/tokens": { tokens },
    "/users": { users, email_enabled: true },
    "/audit": { entries: audit },
    "/domains": { domains },
    "/requests": { retention_seconds: 86400, max_body_bytes: 65536, undecryptable: 0, requests: allRequests },
  };

  const json = (body, status = 200) =>
    new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

  // ---- who is signed in: ?as=admin (default) | user | unverified | guest ----
  // guest shows the sign-in page with sign up open; signing in as "admin"
  // opens the admin view, anything else the user view.
  const as = new URLSearchParams(location.search).get("as") || "admin";
  let session = as === "guest" || as === "setup" ? null : as === "admin" ? { username: "preview", role: "admin" } : { username: "tino", role: "user" };
  let verified = as !== "unverified";

  // the user "tino": the agents above that belong to tino
  const mine = agents.filter((a) => a.username === "tino");
  const myTunnels = mine.flatMap((a) => a.tunnels);
  const myDomains = [
    ...myTunnels.filter((t) => t.proto === "http").map((t, i) => ({
      hostname: t.hostname, kind: i % 2 ? "random" : "custom", online: true, usage: usage(1200 - i * 300, 7400, 61000),
    })),
    { hostname: `demo.${host}`, kind: "custom", online: false, hold_until: new Date(now + 6e6).toISOString(), usage: usage(0, 420, 5200) },
    { hostname: `quiet-otter.${host}`, kind: "random", online: false, hold_until: new Date(now + 2.4e5).toISOString(), usage: usage(12, 80, 300) },
  ];
  const limits = { tunnels: 3, tokens: 3, custom_domains: 3 };
  const me = {
    "/overview": () => ({
      base_domain: host, email: "tino@example.com", email_verified: verified, limits,
      tunnels: myTunnels, domains: myDomains, usage: usage(2650, 15800, 128400),
    }),
    "/tokens": () => ({ email_verified: verified, limit: limits.tokens, tokens: tokens.filter((t) => t.username === "tino" && !t.revoked_at) }),
    "/account": () => (session && session.role === "admin"
      ? { username: session.username, email: "", email_verified: true, role: "admin", created_at: at(90 * 1440), limits: { tunnels: 100, tokens: null, custom_domains: null } }
      : { username: "tino", email: "tino@example.com", email_verified: verified, role: "user", created_at: at(30 * 1440), limits }),
    "/requests": () => ({
      retention_seconds: 86400, max_body_bytes: 65536, undecryptable: 0,
      requests: allRequests.filter((r) => myTunnels.some((t) => t.hostname === r.hostname)),
    }),
  };

  window.fetch = async (input, init = {}) => {
    const url = new URL(String(input), location.href);
    const isMe = url.pathname.startsWith("/api/v1/me");
    if (!/^\/api\/v1\/(admin|me|auth)\//.test(url.pathname)) return realFetch(input, init);
    const path = url.pathname.replace(/^\/api\/v1\/(admin|me|auth)/, "");
    const method = (init.method || "GET").toUpperCase();
    const body = JSON.parse(init.body || "{}");
    await new Promise((r) => setTimeout(r, 250)); // let busy states show

    // sign in, sign up, session
    if (path === "/session") return session ? json(session) : json({ error: { code: "unauthorized", message: "sign in" } }, 401);
    if (path === "/options") {
      const setup = as === "setup" && !session;
      return json({ setup, signup: true, password_reset: true, ...(setup ? { version: "v0.4.0" } : {}) });
    }
    if (path === "/setup") {
      session = { username: body.username, role: "admin" };
      return json({ ...session, email: body.email, email_verified: true }, 201);
    }
    if (path === "/signup/verify") {
      verified = true;
      return json({ verified: true });
    }
    if (path === "/password/forgot") return json(null, 204);
    if (path === "/password/reset") return json(null, 204);
    if (path === "/login") {
      if (body.password === "wrong") return json({ error: { code: "invalid_credentials", message: "wrong username, email or password" } }, 401);
      session = body.username === "admin" ? { username: "admin", role: "admin" } : { username: "tino", role: "user" };
      return json(session);
    }
    if (path === "/signup") {
      if (body.username === "taken") return json({ error: { code: "conflict", message: "That username is taken." } }, 409);
      verified = false;
      return json({ verify_email: true }, 202);
    }
    if (path === "/logout") {
      session = null;
      return json(null, 204);
    }
    if (path === "/signup/resend" || path === "/account/verify/resend") return json(null, 204);
    if (path === "/account/password") {
      if (body.current !== "password123") return json({ error: { code: "bad_password", message: "The current password is wrong (preview: it is password123)." } }, 400);
      return json(null, 204);
    }
    if (path === "/access") {
      // a private tunnel: tino owns lunar-panther; any other account (log in
      // as "admin") is not authorized
      const tunnel = String(body.target).split(/[/?]/)[0];
      if (!tunnel.endsWith("." + host)) return json({ error: { code: "not_found", message: "not a tunnel of this server" } }, 404);
      const owner = session && session.username === "tino" && tunnel === `lunar-panther.${host}`;
      return json({ url: (owner ? "tunnel.html?host=" : "restricted.html?host=") + encodeURIComponent(tunnel), allowed: owner, owner });
    }
    const dev = path.match(/^\/device\/([A-Z0-9-]+)(\/(approve|deny))?$/i);
    if (dev) return dev[2] ? json(null, 204) : json({ user_code: dev[1].toUpperCase(), name: "MacBook-Pro-Tino", created_at: at(0.2) });
    if (isMe && method === "GET" && me[path]) return json(me[path]());

    if (method === "GET") {
      const m = path.match(/^\/requests\/(.+)$/);
      if (m) {
        const r = allRequests.find((x) => x.id === m[1]);
        return r ? json(detail(r)) : json({ error: { code: "not_found", message: "no such request" } }, 404);
      }
      return json(get[path] || {});
    }
    if (path === "/tokens") {
      return json({ id: "t9", user: body.user, name: body.name || "dashboard", token: "mc_" + "0123456789abcdef".repeat(4) }, 201);
    }
    if (path.endsWith("/replay")) return json({ status: 200, duration_ms: 444, response_size: 512 });
    if (path.endsWith("/revoke")) return json({ disconnected_agents: 1 });
    return json(method === "DELETE" ? { deleted: 0, disconnected_agents: 0 } : null, method === "DELETE" ? 200 : 204);
  };
})();
