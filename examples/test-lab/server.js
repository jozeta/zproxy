// A tiny, dependency-free local app for practicing the ZProxy workflow:
// Scope -> Intercept -> browse -> edit -> forward. Not a security example in
// itself — deliberately simple and unauthenticated-by-design so you have
// something safe of your own to point ZProxy at. Run with:
//   node examples/test-lab/server.js
// then add 127.0.0.1 (or localhost) to ZProxy's Scope and browse to
// http://localhost:8787/.
import http from "node:http";
import crypto from "node:crypto";

const PORT = 8787;
const sessions = new Map(); // token -> username

function base64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

function issueFakeJwt(username) {
  // Deliberately unsigned ("alg":"none") — this is a practice target for
  // ZProxy's JWT *decoder*, not a real auth scheme. Never do this for real.
  const header = base64url({ alg: "none", typ: "JWT" });
  const payload = base64url({ sub: username, iat: Math.floor(Date.now() / 1000) });
  return `${header}.${payload}.unsigned`;
}

function sendJson(res, status, body, extraHeaders = {}) {
  res.writeHead(status, { "Content-Type": "application/json", "X-Test-Lab": "zproxy", ...extraHeaders });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
  });
}

const INDEX_HTML = `<!doctype html>
<html>
<head><meta charset="utf-8"><title>ZProxy Test Lab</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 640px; margin: 40px auto; padding: 0 16px; }
  button { padding: 8px 14px; margin: 4px 4px 4px 0; }
  pre { background: #eee; padding: 10px; overflow-x: auto; white-space: pre-wrap; }
  input { padding: 6px; margin: 4px 0; width: 100%; box-sizing: border-box; }
</style>
</head>
<body>
  <h1>ZProxy Test Lab</h1>
  <p>A safe local target for practicing intercept/edit/forward. Nothing here is real auth — don't reuse this pattern.</p>

  <h2>1. Log in</h2>
  <input id="username" placeholder="username" value="alice">
  <button onclick="login()">Log in</button>
  <pre id="login-out"></pre>

  <h2>2. Get profile (uses the token from step 1)</h2>
  <button onclick="profile()">GET /api/profile</button>
  <pre id="profile-out"></pre>

  <h2>3. Feature flags (try a Match/Replace rule on this response body)</h2>
  <button onclick="flags()">GET /api/flags</button>
  <pre id="flags-out"></pre>

  <h2>4. Echo headers (try adding/editing a header in Intercept)</h2>
  <button onclick="echo()">GET /api/echo-headers</button>
  <pre id="echo-out"></pre>

  <script>
    let token = null;
    async function login() {
      const username = document.getElementById('username').value;
      const res = await fetch('/api/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username, password: 'anything' }) });
      const data = await res.json();
      token = data.token;
      document.getElementById('login-out').textContent = JSON.stringify(data, null, 2);
    }
    async function profile() {
      const res = await fetch('/api/profile', { headers: token ? { Authorization: 'Bearer ' + token } : {} });
      document.getElementById('profile-out').textContent = JSON.stringify(await res.json(), null, 2);
    }
    async function flags() {
      const res = await fetch('/api/flags');
      document.getElementById('flags-out').textContent = JSON.stringify(await res.json(), null, 2);
    }
    async function echo() {
      const res = await fetch('/api/echo-headers', { headers: { 'X-Lab-Custom': 'hello' } });
      document.getElementById('echo-out').textContent = JSON.stringify(await res.json(), null, 2);
    }
  </script>
</body>
</html>`;

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === "/" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "text/html", "X-Test-Lab": "zproxy" });
    res.end(INDEX_HTML);
    return;
  }

  if (url.pathname === "/api/login" && req.method === "POST") {
    const body = await readBody(req);
    let username = "anonymous";
    try {
      username = JSON.parse(body).username || username;
    } catch {
      /* tolerate malformed bodies — this is a practice target, not a robustness test */
    }
    const sessionId = crypto.randomBytes(12).toString("hex");
    sessions.set(sessionId, username);
    const token = issueFakeJwt(username);
    sendJson(res, 200, { ok: true, token, user: { username } }, { "Set-Cookie": `zp_session=${sessionId}; HttpOnly; Path=/` });
    return;
  }

  if (url.pathname === "/api/profile" && req.method === "GET") {
    const auth = req.headers.authorization || "";
    const match = auth.match(/^Bearer\s+(.+)$/i);
    if (!match) {
      sendJson(res, 401, { error: "Missing Authorization: Bearer <token>" });
      return;
    }
    try {
      const [, payloadB64] = match[1].split(".");
      const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
      sendJson(res, 200, { user: payload.sub, tokenIssuedAt: payload.iat });
    } catch {
      sendJson(res, 400, { error: "Could not decode token" });
    }
    return;
  }

  if (url.pathname === "/api/flags" && req.method === "GET") {
    sendJson(res, 200, { featureXEnabled: false, betaBanner: true });
    return;
  }

  if (url.pathname === "/api/echo-headers" && req.method === "GET") {
    sendJson(res, 200, { headers: req.headers });
    return;
  }

  sendJson(res, 404, { error: "Not found" });
});

server.listen(PORT, () => {
  console.log(`ZProxy test lab listening on http://localhost:${PORT}`);
});
