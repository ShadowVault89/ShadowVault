const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const HOST = "127.0.0.1";
const PORT = Number(process.env.PORT || 3000);
const ROOT = path.join(__dirname, "public");
const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const sessions = new Map();
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]\n", { mode: 0o600 });

function readUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, "utf8")); }
  catch { return []; }
}
function writeUsers(users) {
  const tmp = USERS_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(users, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, USERS_FILE);
}
function safeUser(user) {
  return { username: user.username, email: user.email, createdAt: user.createdAt };
}
function parseCookies(header = "") {
  return Object.fromEntries(header.split(";").map(part => {
    const i = part.indexOf("=");
    return i < 0 ? ["", ""] : [part.slice(0, i).trim(), decodeURIComponent(part.slice(i + 1).trim())];
  }).filter(([key]) => key));
}
function currentUser(req) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies.sv_session;
  const session = token && sessions.get(token);
  if (!session) return null;
  if (session.expiresAt < Date.now()) { sessions.delete(token); return null; }
  const user = readUsers().find(u => u.id === session.userId);
  return user || null;
}
function send(res, status, body, extraHeaders = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
    ...extraHeaders
  });
  res.end(payload);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", chunk => {
      raw += chunk;
      if (raw.length > 12_000) { reject(new Error("Request is too large.")); req.destroy(); }
    });
    req.on("end", () => {
      try { resolve(JSON.parse(raw || "{}")); }
      catch { reject(new Error("Please send valid JSON.")); }
    });
    req.on("error", reject);
  });
}
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, key) => {
      if (err) reject(err);
      else resolve({ salt, hash: key.toString("hex") });
    });
  });
}
async function verifyPassword(password, user) {
  const result = await hashPassword(password, user.salt);
  const a = Buffer.from(result.hash, "hex");
  const b = Buffer.from(user.passwordHash, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function setSession(res, user) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { userId: user.id, expiresAt: Date.now() + SESSION_TTL_MS });
  res.setHeader("Set-Cookie", `sv_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`);
}
function clearSession(req, res) {
  const token = parseCookies(req.headers.cookie).sv_session;
  if (token) sessions.delete(token);
  res.setHeader("Set-Cookie", "sv_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
}
function validEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254; }

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  if (req.method === "GET" && url.pathname === "/api/me") {
    const user = currentUser(req);
    return send(res, 200, { user: user ? safeUser(user) : null });
  }
  if (req.method === "POST" && ["/api/register", "/api/login", "/api/logout"].includes(url.pathname)) {
    if (req.headers.origin && req.headers.origin !== `http://${req.headers.host}`) {
      return send(res, 403, { error: "Request origin not allowed." });
    }
    if (url.pathname === "/api/logout") {
      clearSession(req, res);
      return send(res, 200, { ok: true });
    }
    let body;
    try { body = await readBody(req); }
    catch (error) { return send(res, 400, { error: error.message }); }
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const users = readUsers();

    if (url.pathname === "/api/register") {
      const username = String(body.username || "").trim();
      if (!/^[a-zA-Z0-9_]{3,24}$/.test(username))
        return send(res, 400, { error: "Username must be 3–24 characters (letters, numbers, underscore)." });
      if (!validEmail(email)) return send(res, 400, { error: "Enter a valid email address." });
      if (password.length < 8 || password.length > 128)
        return send(res, 400, { error: "Password must be 8–128 characters." });
      if (users.some(u => u.email === email))
        return send(res, 409, { error: "An account with this email already exists. Please sign in." });
      if (users.some(u => u.username.toLowerCase() === username.toLowerCase()))
        return send(res, 409, { error: "That username is already taken." });
      const { salt, hash } = await hashPassword(password);
      const user = {
        id: crypto.randomUUID(), username, email, salt, passwordHash: hash,
        createdAt: new Date().toISOString()
      };
      users.push(user);
      writeUsers(users);
      setSession(res, user);
      return send(res, 201, { user: safeUser(user) });
    }

    const user = users.find(u => u.email === email);
    if (!user || !(await verifyPassword(password, user)))
      return send(res, 401, { error: "Email or password is incorrect." });
    setSession(res, user);
    return send(res, 200, { user: safeUser(user) });
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8", "Allow": "GET, HEAD" });
    return res.end("Method not allowed");
  }
  const requested = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname);
  const file = path.resolve(ROOT, "." + requested);
  if (!file.startsWith(ROOT + path.sep) && file !== path.join(ROOT, "index.html")) {
    res.writeHead(403); return res.end("Forbidden");
  }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }); return res.end("Not found"); }
    const ext = path.extname(file);
    const types = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon" };
    res.writeHead(200, {
      "Content-Type": types[ext] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Cache-Control": "no-store"
    });
    if (req.method === "HEAD") return res.end();
    res.end(data);
  });
});
server.listen(PORT, HOST, () => {
  console.log(`\nSHADOW VAULT is running at http://${HOST}:${PORT}`);
  console.log("Press Ctrl+C to stop the local server.\n");
});
