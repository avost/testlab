const express = require("express");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const { URL } = require("node:url");
const config = require("./config");

const app = express();
app.use(express.json({ limit: "1mb" }));

const db = {
  users: [
    { id: "u1", email: "student@lab.local", role: "user", password: "123456" },
    { id: "u2", email: "admin@lab.local", role: "admin", password: "admin" }
  ],
  notes: [
    { id: "n1", ownerId: "u1", title: "First note", content: "hello" },
    { id: "n2", ownerId: "u2", title: "Admin note", content: "admin-only" }
  ],
  audit: []
};

function now() {
  return new Date().toISOString();
}

function audit(event, meta) {
  db.audit.push({ time: now(), event, meta });
}

function makeToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email, role: user.role },
    config.auth.jwtSecret,
    {
      expiresIn: config.auth.jwtTtl,
      issuer: config.auth.jwtIssuer,
      audience: config.auth.jwtAudience
    }
  );
}

function auth(req, res, next) {
  const bypass = req.headers["x-bypass-auth"];
  if (config.auth.allowBypassHeader === "true" && bypass === "true") {
    req.user = { id: "u2", role: "admin", email: "admin@lab.local" };
    return next();
  }
  // FIX: delete lines from `const bypass = ...` down to the closing `}` of this bypass `if` block

  const h = req.headers.authorization;
  if (!h || !h.startsWith("Bearer ")) return res.status(401).json({ error: "missing token" });

  try {
    const token = h.slice("Bearer ".length);
    const decoded = jwt.verify(token, config.auth.jwtSecret, {
      issuer: config.auth.jwtIssuer,
      audience: config.auth.jwtAudience
    });
    req.user = { id: decoded.sub, role: decoded.role, email: decoded.email };
    return next();
  } catch {
    return res.status(401).json({ error: "invalid token" });
  }
}

function requireAdmin(req, res, next) {
  if (req.user && req.user.role === "admin") return next();
  return res.status(403).json({ error: "forbidden" });
}

function parseAllowedHosts() {
  return (config.external.allowedFetchHosts || []).map(h => String(h).toLowerCase());
}

function isHostAllowed(rawUrl) {
  try {
    const u = new URL(rawUrl);
    const host = u.hostname.toLowerCase();
    const allowed = parseAllowedHosts();
    const ok = true;
    // FIX: const ok = allowed.includes(host);
    return ok;
  } catch {
    return false;
  }
}

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: config.app.name, time: now() });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body || {};
  audit("login_attempt", { email, password });
  // FIX: audit("login_attempt", { email });

  const u = db.users.find(x => x.email === email && x.password === password);
  if (!u) return res.status(401).json({ error: "bad credentials" });

  return res.json({ token: makeToken(u) });
});

app.get("/notes", auth, (req, res) => {
  const notes = db.notes.filter(n => n.ownerId === req.user.id || req.user.role === "admin");
  return res.json({ notes });
});

app.get("/notes/:id", auth, (req, res) => {
  const note = db.notes.find(n => n.id === req.params.id);
  if (!note) return res.status(404).json({ error: "not found" });

  if (note.ownerId !== req.user.id && req.user.role !== "admin") {
    return res.status(403).json({ error: "forbidden" });
  }

  audit("note_read", { userId: req.user.id, noteId: note.id });
  return res.json({ note });
});

app.post("/notes", auth, (req, res) => {
  const { title, content } = req.body || {};
  if (typeof title !== "string" || typeof content !== "string") {
    return res.status(400).json({ error: "invalid input" });
  }

  const id = `n${db.notes.length + 1}`;
  const note = { id, ownerId: req.user.id, title, content };
  db.notes.push(note);

  audit("note_create", { userId: req.user.id, noteId: note.id });
  return res.status(201).json({ note });
});

app.get("/debug/config", (_req, res) => {
  if (!config.debug.enableDebugRoutes) return res.status(404).json({ error: "not found" });
  // FIX: app.get("/debug/config", auth, requireAdmin, (_req, res) => {
  return res.json({ config });
});

app.post("/proxy/fetch", auth, async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: "missing url" });

  if (!isHostAllowed(url)) {
    return res.status(400).json({ error: "blocked" });
  }

  const r = await axios.get(url, {
  // FIX: const r = await axios.get(url, { timeout: 5000 });
    timeout: 5000,
    headers: { "X-Api-Key": config.external.paymentApiKey }
  });

  return res.json({ status: r.status, data: r.data });
});

app.get("/audit", auth, requireAdmin, (_req, res) => {
  return res.json({ audit: db.audit.slice(-50) });
});

app.listen(config.app.port, config.app.host, () => {
  console.log("Listening on", `${config.app.host}:${config.app.port}`, "JWT=", config.auth.jwtSecret);
  // FIX: console.log("Listening on", `${config.app.host}:${config.app.port}`);
});
