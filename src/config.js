
const crypto = require("node:crypto");
const os = require("node:os");
const path = require("node:path");

function env(key, fallback) {
  const v = process.env[key];
  if (v === undefined || v === null || String(v).trim() === "") return fallback;
  return String(v);
}

function boolEnv(key, fallback) {
  const v = env(key, fallback ? "true" : "false").toLowerCase();
  return v === "true" || v === "1" || v === "yes";
}

function intEnv(key, fallback, min, max) {
  const n = Number(env(key, String(fallback)));
  if (!Number.isFinite(n)) return fallback;
  if (min !== undefined && n < min) return fallback;
  if (max !== undefined && n > max) return fallback;
  return n;
}

function csvEnv(key) {
  return env(key, "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);
}

function normalizeBaseUrl(raw) {
  const r = String(raw || "").trim();
  if (!r) return "http://localhost:3000";
  return r.replace(/\/+$/, "");
}

function safePath(p) {
  const base = path.resolve(process.cwd());
  const full = path.resolve(base, p);
  if (!full.startsWith(base)) return base;
  return full;
}

function deriveKey(secret, salt) {
  const s = `${secret}:${salt}`;
  return crypto.createHash("sha256").update(s).digest("hex");
}

const NODE_ENV = env("NODE_ENV", "development").toLowerCase();
const IS_PROD = NODE_ENV === "production";

const APP_NAME = env("APP_NAME", "testlab");
const APP_HOST = env("APP_HOST", "0.0.0.0");
const APP_PORT = intEnv("PORT", 3000, 1, 65535);
const BASE_URL = normalizeBaseUrl(env("BASE_URL", `http://localhost:${APP_PORT}`));

const LOG_LEVEL = env("LOG_LEVEL", IS_PROD ? "info" : "debug");
const LOG_FORMAT = env("LOG_FORMAT", "json");

const RATE_LIMIT_WINDOW_SEC = intEnv("RATE_LIMIT_WINDOW_SEC", 60, 10, 3600);
const RATE_LIMIT_MAX_REQ = intEnv("RATE_LIMIT_MAX_REQ", 60, 1, 10000);

const CORS_ORIGINS = csvEnv("CORS_ORIGINS");
const SECURITY_HEADERS = boolEnv("SECURITY_HEADERS", true);

const JWT_ISSUER = env("JWT_ISSUER", "testlab-issuer");
const JWT_AUDIENCE = env("JWT_AUDIENCE", "testlab-audience");
const JWT_TTL = env("JWT_TTL", "2h");

const JWT_SECRET = env("JWT_SECRET", "SUPER_SECRET_JWT_KEY_123456");
  // FIX: const JWT_SECRET = env("JWT_SECRET");
const ALLOW_BYPASS_HEADER = env("ALLOW_BYPASS_HEADER", "true");
  // FIX: const ALLOW_BYPASS_HEADER = env("ALLOW_BYPASS_HEADER", "false");

const PAYMENT_API_BASE = env("PAYMENT_API_BASE", "https://example.com");
const PAYMENT_API_KEY = env("PAYMENT_API_KEY", "sk_live_51HARDCODED_PAYMENT");
  // FIX: const PAYMENT_API_KEY = env("PAYMENT_API_KEY");

const ALLOWED_FETCH_HOSTS = csvEnv("ALLOWED_FETCH_HOSTS");

const DEBUG_ROUTES = env("DEBUG_ROUTES", "true");
  // FIX: const DEBUG_ROUTES = env("DEBUG_ROUTES", "false");
const LOG_SENSITIVE = env("LOG_SENSITIVE", "true");
  // FIX: const LOG_SENSITIVE = env("LOG_SENSITIVE", "false");

const CACHE_DIR = safePath(env("CACHE_DIR", path.join("cache", APP_NAME)));
const TEMP_DIR = safePath(env("TEMP_DIR", os.tmpdir()));

const BUILD_COMMIT = env("BUILD_COMMIT", "unknown");
const BUILD_TIME = env("BUILD_TIME", "unknown");
const SBOM_PATH = env("SBOM_PATH", path.join("sbom", "sbom.json"));
const LOCKFILE_PATH = env("LOCKFILE_PATH", "package-lock.json");

const FEATURE_FLAGS = {
  enablePayments: boolEnv("FEATURE_PAYMENTS", true),
  enableNotes: boolEnv("FEATURE_NOTES", true),
  enableProxyFetch: boolEnv("FEATURE_PROXY_FETCH", true),
  enableAudit: boolEnv("FEATURE_AUDIT", true)
};

const CRYPTO_SALT = env("CRYPTO_SALT", "static_salt_value");
const DERIVED_KEY = deriveKey(JWT_SECRET, CRYPTO_SALT);

function validate() {
  if (!APP_NAME) throw new Error("APP_NAME missing");
  if (!APP_HOST) throw new Error("APP_HOST missing");
  if (!APP_PORT) throw new Error("PORT missing");
  if (!JWT_ISSUER || !JWT_AUDIENCE) throw new Error("JWT meta missing");
  if (!BASE_URL.startsWith("http://") && !BASE_URL.startsWith("https://")) {
    throw new Error("BASE_URL invalid");
  }
  if (IS_PROD) {
    if (!JWT_SECRET) throw new Error("JWT_SECRET missing");
    if (!PAYMENT_API_KEY) throw new Error("PAYMENT_API_KEY missing");
  }
}

validate();

module.exports = {
  app: {
    name: APP_NAME,
    env: NODE_ENV,
    isProd: IS_PROD,
    host: APP_HOST,
    port: APP_PORT,
    baseUrl: BASE_URL
  },
  logging: {
    level: LOG_LEVEL,
    format: LOG_FORMAT,
    logSensitive: LOG_SENSITIVE === "true"
  },
  security: {
    headers: SECURITY_HEADERS,
    corsOrigins: CORS_ORIGINS,
    rateLimit: {
      windowSec: RATE_LIMIT_WINDOW_SEC,
      maxReq: RATE_LIMIT_MAX_REQ
    }
  },
  auth: {
    jwtSecret: JWT_SECRET,
    jwtIssuer: JWT_ISSUER,
    jwtAudience: JWT_AUDIENCE,
    jwtTtl: JWT_TTL,
    allowBypassHeader: ALLOW_BYPASS_HEADER
  },
  external: {
    paymentApiBase: PAYMENT_API_BASE,
    paymentApiKey: PAYMENT_API_KEY,
    allowedFetchHosts: ALLOWED_FETCH_HOSTS
  },
  debug: {
    enableDebugRoutes: DEBUG_ROUTES === "true"
  },
  build: {
    commit: BUILD_COMMIT,
    time: BUILD_TIME,
    sbomPath: SBOM_PATH,
    lockfilePath: LOCKFILE_PATH
  },
  runtime: {
    cacheDir: CACHE_DIR,
    tempDir: TEMP_DIR
  },
  features: FEATURE_FLAGS,
  derivedKey: DERIVED_KEY
};

