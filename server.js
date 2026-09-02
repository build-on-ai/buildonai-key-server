#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only

const http = require('http');
const fs = require('fs');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');
const sshpk = require('sshpk');
const redis = require('redis');
const { getPort } = require('./middleware/ports');
const { version: PACKAGE_VERSION } = require('./package.json');

const PORT = parseInt(process.env.KEY_SERVER_PORT, 10) || getPort('key-server', 3040);
const HOST = process.env.KEY_SERVER_HOST || '0.0.0.0';
const REDIS_HOST = process.env.REDIS_HOST || '127.0.0.1';
const REDIS_PORT = parseInt(process.env.REDIS_PORT, 10) || getPort('redis', 6379);
const BASE_DIR = __dirname;
const KEYS_DIR = path.join(BASE_DIR, 'keys');
const AUTH_CONFIG = path.join(BASE_DIR, 'auth', 'allowed-clients.json');
const AUDIT_LOG = path.join(BASE_DIR, 'logs', 'audit.log');
const AUDIT_JSONL = path.join(BASE_DIR, 'logs', 'audit.jsonl');

// Without a writable audit directory every request is unlogged; refuse to start.
try {
  fs.mkdirSync(path.dirname(AUDIT_LOG), { recursive: true });
} catch (err) {
  console.error(`FATAL: cannot create audit directory ${path.dirname(AUDIT_LOG)}: ${err.message}`);
  process.exit(1);
}
// Not reused from the shared middleware: key-server is the root of trust and cannot call its own /api/verify.
const SENSITIVE_PREFIXES = ['/keys/'];
const SENSITIVE_EXACT = new Set(['/audit']);

const PUB_KEY_MAX_BYTES = 4 * 1024;
const AUDIT_ROTATE_BYTES = 50 * 1024 * 1024;
const AUDIT_ROTATE_CHECK_EVERY = 100;
const TS_WINDOW_BACK_MS = 300 * 1000;
const TS_WINDOW_FWD_MS = 60 * 1000;
// Must outlive the whole timestamp window, or a request from its forward edge is replayable.
const NONCE_TTL_SECONDS = Math.ceil((TS_WINDOW_BACK_MS + TS_WINDOW_FWD_MS) / 1000);
const NONCE_MIN_HEX = 16;                     // 16 hex chars = 8 bytes of entropy
const NONCE_MAX_HEX = 128;
const SIG_B64_MAX = 256;                      // ed25519 is 64 raw bytes = 88 base64

function log(message, level = 'INFO') {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] [${level}] ${message}`);
}

function auditLog(ip, endpoint, result, details = '') {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] IP=${ip} ENDPOINT=${endpoint} RESULT=${result} ${details}\n`;

  fs.appendFile(AUDIT_LOG, logEntry, (err) => {
    if (err) console.error('Failed to write audit log:', err);
  });

  log(`AUDIT: ${ip} → ${endpoint} → ${result}`, 'AUDIT');
}

function loadAuthConfig() {
  try {
    const data = fs.readFileSync(AUTH_CONFIG, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    // A missing config falls back to loopback-only, so name the fix in the error.
    const hint = (err.code === 'ENOENT' || err.code === 'EISDIR')
      ? ' — run: cp auth/allowed-clients.json.example auth/allowed-clients.json'
      : '';
    log(`Failed to load auth config: ${err.message}${hint}`, 'ERROR');
    log('Falling back to loopback-only allowlist (127.0.0.1, ::1)', 'ERROR');
    return { allowed_ips: ['127.0.0.1', '::1'] };
  }
}

function isIpAllowed(clientIp, allowedRanges) {
  if (clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '::ffff:127.0.0.1') {
    return true;
  }

  for (const range of allowedRanges) {
    if (range.includes('/')) {
      const [base, maskStr] = range.split('/');
      const mask = parseInt(maskStr, 10);
      if (!Number.isInteger(mask)) continue;
      const family = net.isIPv4(base) ? 'ipv4' : net.isIPv6(base) ? 'ipv6' : null;
      if (!family) continue;
      const bl = new net.BlockList();
      bl.addSubnet(base, mask, family);
      const clientFamily = net.isIPv4(clientIp) ? 'ipv4' : 'ipv6';
      if (family === clientFamily && bl.check(clientIp, clientFamily)) return true;
    } else if (clientIp === range) {
      return true;
    }
  }

  return false;
}

function checkIp(req) {
  const authConfig = loadAuthConfig();
  const clientIp = req.socket.remoteAddress;

  if (!isIpAllowed(clientIp, authConfig.allowed_ips)) {
    return { allowed: false, reason: 'IP not whitelisted', ip: clientIp };
  }
  return { allowed: true, ip: clientIp };
}

function isSensitivePath(pathname) {
  if (SENSITIVE_EXACT.has(pathname)) return true;
  for (const prefix of SENSITIVE_PREFIXES) {
    if (pathname.startsWith(prefix)) return true;
  }
  return false;
}

// No CORS headers on purpose: this server dispenses secrets and is never browser-facing.
function sendResponse(res, statusCode, body, contentType = 'application/json') {
  res.writeHead(statusCode, {
    'Content-Type': contentType
  });

  if (contentType === 'application/json') {
    res.end(JSON.stringify(body, null, 2));
  } else {
    res.end(body);
  }
}

// Host allowlist blocks DNS rebinding: rejected before routing, whatever the name resolves to.
const ALLOWED_HOSTS = (process.env.KEY_SERVER_ALLOWED_HOSTS ||
  `localhost:${PORT},127.0.0.1:${PORT},[::1]:${PORT}`)
  .split(',').map((h) => h.trim()).filter(Boolean);

function isHostAllowed(hostHeader) {
  return typeof hostHeader === 'string' && ALLOWED_HOSTS.includes(hostHeader);
}

function handleHealth(req, res, auth) {
  auditLog(auth.ip, '/health', 'OK');
  sendResponse(res, 200, {
    status: 'ok',
    service: 'key-server',
    version: PACKAGE_VERSION,
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
}

function handleGetSshKey(req, res, auth, keyName) {
  const keyPath = path.join(KEYS_DIR, 'ssh', keyName);

  if (keyName.includes('..') || keyName.includes('/')) {
    auditLog(auth.ip, `/keys/ssh/${keyName}`, 'REJECTED', 'path_traversal_attempt');
    sendResponse(res, 400, { error: 'Invalid key name' });
    return;
  }

  if (!fs.existsSync(keyPath)) {
    auditLog(auth.ip, `/keys/ssh/${keyName}`, 'NOT_FOUND');
    sendResponse(res, 404, { error: 'Key not found' });
    return;
  }

  try {
    const keyContent = fs.readFileSync(keyPath, 'utf8');
    auditLog(auth.ip, `/keys/ssh/${keyName}`, 'SUCCESS', `size=${keyContent.length}`);
    sendResponse(res, 200, keyContent, 'text/plain');
  } catch (err) {
    auditLog(auth.ip, `/keys/ssh/${keyName}`, 'ERROR', err.message);
    sendResponse(res, 500, { error: 'Failed to read key' });
  }
}

function handleGetApiKey(req, res, auth, service) {
  const keyPath = path.join(KEYS_DIR, service, 'api-key.txt');

  if (service.includes('..') || service.includes('/')) {
    auditLog(auth.ip, `/keys/api/${service}`, 'REJECTED', 'path_traversal_attempt');
    sendResponse(res, 400, { error: 'Invalid service name' });
    return;
  }

  if (!fs.existsSync(keyPath)) {
    auditLog(auth.ip, `/keys/api/${service}`, 'NOT_FOUND');
    sendResponse(res, 404, { error: 'API key not found' });
    return;
  }

  try {
    const keyContent = fs.readFileSync(keyPath, 'utf8').trim();
    auditLog(auth.ip, `/keys/api/${service}`, 'SUCCESS');
    sendResponse(res, 200, { service, api_key: keyContent });
  } catch (err) {
    auditLog(auth.ip, `/keys/api/${service}`, 'ERROR', err.message);
    sendResponse(res, 500, { error: 'Failed to read API key' });
  }
}

function handleListKeys(req, res, auth) {
  try {
    const sshKeys = fs.readdirSync(path.join(KEYS_DIR, 'ssh'))
      .filter(f => !f.endsWith('.pub'));

    const apiServices = fs.readdirSync(KEYS_DIR)
      .filter(f => f !== 'ssh' && fs.statSync(path.join(KEYS_DIR, f)).isDirectory());

    auditLog(auth.ip, '/keys/list', 'SUCCESS');
    sendResponse(res, 200, {
      ssh_keys: sshKeys,
      api_services: apiServices
    });
  } catch (err) {
    auditLog(auth.ip, '/keys/list', 'ERROR', err.message);
    sendResponse(res, 500, { error: 'Failed to list keys' });
  }
}

// Read on every request, so revoking a key is `rm keys/agents/<AGENT>.pub`.
function loadAgentPubKey(agentId) {
  if (!agentId || agentId.includes('..') || agentId.includes('/')) return null;

  const keyPath = path.join(KEYS_DIR, 'agents', `${agentId}.pub`);
  let stat;
  try {
    stat = fs.statSync(keyPath);
  } catch {
    return null;
  }
  // Reject oversized pub-key files before readFile.
  if (stat.size > PUB_KEY_MAX_BYTES) return null;

  let text;
  try {
    text = fs.readFileSync(keyPath, 'utf8');
  } catch {
    return null;
  }

  try {
    const sshKey = sshpk.parseKey(text, 'ssh');
    if (sshKey.type !== 'ed25519') return null;
    return crypto.createPublicKey(sshKey.toString('pem'));
  } catch {
    return null;
  }
}

// Every signer must reproduce this byte for byte — see docs/SIGNING-PROTOCOL.md.
function buildCanonicalMessage({ method, path: reqPath, timestamp, nonce, body_sha256 }) {
  return [
    String(method || '').toUpperCase(),
    String(reqPath || ''),
    String(timestamp || ''),
    String(nonce || ''),
    String(body_sha256 || '')
  ].join('\n');
}

// Length is checked before crypto.verify so timing does not leak whether the agent exists.
function verifyEd25519({ pubKey, canonicalMessage, signatureB64 }) {
  if (!pubKey) return { valid: false, reason: 'unknown_agent' };
  if (typeof signatureB64 !== 'string' || signatureB64.length === 0 ||
      signatureB64.length > SIG_B64_MAX) {
    return { valid: false, reason: 'bad_signature' };
  }
  let sig;
  try {
    sig = Buffer.from(signatureB64, 'base64');
  } catch {
    return { valid: false, reason: 'bad_signature' };
  }
  if (sig.length !== 64) return { valid: false, reason: 'bad_signature' };

  const msgBytes = Buffer.from(canonicalMessage, 'utf8');
  let ok = false;
  try {
    ok = crypto.verify(null, msgBytes, pubKey, sig);
  } catch {
    return { valid: false, reason: 'bad_signature' };
  }
  return ok ? { valid: true } : { valid: false, reason: 'bad_signature' };
}

let auditWriteCounter = 0;
function appendAuditEntry(entry) {
  const logsDir = path.dirname(AUDIT_JSONL);
  try {
    fs.mkdirSync(logsDir, { recursive: true });
  } catch { }

  auditWriteCounter++;
  if (auditWriteCounter >= AUDIT_ROTATE_CHECK_EVERY) {
    auditWriteCounter = 0;
    try {
      const st = fs.statSync(AUDIT_JSONL);
      if (st.size > AUDIT_ROTATE_BYTES) {
        const ts = new Date().toISOString().replace(/[:.]/g, '-').replace(/Z$/, '');
        const archived = path.join(logsDir, `audit.${ts}.jsonl`);
        fs.renameSync(AUDIT_JSONL, archived);
      }
    } catch { }
  }

  const line = { ts: new Date().toISOString(), ...entry };
  try {
    fs.appendFileSync(AUDIT_JSONL, JSON.stringify(line) + '\n');
  } catch (err) {
    console.error('audit write failed:', err.message);
  }
}

function sshKeyFingerprint(pubKeyText) {
  const parts = pubKeyText.trim().split(/\s+/);
  if (parts.length < 2) return null;
  try {
    const raw = Buffer.from(parts[1], 'base64');
    const hash = crypto.createHash('sha256').update(raw).digest('base64').replace(/=+$/, '');
    return `SHA256:${hash}`;
  } catch {
    return null;
  }
}

function handleGetAgentIdentity(req, res, auth, agentId) {
  if (agentId.includes('..') || agentId.includes('/')) {
    auditLog(auth.ip, `/api/agents/identity/${agentId}`, 'REJECTED', 'path_traversal_attempt');
    sendResponse(res, 400, { error: 'Invalid agent id' });
    return;
  }

  const keyPath = path.join(KEYS_DIR, 'agents', `${agentId}.pub`);
  if (!fs.existsSync(keyPath)) {
    auditLog(auth.ip, `/api/agents/identity/${agentId}`, 'NOT_FOUND');
    sendResponse(res, 404, {
      error: 'Agent identity not registered',
      hint: `Bootstrap: place pub key at keys/agents/${agentId}.pub`
    });
    return;
  }

  try {
    const pubKey = fs.readFileSync(keyPath, 'utf8').trim();
    const stat = fs.statSync(keyPath);
    auditLog(auth.ip, `/api/agents/identity/${agentId}`, 'SUCCESS');
    sendResponse(res, 200, {
      agent_id: agentId,
      pub_key: pubKey,
      fingerprint: sshKeyFingerprint(pubKey),
      registered_at: stat.mtime.toISOString()
    });
  } catch (err) {
    auditLog(auth.ip, `/api/agents/identity/${agentId}`, 'ERROR', err.message);
    sendResponse(res, 500, { error: 'Failed to read agent identity' });
  }
}

function handleListAgentIdentities(req, res, auth) {
  const agentsDir = path.join(KEYS_DIR, 'agents');
  try {
    if (!fs.existsSync(agentsDir)) {
      auditLog(auth.ip, '/api/agents/identity', 'SUCCESS', 'empty');
      sendResponse(res, 200, { agents: [], count: 0 });
      return;
    }
    const agents = fs.readdirSync(agentsDir)
      .filter(f => f.endsWith('.pub'))
      .map(f => f.slice(0, -4))
      .sort();
    auditLog(auth.ip, '/api/agents/identity', 'SUCCESS', `count=${agents.length}`);
    sendResponse(res, 200, { agents, count: agents.length });
  } catch (err) {
    auditLog(auth.ip, '/api/agents/identity', 'ERROR', err.message);
    sendResponse(res, 500, { error: 'Failed to list agent identities' });
  }
}

function handleAudit(req, res, auth) {
  try {
    const logContent = fs.readFileSync(AUDIT_LOG, 'utf8');
    const lines = logContent.split('\n').filter(l => l.trim()).slice(-100);

    auditLog(auth.ip, '/audit', 'SUCCESS');
    sendResponse(res, 200, {
      total_entries: lines.length,
      recent_entries: lines
    });
  } catch (err) {
    if (err.code === 'ENOENT') {
      sendResponse(res, 200, { total_entries: 0, recent_entries: [] });
    } else {
      auditLog(auth.ip, '/audit', 'ERROR', err.message);
      sendResponse(res, 500, { error: 'Failed to read audit log' });
    }
  }
}


const redisClient = redis.createClient({
  socket: { host: REDIS_HOST, port: REDIS_PORT }
});
let redisReady = false;
redisClient.on('ready', () => { redisReady = true; log(`Redis ready at ${REDIS_HOST}:${REDIS_PORT}`); });
redisClient.on('end',   () => { redisReady = false; log('Redis connection ended', 'WARN'); });
redisClient.on('error', (err) => {
  redisReady = false;
  log(`Redis error: ${err.message}`, 'ERROR');
});

function parseBody(req, maxBytes = 16 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (c) => {
      total += c.length;
      if (total > maxBytes) {
        req.destroy();
        reject(new Error('body too large'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function isHex(s) { return typeof s === 'string' && /^[0-9a-fA-F]+$/.test(s); }
function looksIso8601(s) { return typeof s === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(s); }

async function verifySensitiveRequest({ headers, method, path: reqPath, bodyBytes }) {
  const agentId = headers['x-agent-id'];
  const timestamp = headers['x-timestamp'];
  const nonce = headers['x-nonce'];
  const signature = headers['x-signature'];

  if (!agentId || !timestamp || !nonce || !signature) {
    return { valid: false, reason: 'missing_headers' };
  }
  if (typeof agentId !== 'string' || agentId.includes('..') || agentId.includes('/')) {
    return { valid: false, reason: 'bad_agent_id' };
  }
  if (typeof timestamp !== 'string' || !looksIso8601(timestamp)) {
    return { valid: false, reason: 'bad_timestamp' };
  }
  if (typeof nonce !== 'string' || !isHex(nonce) ||
      nonce.length < NONCE_MIN_HEX || nonce.length > NONCE_MAX_HEX) {
    return { valid: false, reason: 'bad_nonce' };
  }
  if (typeof signature !== 'string' || signature.length === 0 || signature.length > SIG_B64_MAX) {
    return { valid: false, reason: 'bad_signature' };
  }

  const ts = Date.parse(timestamp);
  if (!Number.isFinite(ts)) return { valid: false, reason: 'timestamp_out_of_window' };
  const now = Date.now();
  if (ts < now - TS_WINDOW_BACK_MS || ts > now + TS_WINDOW_FWD_MS) {
    return { valid: false, reason: 'timestamp_out_of_window' };
  }

  // Anti-replay needs Redis: halt, never skip.
  if (!redisReady) return { valid: false, reason: 'redis_unavailable', status: 503 };

  const nonceKey = `ks:nonce_seen:${nonce}`;
  let claimed;
  try {
    claimed = await redisClient.set(nonceKey, '1', { NX: true, EX: NONCE_TTL_SECONDS });
  } catch {
    return { valid: false, reason: 'redis_error', status: 503 };
  }
  if (claimed === null) return { valid: false, reason: 'nonce_replayed' };

  const pubKey = loadAgentPubKey(agentId);
  if (!pubKey) return { valid: false, reason: 'unknown_agent' };

  const bodySha256 = crypto.createHash('sha256').update(bodyBytes || Buffer.alloc(0)).digest('hex');
  const canonicalMessage = buildCanonicalMessage({
    method, path: reqPath, timestamp, nonce, body_sha256: bodySha256
  });
  const verdict = verifyEd25519({ pubKey, canonicalMessage, signatureB64: signature });
  if (!verdict.valid) return { valid: false, reason: verdict.reason || 'bad_signature' };

  return { valid: true, agent_id: agentId };
}

function readRequestBody(req, maxBytes = 16 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (c) => {
      total += c.length;
      if (total > maxBytes) {
        req.destroy();
        reject(new Error('body too large'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function handleVerify(req, res, auth) {
  let raw;
  try {
    raw = await parseBody(req);
  } catch (err) {
    sendResponse(res, 400, { error: 'bad_request', reason: err.message });
    return;
  }

  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    sendResponse(res, 400, { error: 'bad_request', reason: 'invalid_json' });
    return;
  }

  const { agent_id, timestamp, nonce, method, path: reqPath, body_sha256, signature } = body || {};

  if (typeof agent_id !== 'string'    || agent_id.length === 0 ||
      typeof method !== 'string'      || method.length === 0 ||
      typeof reqPath !== 'string'     || reqPath.length === 0 ||
      typeof timestamp !== 'string'   || !looksIso8601(timestamp) ||
      typeof nonce !== 'string'       || !isHex(nonce) ||
      nonce.length < NONCE_MIN_HEX    || nonce.length > NONCE_MAX_HEX ||
      typeof body_sha256 !== 'string' || !isHex(body_sha256) || body_sha256.length !== 64 ||
      typeof signature !== 'string'   || signature.length === 0 || signature.length > SIG_B64_MAX) {
    sendResponse(res, 400, { error: 'bad_request', reason: 'missing_or_invalid_fields' });
    return;
  }

  const respondFail = (reason) => {
    appendAuditEntry({
      event: 'verify', agent_id, method, path: reqPath,
      result: 'fail', reason, ip: auth.ip
    });
    sendResponse(res, 401, { valid: false, reason });
  };

  const ts = Date.parse(timestamp);
  if (!Number.isFinite(ts)) {
    respondFail('timestamp_out_of_window');
    return;
  }
  const now = Date.now();
  if (ts < now - TS_WINDOW_BACK_MS || ts > now + TS_WINDOW_FWD_MS) {
    respondFail('timestamp_out_of_window');
    return;
  }

  // Anti-replay needs Redis: halt, never skip.
  if (!redisReady) {
    appendAuditEntry({
      event: 'verify', agent_id, method, path: reqPath,
      result: 'error', reason: 'redis_unavailable', ip: auth.ip
    });
    sendResponse(res, 503, { error: 'service_unavailable', reason: 'redis_unavailable' });
    return;
  }

  const nonceKey = `ks:nonce_seen:${nonce}`;
  let claimed;
  try {
    claimed = await redisClient.set(nonceKey, '1', { NX: true, EX: NONCE_TTL_SECONDS });
  } catch (err) {
    appendAuditEntry({
      event: 'verify', agent_id, method, path: reqPath,
      result: 'error', reason: 'redis_error', ip: auth.ip
    });
    sendResponse(res, 503, { error: 'service_unavailable', reason: 'redis_error' });
    return;
  }
  if (claimed === null) {
    respondFail('nonce_replayed');
    return;
  }

  const pubKey = loadAgentPubKey(agent_id);
  if (!pubKey) {
    respondFail('unknown_agent');
    return;
  }

  const canonicalMessage = buildCanonicalMessage({
    method, path: reqPath, timestamp, nonce, body_sha256
  });
  const verdict = verifyEd25519({ pubKey, canonicalMessage, signatureB64: signature });
  if (!verdict.valid) {
    respondFail(verdict.reason || 'bad_signature');
    return;
  }

  appendAuditEntry({
    event: 'verify', agent_id, method, path: reqPath,
    result: 'ok', ip: auth.ip
  });
  sendResponse(res, 200, { valid: true, agent_id });
}

function dispatch(req, res, auth, pathname) {
  if (pathname === '/health') {
    handleHealth(req, res, auth);
  } else if (pathname === '/keys/list') {
    handleListKeys(req, res, auth);
  } else if (pathname === '/audit') {
    handleAudit(req, res, auth);
  } else if (pathname.startsWith('/keys/ssh/')) {
    const keyName = pathname.split('/keys/ssh/')[1];
    handleGetSshKey(req, res, auth, keyName);
  } else if (pathname.startsWith('/keys/api/')) {
    const service = pathname.split('/keys/api/')[1];
    handleGetApiKey(req, res, auth, service);
  } else if (pathname === '/api/agents/identity' || pathname === '/api/agents/identity/') {
    handleListAgentIdentities(req, res, auth);
  } else if (pathname.startsWith('/api/agents/identity/')) {
    const agentId = pathname.split('/api/agents/identity/')[1];
    handleGetAgentIdentity(req, res, auth, agentId);
  } else if (pathname === '/api/verify' && req.method === 'POST') {
    handleVerify(req, res, auth).catch((err) => {
      log(`verify handler crash: ${err.message}`, 'ERROR');
      try { sendResponse(res, 500, { error: 'internal_error' }); } catch { }
    });
  } else {
    auditLog(auth.ip, pathname, 'NOT_FOUND');
    sendResponse(res, 404, { error: 'Endpoint not found' });
  }
}

async function handleRequest(req, res) {
  if (!isHostAllowed(req.headers.host)) {
    log(`Rejected request with disallowed Host header: ${req.headers.host}`, 'WARN');
    sendResponse(res, 403, { error: 'Forbidden', reason: 'invalid_host' });
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  log(`${req.method} ${pathname} from ${req.socket.remoteAddress}`);

  if (req.method === 'OPTIONS') {
    sendResponse(res, 200, {});
    return;
  }

  const auth = checkIp(req);
  if (!auth.allowed) {
    auditLog(auth.ip, pathname, 'FORBIDDEN', auth.reason);
    sendResponse(res, 403, { error: 'Forbidden', reason: auth.reason });
    return;
  }

  if (isSensitivePath(pathname)) {
    let bodyBytes;
    try {
      bodyBytes = await readRequestBody(req);
    } catch (err) {
      sendResponse(res, 400, { error: 'bad_request', reason: err.message });
      return;
    }

    const verdict = await verifySensitiveRequest({
      headers: req.headers,
      method: req.method,
      path: pathname,
      bodyBytes,
    });

    if (!verdict.valid) {
      const status = verdict.status || 401;
      auditLog(auth.ip, pathname, 'UNAUTHORIZED', verdict.reason);
      appendAuditEntry({
        event: 'sensitive_gate', method: req.method, path: pathname,
        result: 'fail', reason: verdict.reason, ip: auth.ip,
        agent_id: req.headers['x-agent-id'] || null,
      });
      sendResponse(res, status, { error: 'unauthorized', reason: verdict.reason });
      return;
    } else {
      auth.agent_id = verdict.agent_id;
      appendAuditEntry({
        event: 'sensitive_gate', method: req.method, path: pathname,
        result: 'ok', ip: auth.ip, agent_id: verdict.agent_id,
      });
    }
  }

  dispatch(req, res, auth, pathname);
}

const server = http.createServer((req, res) => {
  handleRequest(req, res).catch((err) => {
    log(`unhandled request error: ${err.message}`, 'ERROR');
    try { sendResponse(res, 500, { error: 'internal_error' }); } catch { }
  });
});

(async () => {
  try {
    await redisClient.connect();
  } catch (err) {
    log(`Initial Redis connect failed: ${err.message} (will retry in background)`, 'WARN');
  }
})();

server.listen(PORT, HOST, () => {
  log(`🔐 Key Server started on ${HOST}:${PORT}`);
  log(`📁 Keys directory: ${KEYS_DIR}`);
  log(`🔒 Auth config: ${AUTH_CONFIG}`);
  log(`🛂 Signed-request gate: ${[...SENSITIVE_PREFIXES, ...SENSITIVE_EXACT].join(', ')}`);
  log(`📝 Audit log: ${AUDIT_LOG}`);
  log(`📝 Audit JSONL: ${AUDIT_JSONL}`);
  log(`🧠 Redis: ${REDIS_HOST}:${REDIS_PORT}`);
  log('');
  log('Available endpoints:');
  log('  GET  /health                      - Server health check');
  log('  GET  /keys/list                   - List available keys');
  log('  GET  /keys/ssh/:name              - Get SSH private key');
  log('  GET  /keys/api/:service           - Get API key for service');
  log('  GET  /audit                       - View audit log (last 100 entries)');
  log('  GET  /api/agents/identity         - List registered agent identities');
  log('  GET  /api/agents/identity/:id     - Get one agent identity');
  log('  POST /api/verify                  - Verify signed request');
  log('');
  log('🚀 Ready to serve keys!');
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    log(`Port ${PORT} is already in use`, 'ERROR');
  } else {
    log(`Server error: ${err.message}`, 'ERROR');
  }
  process.exit(1);
});

async function shutdown(signal) {
  log(`${signal} received, shutting down gracefully...`, 'INFO');
  server.close(() => log('Server closed', 'INFO'));
  try { await redisClient.quit(); } catch { }
  setTimeout(() => process.exit(0), 200).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
