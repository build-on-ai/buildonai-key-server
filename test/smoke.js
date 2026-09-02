#!/usr/bin/env node
// Requires Redis on REDIS_HOST:REDIS_PORT (default 127.0.0.1:6379).

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const sshpk = require('sshpk');

const REPO_ROOT = path.resolve(__dirname, '..');
const SERVER_FILE = path.join(REPO_ROOT, 'server.js');

let failed = 0;
let passed = 0;

function assert(cond, name, detail = '') {
  if (cond) {
    passed += 1;
    console.log(`  ok   ${name}`);
  } else {
    failed += 1;
    console.log(`  FAIL ${name}${detail ? ' — ' + detail : ''}`);
  }
}

function request(port, method, urlPath, headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const opts = { host: '127.0.0.1', port, method, path: urlPath, headers: { ...headers } };
    if (body !== null) {
      opts.headers['Content-Length'] = Buffer.byteLength(body);
      if (!opts.headers['Content-Type']) opts.headers['Content-Type'] = 'application/json';
    }
    const req = http.request(opts, (res) => {
      let buf = '';
      res.on('data', (c) => { buf += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: buf }));
    });
    req.on('error', reject);
    if (body !== null) req.write(body);
    req.end();
  });
}

function waitForPort(port, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tick = async () => {
      try {
        const r = await request(port, 'GET', '/health');
        if (r.status === 200) return resolve();
      } catch (_) { /* not up yet */ }
      if (Date.now() > deadline) return reject(new Error(`server did not bind on port ${port} within ${timeoutMs}ms`));
      setTimeout(tick, 100);
    };
    tick();
  });
}

function buildCanonical({ method, path: reqPath, timestamp, nonce, bodyBytes }) {
  const bodySha = crypto.createHash('sha256').update(bodyBytes).digest('hex');
  return [method.toUpperCase(), reqPath, timestamp, nonce, bodySha].join('\n');
}

function signEd25519(privKeyPem, canonical) {
  return crypto.sign(null, Buffer.from(canonical, 'utf8'), privKeyPem).toString('base64');
}

async function main() {
  // 1. Temp BASE_DIR with one agent key registered
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'buildonai-key-server-smoke-'));
  fs.mkdirSync(path.join(tmp, 'keys', 'agents'), { recursive: true });
  fs.mkdirSync(path.join(tmp, 'keys', 'ssh'), { recursive: true }); // /keys/list reads this dir
  fs.mkdirSync(path.join(tmp, 'logs'), { recursive: true });
  fs.mkdirSync(path.join(tmp, 'auth'), { recursive: true });

  // Allow loopback
  fs.writeFileSync(
    path.join(tmp, 'auth', 'allowed-clients.json'),
    JSON.stringify({ allowed_ips: ['127.0.0.1', '::1'] }, null, 2)
  );

  // Generate an ed25519 keypair for agent "smoke"
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const sshpkPub = sshpk.parseKey(publicKey.export({ format: 'pem', type: 'spki' }), 'pem');
  const sshPub = sshpkPub.toString('ssh') + ' smoke@test\n';
  fs.writeFileSync(path.join(tmp, 'keys', 'agents', 'smoke.pub'), sshPub);

  // 2. Spawn server
  const port = 30000 + Math.floor(Math.random() * 5000);
  const env = {
    ...process.env,
    KEY_SERVER_PORT: String(port),
    KEY_SERVER_HOST: '127.0.0.1',
    REDIS_HOST: process.env.REDIS_HOST || '127.0.0.1',
    REDIS_PORT: process.env.REDIS_PORT || '6379',
  };

  // Override BASE_DIR by cd'ing into the tmp tree (server.js resolves keys/, logs/, auth/ relative to __dirname).
  // We copy server.js into tmp so BASE_DIR = tmp.
  fs.copyFileSync(SERVER_FILE, path.join(tmp, 'server.js'));
  fs.copyFileSync(path.join(REPO_ROOT, 'package.json'), path.join(tmp, 'package.json'));
  fs.cpSync(path.join(REPO_ROOT, 'middleware'), path.join(tmp, 'middleware'), { recursive: true });
  // Symlink node_modules so the spawned server can resolve `redis` and `sshpk`.
  fs.symlinkSync(path.join(REPO_ROOT, 'node_modules'), path.join(tmp, 'node_modules'));

  const child = spawn(process.execPath, ['server.js'], { cwd: tmp, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let child2 = null;
  let serverOutput = '';
  child.stdout.on('data', (c) => { serverOutput += c.toString(); });
  child.stderr.on('data', (c) => { serverOutput += c.toString(); });

  try {
    await waitForPort(port);

    // 3. /health
    let r = await request(port, 'GET', '/health');
    assert(r.status === 200, 'GET /health → 200', `got ${r.status}`);

    // 4. /api/agents/identity — should list "smoke"
    r = await request(port, 'GET', '/api/agents/identity');
    assert(r.status === 200, 'GET /api/agents/identity → 200', `got ${r.status}`);
    let parsed;
    try { parsed = JSON.parse(r.body); } catch (_) { parsed = null; }
    assert(parsed && Array.isArray(parsed.agents) && parsed.agents.includes('smoke'),
      'GET /api/agents/identity lists "smoke"', `body=${r.body.slice(0, 200)}`);

    // 5. Valid signed-request round-trip via /api/verify
    const verifyPath = '/api/notes/create';
    const verifyMethod = 'POST';
    const reqBody = JSON.stringify({ title: 'smoke' });
    const ts = new Date().toISOString().split('.')[0] + 'Z';
    const nonce = crypto.randomBytes(16).toString('hex');
    const canonical = buildCanonical({
      method: verifyMethod, path: verifyPath, timestamp: ts, nonce,
      bodyBytes: Buffer.from(reqBody, 'utf8'),
    });
    const sig = signEd25519(privateKey, canonical);

    const verifyPayload = JSON.stringify({
      agent_id: 'smoke',
      method: verifyMethod,
      path: verifyPath,
      timestamp: ts,
      nonce,
      signature: sig,
      body_sha256: crypto.createHash('sha256').update(reqBody).digest('hex'),
    });
    r = await request(port, 'POST', '/api/verify', { 'Content-Type': 'application/json' }, verifyPayload);
    let v;
    try { v = JSON.parse(r.body); } catch (_) { v = null; }
    assert(r.status === 200 && v && v.valid === true,
      'POST /api/verify with valid signature → {valid: true}',
      `status=${r.status} body=${r.body.slice(0, 200)}`);

    // 6. Replay: resend the exact same payload → nonce_replayed
    r = await request(port, 'POST', '/api/verify', { 'Content-Type': 'application/json' }, verifyPayload);
    try { v = JSON.parse(r.body); } catch (_) { v = null; }
    assert(r.status === 401 && v && v.valid === false && v.reason === 'nonce_replayed',
      'POST /api/verify rejects replayed nonce', `status=${r.status} body=${r.body.slice(0, 200)}`);

    // 7. Tamper: fresh nonce, but body sha differs from what was signed → bad_signature
    const tamperNonce = crypto.randomBytes(16).toString('hex');
    const tamperCanonical = buildCanonical({
      method: verifyMethod, path: verifyPath, timestamp: ts, nonce: tamperNonce,
      bodyBytes: Buffer.from(reqBody, 'utf8'),
    });
    const tamperedPayload = JSON.parse(verifyPayload);
    tamperedPayload.nonce = tamperNonce;
    tamperedPayload.signature = signEd25519(privateKey, tamperCanonical);
    tamperedPayload.body_sha256 = crypto.createHash('sha256').update('different body').digest('hex');
    r = await request(port, 'POST', '/api/verify', { 'Content-Type': 'application/json' }, JSON.stringify(tamperedPayload));
    try { v = JSON.parse(r.body); } catch (_) { v = null; }
    assert(v && v.valid === false && v.reason === 'bad_signature',
      'POST /api/verify rejects tampered body_sha256', `body=${r.body.slice(0, 200)}`);

    // 8. Unknown agent (fresh nonce) → unknown_agent
    const unknownPayload = JSON.parse(verifyPayload);
    unknownPayload.agent_id = 'does-not-exist';
    unknownPayload.nonce = crypto.randomBytes(16).toString('hex');
    r = await request(port, 'POST', '/api/verify', { 'Content-Type': 'application/json' }, JSON.stringify(unknownPayload));
    try { v = JSON.parse(r.body); } catch (_) { v = null; }
    assert(v && v.valid === false && v.reason === 'unknown_agent',
      'POST /api/verify rejects unknown agent', `body=${r.body.slice(0, 200)}`);

    // 9. Expired timestamp → reject
    const oldTs = new Date(Date.now() - 10 * 60 * 1000).toISOString().split('.')[0] + 'Z';
    const oldNonce = crypto.randomBytes(16).toString('hex');
    const oldCanonical = buildCanonical({
      method: verifyMethod, path: verifyPath, timestamp: oldTs, nonce: oldNonce,
      bodyBytes: Buffer.from(reqBody, 'utf8'),
    });
    const oldSig = signEd25519(privateKey, oldCanonical);
    const oldPayload = JSON.stringify({
      agent_id: 'smoke', method: verifyMethod, path: verifyPath,
      timestamp: oldTs, nonce: oldNonce, signature: oldSig,
      body_sha256: crypto.createHash('sha256').update(reqBody).digest('hex'),
    });
    r = await request(port, 'POST', '/api/verify', { 'Content-Type': 'application/json' }, oldPayload);
    try { v = JSON.parse(r.body); } catch (_) { v = null; }
    assert(v && v.valid === false, 'POST /api/verify rejects expired timestamp', `body=${r.body.slice(0, 200)}`);

    // 10. Sensitive-endpoint gate on a second instance.
    const port2 = port + 1;
    child2 = spawn(process.execPath, ['server.js'], {
      cwd: tmp,
      env: { ...env, KEY_SERVER_PORT: String(port2) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child2.stdout.on('data', (c) => { serverOutput += c.toString(); });
    child2.stderr.on('data', (c) => { serverOutput += c.toString(); });
    await waitForPort(port2);

    // 10a. Unsigned request to a sensitive endpoint → 401
    r = await request(port2, 'GET', '/keys/list');
    assert(r.status === 401, 'enforce: GET /keys/list without signature → 401', `got ${r.status} body=${r.body.slice(0, 200)}`);

    // 10b. Correctly signed request → 200
    const ts2 = new Date().toISOString().split('.')[0] + 'Z';
    const nonce2 = crypto.randomBytes(16).toString('hex');
    const canonical2 = buildCanonical({
      method: 'GET', path: '/keys/list', timestamp: ts2, nonce: nonce2,
      bodyBytes: Buffer.alloc(0),
    });
    r = await request(port2, 'GET', '/keys/list', {
      'X-Agent-Id': 'smoke',
      'X-Timestamp': ts2,
      'X-Nonce': nonce2,
      'X-Signature': signEd25519(privateKey, canonical2),
    });
    assert(r.status === 200, 'enforce: GET /keys/list with valid signature → 200', `got ${r.status} body=${r.body.slice(0, 200)}`);

  } finally {
    child.kill('SIGTERM');
    setTimeout(() => child.kill('SIGKILL'), 500);
    if (child2) {
      child2.kill('SIGTERM');
      setTimeout(() => child2.kill('SIGKILL'), 500);
    }
    if (failed > 0) {
      console.log('\n--- server output (last 2000 chars) ---');
      console.log(serverOutput.slice(-2000));
    }
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('Smoke test crashed:', err);
  process.exit(1);
});
