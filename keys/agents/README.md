# Agent identity keys

One file per agent: `<AGENT>.pub`. File format = OpenSSH public key
(single line, e.g. `ssh-ed25519 AAAA... comment`). Only ed25519 is
accepted — RSA / ECDSA / DSA keys are rejected by `/api/verify`.

## Bootstrap procedure

On each agent's host:

```bash
# 1. Generate the keypair once per agent
ssh-keygen -t ed25519 -C "<AGENT>@$(hostname)" \
  -f ~/.ssh/ecosystem-<AGENT> -N ""

# 2. Copy the PUBLIC key to this dir on the key-server host
scp ~/.ssh/ecosystem-<AGENT>.pub \
    operator@key-server-host:/opt/ecosystem/key-server/keys/agents/<AGENT>.pub

# 3. Private key stays on the agent's host. Never leaves.
```

Revocation: `rm keys/agents/<AGENT>.pub`. Takes effect immediately —
blocks read the file on every verify, there is no cache.

## Read endpoints

- `GET /api/agents/identity` → list registered agents.
- `GET /api/agents/identity/<AGENT>` →
  `{agent_id, pub_key, fingerprint, registered_at}`.

Both honour the same IP whitelist as the rest of key-server.

## Signing requests

Each agent request to any block carries four headers:

| Header         | Value                                                   |
|----------------|---------------------------------------------------------|
| `X-Agent-Id`   | e.g. `agent1`                                           |
| `X-Timestamp`  | ISO-8601 UTC, `YYYY-MM-DDTHH:MM:SSZ`                    |
| `X-Nonce`      | 16 random bytes, hex-encoded (32 chars)                 |
| `X-Signature`  | base64 of ed25519 signature over the canonical message  |

The **canonical message** is five fields joined by `\n` (literal LF):

```
<METHOD-UPPERCASE>\n<PATH>\n<X-Timestamp>\n<X-Nonce>\nSHA256(body)
```

`SHA256(body)` is hex-encoded. `PATH` is the request path without query
string. For a `GET` with no body, `SHA256("") = e3b0c442...52b855`.

The agent signs those exact bytes with its private key. The target
block POSTs the four fields + `method` + `path` + `body_sha256` to
`/api/verify` and accepts the request only on `{"valid": true}`.

### Signing — Node

```javascript
const crypto = require('crypto');
const sshpk  = require('sshpk');
const fs     = require('fs');

function sign(privPath, method, path, bodyStr) {
  const priv = sshpk.parsePrivateKey(fs.readFileSync(privPath), 'ssh');
  const key  = crypto.createPrivateKey(priv.toString('pkcs8'));
  const ts   = new Date().toISOString().split('.')[0] + 'Z';
  const nonce = crypto.randomBytes(16).toString('hex');
  const bodySha = crypto.createHash('sha256').update(bodyStr).digest('hex');
  const msg  = `${method.toUpperCase()}\n${path}\n${ts}\n${nonce}\n${bodySha}`;
  const sig  = crypto.sign(null, Buffer.from(msg), key).toString('base64');
  return { 'X-Agent-Id': 'agent1', 'X-Timestamp': ts, 'X-Nonce': nonce, 'X-Signature': sig };
}
```

### Signing — Python

```python
import base64, hashlib, secrets
from datetime import datetime, timezone
from cryptography.hazmat.primitives.serialization import load_ssh_private_key

def sign(priv_path, method, path, body_bytes):
    priv = load_ssh_private_key(open(priv_path, 'rb').read(), password=None)
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    nonce = secrets.token_hex(16)
    body_sha = hashlib.sha256(body_bytes).hexdigest()
    msg = f'{method.upper()}\n{path}\n{ts}\n{nonce}\n{body_sha}'.encode('utf-8')
    sig = base64.b64encode(priv.sign(msg)).decode('ascii')
    return {'X-Agent-Id': 'agent1', 'X-Timestamp': ts, 'X-Nonce': nonce, 'X-Signature': sig}
```

### Signing — CLI helper

A ready-made helper lives at `bin/sign-request` (repo root). It is
an executable Node script (reuses the repo's `sshpk` dependency) that
prints the four headers to stdout as curl-ready `-H '...'` lines:

```bash
# GET (no body)
bin/sign-request agent1 GET /api/notes/recent

# POST with inline JSON
bin/sign-request agent1 POST /api/notes '{"title":"hello"}'

# POST with body from file
bin/sign-request agent1 POST /api/notes @/tmp/payload.json
```

Interface: `bin/sign-request <agent> <METHOD> <path> [body|@file]`.
Query strings are stripped from `<path>` before signing (the query
string is not part of the canonical message). By default it reads
the private key from `~/.ssh/ecosystem-<AGENT>`; override with
`AGENT_PRIV_KEY=/path/to/key` (OpenSSH ed25519 key file). Example:

```bash
eval curl -s $(bin/sign-request agent1 GET /keys/list) http://localhost:3040/keys/list
```

## Anti-replay notes

- `X-Timestamp` must be within `[now-300s, now+60s]`. Requests outside
  the window are rejected with `timestamp_out_of_window`.
- Each `X-Nonce` is accepted at most once per 6 minutes (Redis
  `SET NX EX 360` — the TTL covers the full timestamp window of
  300 s back + 60 s forward). Re-using a nonce → `nonce_replayed`.
- Generate a fresh nonce per request (`openssl rand -hex 16` or the
  language-native equivalent). Do **not** seed it from the timestamp.

## Key rotation

Procedure (manual):

```bash
# 1. Generate the new keypair on the agent host.
ssh-keygen -t ed25519 -C "<AGENT>-rot@$(hostname)" \
  -f ~/.ssh/ecosystem-<AGENT>-new -N ""

# 2. Copy the new .pub onto the key-server host under a temporary name.
scp ~/.ssh/ecosystem-<AGENT>-new.pub \
    operator@key-server-host:/opt/ecosystem/key-server/keys/agents/<AGENT>.pub.new

# 3. On the key-server host, promote atomically.
ssh operator@key-server-host \
  'mv /opt/ecosystem/key-server/keys/agents/<AGENT>.pub.new \
      /opt/ecosystem/key-server/keys/agents/<AGENT>.pub'

# 4. Cut agent over to the new private key. Old one can be deleted.
mv ~/.ssh/ecosystem-<AGENT>-new ~/.ssh/ecosystem-<AGENT>
```

There is no "both keys valid for a while" mode — one file, one
key. If you need an overlap window, bootstrap a parallel agent id
(`<AGENT>-next`) and migrate calls, then remove the old one.
