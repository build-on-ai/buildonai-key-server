# Signing protocol

How an agent proves its identity to a block, and how a block decides
whether to trust the request. This is the authoritative reference
for writing a custom client or a non-standard block.

## Overview

Every request an agent sends to a gated endpoint carries four HTTP
headers. The block does not decide on its own whether the request is
authentic — it forwards the four headers plus a hash of the body to
`key-server`'s `POST /api/verify`. Key-server replies yes or no. The
block acts on that verdict:

An invalid verdict means the request is rejected with `401`.

Key-server itself has no opinion
about what blocks do with its verdict; it only answers whether the
signature checks out.

## Request headers

Four headers on every signed request:

| Header | Value | Purpose |
|---|---|---|
| `X-Agent-Id` | e.g. `agent1` | Which agent is calling |
| `X-Timestamp` | ISO 8601 UTC, e.g. `2026-04-19T22:00:00Z` | Anti-replay window |
| `X-Nonce` | 32 hex chars of random | Anti-replay (unique per request) |
| `X-Signature` | base64 of 64-byte ed25519 signature | Proof of identity |

## Canonical message

Agent, block, and key-server must all reconstruct the **same bytes**
to sign and verify. The canonical message is five fields joined by a
single `\n` (LF):

```
<METHOD>\n<PATH>\n<X-Timestamp>\n<X-Nonce>\nSHA256(body)
```

Example for `POST /api/notes` with body `{"title":"x"}`:

```
POST
/api/notes
2026-04-19T22:00:00Z
abc123def456...
sha256-of-body-bytes-as-hex...
```

Rules:

- Separator is exactly `\n`, not `\r\n`.
- Method is uppercased (`POST`, not `post`).
- Path is without query string (`/api/notes`, not `/api/notes?x=1`).
  Query string is not part of the signature in this version.
- Body is the raw bytes of the request body, **before** any JSON
  parsing. For a `GET` with no body the body is the empty string;
  `sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- SHA-256 is hex-encoded (64 lowercase chars), not base64.

The agent signs those exact bytes with its private ed25519 key. The
block forwards method, path, timestamp, nonce, `body_sha256`, and
the signature to key-server, which rebuilds the same message a third
time and verifies.

Three independent reconstructions — if any of the three produces a
different byte string, `verify` fails with `bad_signature`. That is
why the rules above are explicit and minimal.

## Crypto

- **Algorithm:** ed25519 only. Not RSA, not ECDSA. Matches OpenSSH
  defaults for new keypairs and Node 20's native `crypto.verify`.
- **Signature:** 64 raw bytes, base64-encoded on the wire.
- **Public-key format on disk:** OpenSSH, e.g. the content of
  `~/.ssh/id_ed25519.pub` — one line starting with `ssh-ed25519`.
- **Key-server converts** the OpenSSH format to PEM internally using
  `sshpk` (npm). Custom implementations can do the same with 32 raw
  bytes of the public key wrapped in the standard SPKI DER prefix
  for ed25519.
- **Constant-time:** `crypto.verify` is CT at the OpenSSL level.
  Implementations should do length checks on signature and nonce
  *before* calling verify so the code path is identical whether the
  agent exists or not. Revealing that an agent exists is itself a
  minor information leak.

## Anti-replay

Two independent checks, both on key-server:

1. **Timestamp window.** A request with `X-Timestamp` older than 300s
   or more than 60s in the future is rejected with
   `timestamp_out_of_window`. Back-window is wider than forward-
   window because network/queue delay is common; future-window is
   tight because clock skew above 60s is a host-level issue worth
   fixing.
2. **Nonce cache.** Every nonce is stored in Redis for 360s
   using `SET ks:nonce_seen:<nonce> 1 NX EX 360` — an atomic
   set-if-not-exists with TTL. The atomic form is what makes the
   check safe against concurrent requests: if `SET NX` reports the
   key already existed, the nonce has been seen and we return
   `nonce_replayed`. A repeat of the same `X-Nonce` within the
   window is rejected.
   The TTL is 360s, not 300s, because it must outlive the **full**
   timestamp acceptance window (300s back + 60s forward = 360s).
   A request timestamped near the forward edge stays timestamp-valid
   for up to 360s of wall-clock time; if the nonce expired sooner,
   it could be replayed after nonce expiry but before its timestamp
   goes stale.

Together: every request is effective exactly once, inside the
timestamp acceptance window.

## The `POST /api/verify` endpoint

Blocks call this on key-server for every gated request. JSON request,
JSON response.

**Request:**

```json
{
  "agent_id": "agent1",
  "timestamp": "2026-04-19T22:00:00Z",
  "nonce": "abc123def456...",
  "method": "POST",
  "path": "/api/notes",
  "body_sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
  "signature": "<base64 of 64-byte ed25519 signature>"
}
```

**Responses:**

`200` on success:

```json
{ "valid": true, "agent_id": "agent1" }
```

`401` on failure, with one of four reason codes:

```json
{
  "valid": false,
  "reason": "bad_signature"
          | "unknown_agent"
          | "timestamp_out_of_window"
          | "nonce_replayed"
}
```

`400` only if the verify request itself is structurally malformed:
missing field, wrong type, nonce or `body_sha256` not hex, wrong
`body_sha256` length, signature missing/empty or longer than the
size cap. Note that a well-formed base64 string that is simply not a
valid signature (wrong bytes, wrong decoded length) is **not** a
`400` — it fails signature verification and comes back as
`401 bad_signature`. The `400`/`401` split lets clients tell "my
request shape is wrong" from "my signature/keys are wrong".

Performance target: under 1 ms on localhost. Every operation is
O(1): one Redis lookup, one file read (public key, cached by OS),
one `crypto.verify` call.

## Side effects

Key-server writes two things per verify call:

- `SET ks:nonce_seen:<nonce> 1 NX EX 360` — Redis, for anti-replay.
  The nonce is claimed **before** the signature is verified, so a
  nonce is burned even when the request is ultimately rejected
  (e.g. `unknown_agent`, `bad_signature`). Failed attempts cannot be
  retried with the same nonce.
- One line to `logs/audit.jsonl` — `{ts, event:"verify", agent_id,
  method, path, result, ip}` (the timestamp field is named `ts`).
  Written on failure as well as success (`result: "fail"` carries a
  `reason` field). The file self-rotates at 50 MB
  (`AUDIT_ROTATE_BYTES` in `server.js`) — no external log-rotation
  dependency, consistent with SECURITY.md.

## Signing example — Node

```javascript
import crypto from 'crypto';
import fs from 'fs';

const privKey = crypto.createPrivateKey(
  fs.readFileSync('~/.ssh/agent1_ed25519')
);

const ts = new Date().toISOString();
const nonce = crypto.randomBytes(16).toString('hex');
const body = JSON.stringify({ title: 'hello' });
const bodyHash = crypto.createHash('sha256').update(body).digest('hex');

const canonicalMessage =
  `POST\n/api/notes\n${ts}\n${nonce}\n${bodyHash}`;

const sig = crypto
  .sign(null, Buffer.from(canonicalMessage), privKey)
  .toString('base64');

await fetch('http://consciousness-server:3032/api/notes', {
  method: 'POST',
  headers: {
    'X-Agent-Id': 'agent1',
    'X-Timestamp': ts,
    'X-Nonce': nonce,
    'X-Signature': sig,
    'Content-Type': 'application/json',
  },
  body,
});
```

## Signing example — Python

```python
import base64, hashlib, secrets
from datetime import datetime, timezone
from cryptography.hazmat.primitives.serialization import load_ssh_private_key

priv = load_ssh_private_key(
    open('agent1_ed25519', 'rb').read(),
    password=None,
)

ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
nonce = secrets.token_hex(16)
body = b'{"title":"hello"}'
body_hash = hashlib.sha256(body).hexdigest()

canonical_message = f'POST\n/api/notes\n{ts}\n{nonce}\n{body_hash}'.encode()
sig = base64.b64encode(priv.sign(canonical_message)).decode()

headers = {
    'X-Agent-Id': 'agent1',
    'X-Timestamp': ts,
    'X-Nonce': nonce,
    'X-Signature': sig,
    'Content-Type': 'application/json',
}
# requests.post('http://consciousness-server:3032/api/notes',
#               headers=headers, data=body)
```

## CLI helper

`bin/sign-request` (a Node script in this repo, executable directly)
wraps the snippet above so you don't have to paste it into every
script:

```bash
# Private key path from $AGENT_PRIV_KEY, or ~/.ssh/ecosystem-<agent> by default
AGENT_PRIV_KEY=~/.ssh/buildonai-agent1 \
  bin/sign-request agent1 POST /api/notes '{"title":"hello"}'
# prints the four X-* headers as curl-ready -H '...' lines
```

Full usage (body from file, GET without body) is documented in
[`keys/agents/README.md`](../keys/agents/README.md).

## Design decisions worth knowing

**Why sign `SHA256(body)` and not the body itself?** Body may be
megabytes (uploads, embedded attachments). A 32-byte hash gives
constant-size canonical messages. ed25519 hashes its input anyway
(SHA-512 internally), so pre-hashing costs nothing and simplifies
streaming.

**Why not include query string?** Most mutations are POST/PATCH with
a body. Secrets in `GET ?token=...` are a URL-logging hazard
regardless of signing. If a future version adds query-string signing,
it will be a separate capability negotiated per agent.

**Why only ed25519?** Current agents all use ed25519. RSA would add
~100 lines of padding and key-size handling. ECDSA has weaker
constant-time properties. Extending to additional algorithms is a
minor change but intentionally deferred until a real caller needs it.

**Why halt rather than fail-open when key-server is down?** In
`enforce` mode, blocks return `503 service_unavailable` if they
cannot reach key-server. Fail-open would let a compromised key-server
(or a DoS that silences it) silently de-authenticate the entire
ecosystem. Operators who cannot tolerate downtime during a key-server
outage flip blocks back to `off` or `observe` — a per-block compose
restart, about 10 seconds each.
