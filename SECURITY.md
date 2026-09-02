# Security

buildonai-key-server provides two related but independent functions:

1. **ed25519 signature-per-request verification** — `POST /api/verify`. Stateless. The server holds a public key per agent and checks that each request is signed by the matching private key. No sessions, no bearer tokens, no token issuance.
2. **Optional on-disk vault** for SSH keys and API tokens, served over HTTP to IP-allow-listed callers — `GET /keys/ssh/<name>`, `GET /keys/api/<service>`.

The two layers compose. The vault inherits the same trust model as `/api/verify`: with a signed request, vault reads require both the IP allow-list and a valid ed25519 signature.

## Threat model

**Intended deployment.** Single host, trusted LAN or VPN. Not exposed directly to the public internet. The operator owns the host, the filesystem, and the set of callers that can reach port 3040.

**Defended against:**

- An attacker on the same LAN replaying captured requests (nonce + timestamp window).
- An attacker forging requests from a foreign host (IP allow-list).
- DNS rebinding: the `Host:` header must match the `KEY_SERVER_ALLOWED_HOSTS` allowlist (default: loopback names only) or the request is rejected with 403 before routing.
- An attacker who reads a body once and tries to send it to a different endpoint (canonical message binds method + path + body hash).
- A compromised agent whose private key is now in attacker hands — **only when** you remove the corresponding `keys/agents/<AGENT>.pub` file. Revocation takes effect immediately because the server re-reads the pub key on every verify.
- Accidental commit of secrets: the shipped `.gitignore` excludes everything under `keys/` and `logs/` wholesale (only the READMEs and empty `.gitkeep` placeholders are re-included) plus the real `auth/allowed-clients.json` (only the `.example` ships).

**NOT defended against (deliberate scope):**

- Network eavesdropping on the request body. ed25519 is a signature scheme, not encryption. Wrap the server behind TLS (Caddy, nginx) if requests carry sensitive payloads.
- An attacker with root on the host. They can read private keys, the pub-key vault, the audit log, and `auth/allowed-clients.json` directly from disk.
- An attacker who steals the operator's own SSH key and adds their public key to `keys/agents/`. The server cannot tell a malicious admin commit from a legitimate one — that's what `git log` is for.
- Cryptographic break of ed25519. We trust Node's `crypto.verify` for `ed25519` and the Edwards-curve construction.
- High-volume DoS on `/api/verify`. The server rate-limits nothing; put it behind a reverse proxy if untrusted callers can reach it.

## What the server holds

| Kind | Path | Authorisation to read |
|---|---|---|
| Per-agent public keys | `keys/agents/<AGENT>.pub` | Readable via `GET /api/agents/identity` behind the IP + Host allow-lists, no signature required (intentional — public keys are not secret) |
| SSH private keys | `keys/ssh/<name>` | IP allow-list + ed25519 signature |
| API tokens | `keys/<service>/api-key.txt` | IP allow-list + ed25519 signature |
| Audit log | `logs/audit.log` and `logs/audit.jsonl` | Only `logs/audit.log` is served over HTTP, via `GET /audit` (last 100 entries): IP allow-list + ed25519 signature. `logs/audit.jsonl` is never served — disk access only. |

The plaintext audit log is **exposed over HTTP** at `GET /audit` to any allow-listed caller (and, with a signed request, only to callers presenting a valid ed25519 signature — `/audit` is on the sensitive-endpoint list alongside `/keys/*`). It contains IPs, endpoints, results, and response sizes — treat it as observable metadata, not as a private record. If you want operator-only access, drop the route behind a reverse proxy or remove the handler from `server.js`.

## Deliberate trade-offs

- **No "both keys valid for a while" rotation.** One file, one key per agent. If you need overlap, bootstrap a parallel agent id (`<AGENT>-next`), migrate callers, then remove the old one. Simpler invariant, fewer edge cases.
- **No certificate revocation list.** Revocation is `rm keys/agents/<AGENT>.pub`. Cache is the filesystem; effect is immediate.
- **Plaintext HTTP by default.** Designed for LAN/VPN. Adding TLS is the operator's job (reverse proxy or `tls: '...'` to the `https` module) — we don't want to pretend the server handles certificate lifecycle.
- **No multi-tenant separation.** One vault, one set of allow-listed IPs, one trust boundary. Run multiple instances if you need isolation between tenants.
- **Audit log self-rotation at 50 MB.** No external log-rotate dependency. If 50 MB/cycle is too coarse, edit `AUDIT_ROTATE_BYTES` in `server.js`.

## Reporting a vulnerability

Email **buildonai.tm@gmail.com** with subject prefix `[security]`. Please include:

- Affected version (commit SHA or release tag).
- A short reproduction (curl commands or a self-contained script).
- What you observed vs. what you expected.

We do not yet operate a bounty programme. We will acknowledge receipt within 7 days. Public disclosure timeline is coordinated case-by-case.

For non-security bugs, please open a regular GitHub issue.
