# BuildOnAI Key Server

**ed25519 signature-per-request authentication for HTTP services. Plus an optional on-disk vault for SSH keys and API tokens.**

[![CI](https://github.com/build-on-ai/buildonai-key-server/actions/workflows/ci.yml/badge.svg)](https://github.com/build-on-ai/buildonai-key-server/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Commercial License Available](https://img.shields.io/badge/Commercial-Available-green.svg)](LICENSE-COMMERCIAL.md)
[![Node.js](https://img.shields.io/badge/Node.js-%E2%89%A520-brightgreen.svg)](package.json)

A standalone HTTP service that does two jobs:

1. **Verifies ed25519-signed requests.** A caller signs `(method, path, timestamp, nonce, body-hash)` with its private key. The server holds the matching public key and answers `valid: true | false`. No sessions, no bearer tokens, no token issuance, no token expiry to manage. The key is the identity.
2. **Hands out secrets on demand.** SSH private keys for deploy/push, API tokens for outbound calls. IP allow-list as the first gate; with a signed request, the same ed25519 signature is required on top.

Designed as a sidecar for [Consciousness Server](https://github.com/build-on-ai/consciousness-server) and [Cortex](https://github.com/build-on-ai/cortex), but works standalone for any HTTP service that wants stateless, key-based authentication without standing up Vault, OAuth, or a JWT issuer.

## Why this exists

If you run a small group of services or agents that talk HTTP to each other, your auth options today are bad in three different ways:

1. **Bearer tokens in headers.** Now you have token issuance, token storage, token rotation, token revocation, refresh flows, and a token database to back up. Half of "auth" is now "token lifecycle".
2. **mTLS between every pair.** Cleaner trust model, but every operator hits the same wall: certificate authority, intermediate certs, rotation, and a hard story for revocation.
3. **Shared secret in `.env`.** Works until the day it leaks — then everyone learns about it at the same time.

Signed requests sit in the middle. The agent's public key sits in a file on the verifier's disk. Removing the file revokes the agent. The signature is per-request, so there is no token to steal that grants ongoing access. The verifier holds no state about who signed what — only "is this signature valid for this canonical message".

This pattern is well-known (AWS SigV4, GitHub Apps JWT, SSH agent forwarding). This repo is the self-contained, predictable implementation of it.

## When this is the right choice

- You run several services/agents on hosts you control and they need to authenticate to each other.
- You want revocation that is `rm file` and takes effect immediately, with no token cache to invalidate.
- You don't want to operate a JWT issuer, a session store, or HashiCorp Vault.
- You can put the verifier behind a reverse proxy if you need TLS, and you can run it on a trusted LAN/VPN.

## When this is the wrong choice

- You serve untrusted public clients (signed requests assume you can ship a private key to each caller — fine for service-to-service, wrong for arbitrary browsers).
- You need centralised audit + policy + secret-scanning at scale (use HashiCorp Vault or a cloud KMS — this server's audit log is local file + JSONL, not OpenTelemetry).
- You need multi-tenant separation in a single instance (run multiple instances instead).

## Quick start

```bash
git clone https://github.com/build-on-ai/buildonai-key-server.git
cd buildonai-key-server
cp auth/allowed-clients.json.example auth/allowed-clients.json
# edit auth/allowed-clients.json: add the IPs your callers will use
docker compose up -d
curl http://localhost:3040/health
```

> **403 on the first `curl`?** Two causes, in order of likelihood.
>
> **The `cp` above was skipped.** Without `auth/allowed-clients.json` the
> server logs `Failed to load auth config` at startup and falls back to a
> loopback-only allowlist, which rejects everything arriving over the Docker
> bridge. Check with `docker compose logs key-server | grep 'auth config'`,
> then copy the example and restart.
>
> **Your bridge is on a different subnet.** Requests reach the container via
> the Docker bridge, so the source IP is the bridge subnet, not `127.0.0.1`.
> The example config pre-allows the common ranges (`172.17`–`172.20`). If your
> Compose project landed elsewhere, run
> `docker network inspect buildonai-key-server_default` and add the actual CIDR.

> **Testing the signature layer?** `npm test` runs seventeen address-allowlist
> cases and ten checks over verification, replay rejection and the `enforce`
> path. The second half needs Redis on the host:
>
> ```bash
> docker compose -f docker-compose.yml -f docker-compose.test.yml up -d redis
> npm ci && npm test
> ```

### Register an agent (ed25519)

```bash
# On the agent's host:
ssh-keygen -t ed25519 -C "agent1@$(hostname)" -f ~/.ssh/buildonai-agent1 -N ""

# Copy the PUBLIC key to the key-server host:
scp ~/.ssh/buildonai-agent1.pub operator@key-server-host:/opt/buildonai-key-server/keys/agents/agent1.pub

# Confirm the server picked it up:
curl http://key-server-host:3040/api/agents/identity
# {"agents": ["agent1"], "count": 1}
```

> Calling the server by a hostname other than `localhost` / `127.0.0.1` / `[::1]` (like `key-server-host:3040` above) requires that host:port to be listed in `KEY_SERVER_ALLOWED_HOSTS` — see [Configuration](#configuration).

Private key stays on the agent's host. It never leaves.

### Sign a request

A Node CLI helper ships at [`bin/sign-request`](bin/sign-request); its usage is documented in [`keys/agents/README.md`](keys/agents/README.md), along with inline Node and Python signing snippets.

## Signature checking

Every request to a sensitive endpoint must carry a valid ed25519 signature.
An invalid or missing one gets `401`, or `503` when the verify lookup itself
is unavailable. Sensitive means anything that dispenses secrets or audit
history; `/health`, `/api/agents/identity*` and `/api/verify` stay open by
design.

Revoking an agent is `rm keys/agents/<AGENT>.pub` — it takes effect on the
next request.

## Architecture

```
                  ┌──────────────┐
                  │  Agent host  │
                  │              │
                  │  ~/.ssh/     │     1. signs canonical message
                  │  buildonai-  │        with ed25519 private key
                  │  agent1      │
                  └──────┬───────┘
                         │ HTTP request + 4 headers
                         │ (X-Agent-Id, X-Timestamp,
                         │  X-Nonce, X-Signature)
                         ▼
                  ┌──────────────────┐
                  │ Any HTTP service │     2. forwards headers + body hash
                  │ (CS, your API,   ├────►│
                  │  webhook target) │
                  └──────────────────┘     POST /api/verify
                                                  │
                                                  ▼
                                ┌──────────────────────────┐
                                │   buildonai-key-server   │
                                │                          │
                                │  keys/agents/agent1.pub  │  ← reads pubkey from disk
                                │                          │     on every verify
                                │  Redis: nonce cache      │  ← anti-replay (TTL 360s)
                                │                          │
                                │  → {valid: true|false}   │
                                └──────────────────────────┘
```

Wire-level details: [`docs/SIGNING-PROTOCOL.md`](docs/SIGNING-PROTOCOL.md).

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` | Host + IP allow-list (no signature) | Liveness probe |
| `GET` | `/api/agents/identity` | IP allow-list | List registered agent ids |
| `GET` | `/api/agents/identity/<agent>` | IP allow-list | Public key + fingerprint for one agent |
| `POST` | `/api/verify` | IP allow-list | Verify a signature (called by gated services) |
| `GET` | `/keys/list` | IP allow-list + (enforce) sig | List vault contents (SSH key names, API services) |
| `GET` | `/keys/ssh/<name>` | IP allow-list + (enforce) sig | Fetch an SSH private key from the vault |
| `GET` | `/keys/api/<service>` | IP allow-list + (enforce) sig | Fetch an API token from the vault |
| `GET` | `/audit` | IP allow-list + (enforce) sig | Last 100 audit log entries |

Every endpoint (all rows above) additionally sits behind the Host-header allowlist (`KEY_SERVER_ALLOWED_HOSTS`) — requests with an unexpected `Host:` are rejected with 403 before routing.

## Configuration

All via environment variables. Defaults shown.

```bash
KEY_SERVER_PORT=3040
KEY_SERVER_HOST=0.0.0.0
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
KEY_SERVER_ALLOWED_HOSTS=localhost:3040,127.0.0.1:3040,[::1]:3040
```

**`KEY_SERVER_ALLOWED_HOSTS`** is the Host-header allowlist (defence against DNS rebinding). Format: comma-separated list of exact `host:port` values matched verbatim against the incoming `Host:` header (port included; IPv6 in brackets). The default only covers loopback names on the configured port. Override it whenever callers reach the server by any other name — a LAN hostname, a Docker Compose service name (the shipped `docker-compose.yml` sets `key-server:3040`), or an IP address. A request with a `Host:` not on the list gets `403 {"reason": "invalid_host"}` before any routing.

## Security

See [`SECURITY.md`](SECURITY.md) for the threat model, deliberate trade-offs, and how to report a vulnerability.

## License

Dual-licensed:

- **[AGPL-3.0-only](LICENSE)** for personal use, open-source projects, internal use without offering as a network service, and AGPL-licensed redistribution.
- **[Commercial license](LICENSE-COMMERCIAL.md)** for embedding in closed-source products, offering as a hosted service (SaaS) without publishing modifications, or any case where AGPL's network-service obligation is incompatible with your business model. Contact: **buildonai.tm@gmail.com**.

## Standalone use cases

The server has no dependency on Consciousness Server, Cortex, or anything else in the BuildOnAI ecosystem. Three patterns it fits:

- **Inter-service auth in a small monorepo.** Each service holds its own private key, signs outbound requests. The verifier is one container.
- **Webhook authentication.** Your source signs the payload before sending; the receiver forwards the headers to `/api/verify`. Now your webhook receiver has cryptographic proof of origin without a shared secret per source.
- **IoT device auth.** Each device generates its own ed25519 keypair on first boot. Public key registered out of band. Telemetry is signed per request. Stolen device → `rm` its `.pub` file, telemetry stops being accepted, the device's stored private key is now useless against you.

## Upgrading from v1.0.0

v1.0.0 shipped a vault-only model with bearer tokens. That model is gone; ed25519 signature-per-request is the trust primitive. A v1.0.0 deployment will not work against this server without re-registering agents and switching their clients to signing.
