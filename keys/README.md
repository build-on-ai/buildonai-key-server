# key-server/keys/

This directory is where the key-server reads material at runtime. It
is empty in a fresh clone — every subdirectory starts as a template
and fills up once you bootstrap your deployment.

## Layout

```
keys/
├── agents/       # Per-agent ed25519 public keys — see keys/agents/README.md
├── ssh/          # SSH host / deploy keypairs served via /keys/ssh/:name
├── anthropic/    # Anthropic API key under api-key.txt
└── github/       # GitHub API key under api-key.txt
```

Only the `agents/` subtree is required for the `/api/verify`
signed-request flow. The `ssh/`, `anthropic/`, and `github/`
subdirectories exist for operators who want the key-server to
vend credentials they already use elsewhere — they are optional.

## Bootstrapping

1. `agents/<AGENT>.pub` — ed25519 public key per agent. See
   `agents/README.md` for the full procedure.
2. `ssh/<name>` — private key file plus `ssh/<name>.pub`. The
   key-server exposes `GET /keys/ssh/<name>` that returns the private
   key text to an IP-whitelisted caller.
3. `anthropic/api-key.txt` / `github/api-key.txt` — single-line API
   token files. Served via `GET /keys/api/<service>`.

Nothing in `keys/` should ever be committed. The shipped
`.gitignore` at the repo root excludes this tree wholesale; the
per-directory `.gitkeep` files only preserve the paths so a fresh
clone already has the expected shape.

## Permissions

Set them tight. The key-server runs as one user; nobody else on the
host needs to read these files directly.

```bash
chmod 700 keys
chmod 600 keys/ssh/* keys/anthropic/api-key.txt keys/github/api-key.txt
chmod 644 keys/agents/*.pub
```

`/api/verify` does not rely on filesystem permissions for its trust
model — it re-reads the agent `.pub` file on every verify — but the
SSH and API-key endpoints pass the file contents straight through,
so the host must not leak them.
