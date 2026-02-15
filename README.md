# Turret

Capability interface for agents.

Turret is a small, security-focused service that proxies approved actions to downstream services without ever returning raw credential material to the caller.

This is designed for LLM agents (OpenCode, Corvus, etc.) where you want:

- One per-agent auth token to Turret (easy revoke/rotate if an agent is compromised).
- Downstream secrets kept inside Turret (SOPS/systemd credentials) and never exposed to agents.
- A staged path from broad plumbing (proxy) to strict, capability-first APIs.

## Status

Early scaffolding. Stage 1 goal: reduce blast radius by removing ambient secrets exposure (e.g. shell-wide env exports) and routing authenticated calls through Turret.

## Non-goals

- Turret is not a general-purpose secrets manager UI.
- Turret does not aim to make untrusted code "safe"; it limits what authenticated clients can do.

## Staged roadmap

### Stage 1: Plumbing (blast radius reduction)

- Turret runs as a small service (local-first).
- Agents authenticate to Turret with a single token.
- Turret holds downstream credentials and performs requests on behalf of agents.
- Guardrails: upstream allowlist, method allowlist, timeouts, max response sizes, no caller-controlled Authorization headers.

### Stage 2: Capability-first API

- Replace generic proxy calls with explicit capabilities:
  - `matrix.send_message(room_id, body)`
  - `qbittorrent.add_torrent(magnet, category)`
  - `proxmox.pct_status(ctid)`
  - etc.
- Per-agent policy: which capabilities + parameter scoping.

### Stage 3: Operations

- Structured audit logs.
- Key age tracking.
- Assisted rotation workflows (and eventually automatic rotation where possible).

## High-level design

- Clients: OpenCode agents / Corvus / other automation.
- Auth: per-agent bearer token presented to Turret.
- Secrets: stored outside the repo; provided to Turret via OS secret plumbing (e.g. SOPS -> `/run/secrets/*` and/or systemd credentials).
- Policy: allow/deny per agent + service/capability.

## Quick principles

- Prefer explicit capabilities over arbitrary HTTP proxying.
- Treat responses as sensitive too (avoid returning data dumps when not required).
- Make revocation simple and reliable.
- Log metadata, not secrets/PII.

## License

TBD.
