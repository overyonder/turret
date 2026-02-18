# Turret

Turret is a capability firewall for AI agents.

Stop giving your agents secrets. Give them capabilities.

## BLUF

LLM agents are now practical operators: they can run shell commands, deploy code, and touch real systems. That also makes them a different trust boundary from traditional scripts.

Turret is a small local control point that lets agents act without directly holding service credentials.

This is currently a proof of concept. It is not a hardened production security boundary, but it is already a better default than handing an agent a directory full of long-lived tokens.

In practice:

- Operators define targets (approved actions).
- Operators bind targets to rookies (agents).
- Operators keep secrets inside an encrypted bunker.
- A daemon is engaged once by an operator and holds decrypted policy in memory.
- Rookies call `fire` with their own shared secret to request actions.

This keeps authority explicit and revocable while avoiding ambient token sprawl in agent runtimes.

## The problem Turret solves

Most agent setups still look like this:

- Environment full of API keys, SSH keys, and long-lived tokens.
- Agents encouraged to do direct API calls with broad credentials.
- Prompt injection can pivot into secret retrieval and lateral movement.
- Incident response means rotating many unrelated secrets.

Turret changes that shape:

- one rookie credential,
- one policy boundary,
- one place to revoke access quickly.

## Why this is not already solved

Existing secret tooling is good at storage and distribution to trusted software.

The specific agent requirement is different:

> Let automation perform approved work without giving it raw service credentials.

Turret sits in that gap by combining auth, authorization, constrained input validation, secret substitution, and direct command execution.

## The winds have changed

Automation assumptions have shifted:

- deterministic scripts are no longer the only actor,
- probabilistic agents consume untrusted inputs,
- hosted model backends introduce retention and leakage concerns.

Treating an agent runtime like a normal trusted process is no longer a safe default.

Turret exists to make this new model operationally manageable.

## Threat model (AI agents)

Turret is designed for the case where:

- the rookie agent is the primary external risk,
- the host and local operator-controlled binaries are trusted,
- the goal is to prevent credential disclosure to the rookie while still allowing bounded actions.

One rookie is one risk vector. It gets one identity and explicit permissions.

## Before vs after

![Turret threat model diagram](docs/threat-model.svg)

> If you remember nothing else: agents should not carry secrets.

### Before: what many users are doing

- Inject multiple service credentials into the agent environment.
- Let agent tools call external services directly.
- Recover from mistakes by rotating many tokens.

This is many agents -> many services -> many credentials.

### After: Turret

Turret is the front door:

- Rookies authenticate to Turret.
- Turret enforces permissions and payload shape.
- Turret resolves secrets internally.
- Turret executes the approved target and returns output only.

## What Turret does

1. Rookie authentication with shared secret.
2. Rookie-to-target authorization checks.
3. Target shape validation (`allow`, `forbid`, `require`, `argv_placeholders`).
4. Target transform application (`out_command`, `out_argv_replace`, `out_env`, `out_stdin_replace`).
5. Secret substitution from bunker `[secrets]` using `{SECRET_NAME}` tokens.
6. Direct process execution (no shell), controlled env, stdout return.
7. Daemon lifecycle (`engage` / `fire` / `disengage`) so operator key is not needed per request.

## What Turret is for (and who it is for)

Turret is for operators running agents that need to do real work, such as:

- messaging and notification actions,
- deployment and admin actions,
- internal automation that would otherwise require handing tokens to agent tools.

If your current setup relies on putting sensitive credentials in agent-accessible context, Turret is meant to replace that pattern.

## Trade-offs (and why they are acceptable)

Turret intentionally centralizes control. Trade-offs:

- If a rookie credential is compromised, attacker gets that rookie's allowed targets.
- If the host is compromised, in-memory material can be exposed.

Why still useful:

- one identity to revoke quickly,
- explicit per-target authorization,
- less credential sprawl,
- deterministic boundary for incident response.

## Limitations (read this first)

- Turret is not an OS sandbox.
- Turret does not protect against local root compromise.
- Turret does not prevent exfiltration of data you intentionally return to rookies.
- Turret is not an HSM/TPM replacement.

Treat Turret as a capability-control and containment primitive, not as a host-compromise defense.

## Staged roadmap

### Stage 1: plumbing (blast radius reduction)

- Keep secrets in bunker, not in rookie env.
- Enforce rookie auth + target authorization.
- Run constrained targets through one policy boundary.

### Stage 2: capability-first API

- Stabilize target libraries for common operational actions.
- Reduce broad/generic targets in favor of narrowly scoped actions.

### Stage 3: operations

- Structured audit output.
- Better lifecycle tooling and health checks.
- Easier rotation workflows for rookie secrets and bunker recipients.

## Encrypted state + operators (age recipients)

This is active in the current CLI model.

Bunkers are encrypted with age/rage recipients and stored as `./<name>.bnkr`.

Operator model:

- `dig` creates bunker with recipients.
- `in/out operator` manages recipients.
- `engage` decrypts bunker (host key attempt first, operator key fallback).

Runtime model:

- Daemon holds decrypted bunker in memory while engaged.
- `fire` requests do not require operator key.
- `disengage` is operator-gated and stops daemon.

## Repeaters (the modularity model)

The current design does not use repeater processes.

Turret executes local targets directly from target definitions. That keeps the runtime model minimal while core policy behavior is stabilized.

If modular connectors are added later, they should preserve the same principle: rookies never receive raw credentials.

### How repeaters fit the threat model

If introduced in the future, repeaters should remain operator-trusted local components and not expand rookie credential visibility.

### Repeater registration (conceptual)

Not part of the current implementation.

### Actions, schemas, and permissions in depth

Today, actions are target definitions in bunker:

- shape enforces input contract,
- transform defines execution material,
- permissions bind rookie -> target.

### Sandboxing (optional, but recommended)

Turret currently executes local commands directly without additional sandboxing. Operators should apply OS-level isolation where needed.

### Trust boundary

Primary boundary is still rookie vs Turret policy engine.

## Non-goals

- General secret-manager UX replacement.
- Full host hardening solution.
- Automatic guarantee that action outputs are non-sensitive.
- Broad policy language beyond current shape+transform model.

## Status

Proof of concept / working prototype:

- Not hardened: minimal auditing, no formal security review, and limited ergonomics.
- Still useful today: replaces "give the agent everything" with explicit, revocable capabilities.

Current CLI and daemon lifecycle:

- `turret <name> dig`
- `turret <name> in|out operator|recruit|target|secret`
- `turret <name> allow|deny`
- `turret <name> engage|fire|disengage`

See `SPEC.md` for the contract-level behavior.

## License

TBD.
