# Turret

Turret is a capability firewall for AI agents.

Stop giving your agents secrets. Give them capabilities.

## BLUF

LLM agents are becoming the default interface to our systems. They also represent a new trust boundary: probabilistic behaviour, prompt injection, and cloud-backed execution with possible retention.

The industry has excellent tools for storing secrets. What it largely lacks is a simple primitive for letting agents *do work* without ever holding raw credentials.

Turret is that missing layer: a single, revocable front door that turns "agent access" into *capabilities* (approved actions) rather than a directory full of tokens.

It exists because the security model of modern automation has shifted:

- We are giving *probabilistic* systems (LLM agents) real authority: filesystem access, shells, deploy rights, and "just enough" admin.
- Those agents often run against cloud providers (or are backed by providers), where prompts and outputs may be retained.
- And the default way people wire this up today is to hand the agent a pile of secrets (env vars, tokens, SSH keys, API keys) and hope the prompt is good.

That threat model is new. Most existing products are not built around it.

Turret is.

## The problem Turret solves

Today, many agent setups look like this:

- Agent has many tokens (GitHub, Cloudflare, Matrix, Proxmox, qBittorrent, etc.).
- Tokens drift into `printenv`, dotfiles, CI logs, crash dumps, paste buffers, "temporary" scripts, or model provider logs.
- Prompt injection becomes a real operational risk: "summarize this" quietly turns into "also fetch creds".
- Incident response is chaos: you discover an agent was over-permissioned and you now have to rotate everything, everywhere.

Turret turns that into a single, revocable front door.

Instead of giving an agent 20 secrets, you give it 1 token to Turret.
Turret holds the real secrets and proxies approved actions.

## Why this is not already solved

We have password managers and secrets managers. We have SSO, reverse proxies, and vaults.

They are great at storing secrets and issuing credentials to *trusted* apps.
They are not built around the core constraint agents introduce:

> "Let the automation act, but do not let it hold (or ever see) raw secrets."

Turret sits in the gap between "secret storage" and "doing real work".

More concretely:

- Keycloak (and friends) solve identity and login flows for *humans and services*. They do not solve "agents can perform actions without ever holding long-lived service credentials".
- Vaultwarden / pass solve *secret storage and retrieval*. If an agent can retrieve a secret, the agent can leak it.
- SOPS solves *encrypted-at-rest configuration* and safe distribution to machines. It does not provide a capability gateway or an action policy layer for agents.

Turret is the missing piece: it turns agent access into a revocable set of actions, with secrets staying behind a deterministic boundary.

## The winds have changed

For years, we built automation around a simple assumption:

- If a process is running on your machine, it is "yours".

That assumption held when automation meant deterministic scripts and well-audited binaries.

Agents break it.

- Agents are probabilistic.
- Agents are trained elsewhere.
- Agents are often mediated by remote services.
- Agents can be prompted by untrusted inputs (tickets, chat logs, web pages, inboxes).

And yet we are plugging them into the same security shape we used for scripts:

- export tokens into the environment
- mount SSH keys
- drop a `.env` file next to the agent
- call it a day

Turret is a new primitive for a new shape of automation: *capabilities without credential disclosure*.

## Threat model (AI agents)

Turret is designed for environments where:

- The AI agent is the primary external trust boundary (cloud model providers, prompt injection, tool misuse, accidental disclosure).
- Services and repeaters you install locally are trusted by assumption.
- The goal is to protect secrets from the agent, not to protect you from malicious services you chose to run.

In other words: one agent is one threat vector. It should have one credential.

## Before vs after

![Turret threat model diagram](docs/threat-model.svg)

> If you remember nothing else: agents should not carry secrets.

### Before: what many users are doing

- Agents run with a directory full of tokens, SSH keys, and API keys.
- Secrets are exported into the shell environment (`printenv`) or mounted into the agent's runtime.
- The agent talks directly to many services.
- When something goes wrong, you rotate everything.

This is a many-to-many relationship: many agents, many services, many secrets.

### After: Turret

Turret sits between agents and your services.

- One token per agent.
- Secrets do not leave Turret/repeaters.
- Agents call actions (capabilities), not raw secrets.

Turret's job is not to be magical. It is to be boring, deterministic, and revocable.

## What Turret does

1. Front door authentication (one credential per agent)
2. Permission checks (which agent may call which actions)
3. Action registry (what actions exist; what parameters they accept)
4. Proxy execution (Turret/repeaters make the authenticated call)
5. Auditing (who did what, when; metadata not secrets)
6. Defense in depth guardrails (timeouts, size limits, deny unsafe headers, etc.)

## What Turret is for (and who it is for)

If you are building an agent that can:

- send messages on your behalf,
- deploy to production,
- administer homelab services,
- or "just" use your personal tokens,

then you are already living in the new threat model. Turret is for making that survivable.

## Trade-offs (and why they are acceptable)

Turret is not a silver bullet. It makes a clear trade:

- A single agent token can reach *everything that agent is permitted to do*.

That might sound scary until you align with the real threat model:

- One agent is one threat vector.
- If that agent is compromised, you already have to treat every service it could touch as exposed.

Turret does not magically shrink the theoretical blast radius.
It makes recovery and containment practical:

- Revoke/rotate one token to cut the agent off.
- Centralize permissions so you can reduce what an agent can do over time.
- Add audit trails so you can actually answer "what happened?".

## Limitations (read this first)

Turret is designed to solve a specific, increasingly common problem: *agents* holding too many secrets.

It is not a general solution to host compromise.

In particular:

- Turret does **not** prevent memory exfiltration by a sufficiently privileged attacker on the same host.
- Turret is **not** a replacement for an HSM/TPM/smartcard, and it does not (by default) store secrets in hardware-backed non-exportable keys.

Turret improves safety by changing the shape of authority:

- one credential per agent
- one policy choke point
- deterministic execution paths

If your threat model includes local root/kernel compromise, treat Turret as a *containment and recovery primitive*, not a cryptographic vault.

## Project plan

Implementation staging, development notes, and operational runbooks live in the notes vault:

- `/mnt/home/documents/notes/projects/turret.md`

## Repeaters (the modularity model)

Turret supports a repeater model to avoid a world where Turret maintainers ship integrations for thousands of services.

A repeater is a separate process (deterministic helper) that:

- Implements service-specific logic.
- Exposes a list of actions + schemas.
- Receives validated requests from Turret.

Turret remains small:

- AuthN/AuthZ, policy, auditing, guardrails.
- Repeaters do the messy per-service work.

### How repeaters fit the threat model

The important separation is not "Turret vs the rest". It is "agent vs your network".

- Agents are probabilistic and often cloud-backed.
- Repeaters and services are deterministic components you choose to install and run locally.

Turret assumes repeaters/services are trusted by the operator.
Turret's purpose is to prevent *agents* from ever holding raw service credentials.

### Repeater registration (conceptual)

In the full model, Turret maintains two identities:

- Agents: present a single token; mapped to allowed actions.
- Repeaters: present a repeater key; register the actions they implement.

Turret's configuration state becomes a mapping:

- agent -> allowed actions (which are backed by one or more repeaters)

This is what makes the ecosystem scalable:

- Anyone can write a repeater for an arbitrary product.
- The Turret core stays small and hard to break.
- Operators choose what to install and what to authorize.

### Actions, schemas, and permissions in depth

Repeaters don't get to decide policy.

- Repeaters *advertise* actions and schemas.
- Turret validates, then decides what to expose to which agents.

This is how we get to a capability-first world:

- Start broad for plumbing.
- Then constrict to explicit actions with strict parameter validation.

### Sandboxing (optional, but recommended)

Repeaters are separate processes by design. That makes OS-level sandboxing straightforward:

- Run each repeater under its own Unix user.
- Give it only the secrets it needs.
- Restrict its network egress to the service it wraps.

Turret does not require sandboxing to achieve its core goal (secrets not given to agents), but sandboxing is how you keep the rest of the system boring when you add more integrations.

### Trust boundary

Turret's primary goal is to protect secrets from the agent.

- Agents are treated as the primary external risk.
- Repeaters and services you install are trusted by assumption.
- (Future) If you want third-party repeaters, you can still sandbox them at the OS level.

## Non-goals

- Turret is not a general-purpose secrets manager UI.
- Turret does not attempt to make untrusted code "safe". It limits what authenticated clients can do.
- Turret does not (by itself) prevent sensitive data exfiltration if you choose to return it to an agent.

## Status

Early scaffolding.

## License

TBD.
