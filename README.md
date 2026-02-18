# Turret

Turret is a secret firewall for AI agents.

Stop giving your agents secrets.

## BLUF

LLM agents are now practical admins: they can run shell commands, deploy code, and touch real systems. That also makes them a different trust boundary from traditional scripts.

Turret is a small local control point that lets agents act without directly holding service credentials.

This is currently a proof of concept. It is not a hardened production security boundary, but it is already a better default than handing an agent a directory full of long-lived tokens.

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

In practice:

- Operators (you) create a bunker (encrypted secret store on disk)
- Operators add things into the bunker:
  - other operators
  - targets (API/command actions with a flexible shape based on secret **names**)
  - named secrets
  - rookies (untrusted users -- like agents)

- Operators allow/disallow rookies to fire at targets
- Operators engage the turret (a daemon decrypts the bunker and holds it in memory, then opens a socket to accept requests from rookies)
- Rookies call `fire` on specific targets, with an optional data payload and their dog tags (shared secrets).

This keeps authority explicit and revocable while avoiding ambient token sprawl in agent runtimes.

## Why this is not already solved

Existing secret tooling is good at storage and distribution to trusted software.

The specific agent requirement is different. Agents shouldn't be trusted. They are closed source, and likely inscrutable even if their weights were known. They probabilistically exfiltrate data from the system and report it to the cloud where it is used (with or without permission) to train the next generation of models by unscrupulous providers:

> Let automation perform approved work without giving it raw service credentials.

Turret sits in that gap by combining auth, authorization, constrained input validation, secret substitution, and direct command execution.

## Trade-offs

Turret intentionally centralizes control. Trade-offs:

- If a rookie credential is compromised, attacker gets that rookie's allowed targets.
- If the host is compromised, in-memory material can be exposed.

Why still useful:

- one identity to revoke quickly,
- explicit per-target authorization,
- less credential sprawl,
- deterministic boundary for incident response.

## Limitations

- Turret is not an OS sandbox.
- Turret does not protect against local root compromise.
- Turret does not prevent exfiltration of data you intentionally return to rookies.
- Turret is not an HSM/TPM replacement.

Treat Turret as a capability-control and containment primitive, not as a host-compromise defense. It's conceptually similar to a password manager where the user is able to use passwords but not read them. Think HashiVault at much smaller local native binary scale.

## Status

Proof of concept / working prototype:

- Not hardened: minimal auditing, no formal security review, and limited ergonomics.
- Still useful today: replaces "give the agent everything" with explicit, revocable capabilities.

Current CLI and daemon lifecycle:

- `turret <name> dig`
- `turret <name> in|out operator|recruit|target|secret`
- `turret <name> allow|deny`
- `turret <name> engage|fire|disengage`

## License

TBD.
