# Turret Spec (v1)

This document is the stable technical contract for Turret v1.

If implementation differs, update this spec first.

## Terminology

- Operator: a human who can "fire up the turret" by decrypting persisted state.
- Agent: an automation client (LLM-backed or otherwise) that invokes actions through Turret.
- Repeater: a deterministic helper process that implements actions; it receives secrets from Turret but does not persist them.

## Transport

- IPC: unix domain sockets.
- Socket paths:
  - `turret-agent.sock`
  - `turret-repeater.sock`
- No TCP listener by default.

## Framing

Each message is a single frame:

- 4-byte unsigned big-endian length prefix (number of bytes in payload)
- payload: custom binary message

Max frame size (v1): 262144 bytes (256 KiB). Frames larger than this are rejected.

## Authentication

- Algorithm: Ed25519 signatures.
- Turret stores a mapping of `principal_id -> ed25519 public key` for both agents and repeaters.
- Each message is signed by the sending principal.

Note (scaffolding): Turret-generated error replies may be unsigned until Turret has its own
principal/key material. Agents should treat such errors as best-effort.

Canonical signing bytes (v1):

```text
<principal>\n<ts_ms>\n<nonce>\n<body_bytes>
```

Where:

- `principal` is the exact string from the envelope.
- `ts_ms` is the decimal string form of the integer timestamp.
- `nonce` is the exact bytes from the envelope.
- `body_bytes` is the exact payload bytes of the message body.

Anti-replay (v1):

- `ts_ms` must be within +/- 120 seconds of Turret wall clock.
- Turret maintains an in-memory cache of recently seen `(principal, nonce)` pairs within the window.
- If a `(principal, nonce)` pair is seen twice within the window, reject with `REPLAY`.

## Binary message format (v1)

Turret uses a custom binary format to reduce dependencies and remove ambiguity.

Magic constants:

- `TRT1`: Turret protocol envelope marker (the trailing `1` is the protocol major version).

All integers are unsigned.

- Envelope fields are little-endian unless stated.
- `bstr` lengths are big-endian to match outer framing.

### Common primitives

- `u8`, `u16`, `u32`, `u64`: fixed-width integers
- `bytes(n)`: n raw bytes
- `bstr`: `u32 len_be` + `bytes(len)`
  - Constraints:
    - `len <= 262144`
    - `len` must not exceed remaining frame bytes

### Envelope layout

```text
magic            bytes(4)   = "TRT1"
version          u16        = 1
type             u16        enum
principal        bstr       principal_id
ts_ms            u64        unix epoch millis
nonce            bstr       opaque nonce bytes (recommended 16-32 random bytes)
body             bstr       type-specific body bytes
sig              bstr       Ed25519 signature (64 bytes)
```

`type` enum (v1):

- 1 = `register`
- 2 = `invoke`
- 3 = `result`
- 4 = `error`

Signing bytes (v1):

```text
<principal>\n<ts_ms_decimal>\n<nonce>\n<body>
```

Notes:

- `principal` and `nonce` are the exact bytes of the decoded `bstr` fields.
- `ts_ms_decimal` is the ASCII decimal representation of `ts_ms`.
- `body` is the exact decoded `body` bytes.
- `sig` is computed over the signing bytes.

## Message types

### Repeater registration (`type: register`)

Sent by a repeater to `turret-repeater.sock`.

Body layout:

```text
repeater_id      bstr
action_count     u32
actions          action_count * bstr   (each is an action name)
```

Rules:

- Envelope `principal` must equal `repeater_id`.
- Turret accepts registration only if `repeater_id` exists in the persisted state (known repeater).
- A repeater may only register actions that map to itself in the actions registry.

### Agent invocation (`type: invoke`)

Sent by an agent to `turret-agent.sock`.

Body layout:

```text
request_id       bstr
action           bstr
params           bstr   (opaque bytes; interpreted by repeater)
```

Rules:

- Deny by default.
- `action` must be present in the agent permission table.
- `action` must exist in the actions registry.
- The mapped repeater must be currently connected and registered for that action.

### Result (`type: result`)

Returned to the caller.

Body layout:

```text
request_id       bstr
result           bstr   (opaque bytes)
```

### Error (`type: error`)

Returned to the caller.

Body layout:

```text
request_id       bstr
code             u16    enum
message          bstr   human-readable error
```

Error codes (v1):

- 1 = `UNAUTHENTICATED`
- 2 = `REPLAY`
- 3 = `DENIED`
- 4 = `UNKNOWN_ACTION`
- 5 = `NO_REPEATER`
- 6 = `BAD_REQUEST`
- 7 = `INTERNAL`

## Action registry model

- Persisted mapping: `action -> repeater_id`.
- Runtime requirement: repeater must be connected + registered for that action.

## Permission table model

- Persisted mapping: `agent_id -> [action]`.
- Exact match only in v1 (no wildcards).
- Deny by default.

## Persisted data model (bunker)

Bunker is the single persisted state store.

- Encrypted at rest using `age`.
- Recipients are the operator recipient set.

Bunker plaintext is a TOML document (UTF-8).

Minimum shape (v1):

```toml
version = 1

[operators]
recipients = [
  "ssh-ed25519 AAAA...",
  "age1...",
]

[agents]
# agents."agent-1".ed25519_pubkey_b64 = "..."

[repeaters]
# repeaters."rep-1".ed25519_pubkey_b64 = "..."

[actions]
# "echo" = "rep-1"

[permissions]
# permissions."agent-1".allow = ["echo"]
```

Validation rules:

- `magic` and `version` must match.
- `operators.recipients` must contain at least 1 recipient.
- `actions` must reference known repeaters.
- `permissions` must reference known agents and actions.

Operator identities (private keys) are never stored in the bunker.

## Fire-up procedure

- Turret starts by attempting to decrypt the bunker.
- If decryption using host identity succeeds, Turret starts without operator input.
- Otherwise, Turret requires operator input to fire up.

Console UX (v1):

```text
Unable to decrypt with host keys. Operator required.
Select type: 1) Passphrase, 2) Hardware key (work in progress)
```
