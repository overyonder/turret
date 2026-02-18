# Turret Spec (v1)

Turret is a local capability gate with an operator-started daemon.

## Naming and Paths

- CLI shape: `turret <bunker-name> <command> ...`
- Bunker file path: `./<bunker-name>.bnkr`
- Daemon socket path: `./<bunker-name>.sock`
- Daemon pid path: `./<bunker-name>.pid`

## Command Surface

- `dig`
- `in operator|recruit|target|secret`
- `out operator|recruit|target|secret`
- `allow --rookie <id> --target <id> --operator <key>`
- `deny --rookie <id> --target <id> --operator <key>`
- `engage --operator <key>`
- `fire --rookie <id> (--params <json> | --params-file <file>)`
- `disengage --operator <key>`

## Bunker Model

```toml
version = 1

[operators]
recipients = ["ssh-ed25519 AAAA...", "age1..."]

[agents]
# corvus = "shiny"

[targets.<name>.shape]
allow = ["argv", "stdin"]
forbid = ["command", "env"]
require = ["argv"]
argv_placeholders = 1

[targets.<name>.transform]
out_command = "set-by-operator"
out_argv_replace = {"{1}" = "{LOCKBOX_1}"}
out_env = {"KEY" = "{LOCKBOX_2}"}
out_stdin_replace = {}

[permissions]
# corvus = ["lockbox"]

[secrets]
# LOCKBOX_1 = "rumplestiltskin"
```

## Fire Payload

`fire` sends an invoke JSON payload to the daemon over the local Unix socket.

```json
{
  "agent_id": "optional and overridden by --rookie",
  "agent_secret": "required",
  "target": "required",
  "command": "optional string",
  "argv": ["optional", "string", "list"],
  "env": {"OPTIONAL": "map"},
  "stdin": "optional string"
}
```

The caller must include the rookie shared secret (`agent_secret`) in the fire payload.

## Execution Flow

1. Operator runs `engage`; turret decrypts bunker once and holds it in memory.
2. Agent runs `fire`; daemon receives payload.
3. Turret authenticates (`agent_id` + `agent_secret`).
4. Turret authorizes (`permissions[agent_id]` contains target).
5. Turret enforces target shape (`allow`/`forbid`/`require`/`argv_placeholders`).
6. Turret applies target transform, resolving `{SECRET_NAME}` from `[secrets]`.
7. Turret executes `out_command + argv` directly (no shell), with cleared env + injected env.

## Error Semantics

- `unauthenticated`: bad agent credentials
- `denied`: rookie lacks permission for target
- `unknown_target`: target is not present
- `bad_request`: payload shape mismatch or missing secret token
- `internal`: command execution failure
