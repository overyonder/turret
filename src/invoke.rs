use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::bunker::{Bunker, TargetDef};

#[derive(Debug, Deserialize, Serialize)]
pub struct InvokePayload {
    pub agent_id: String,
    pub agent_secret: String,
    pub target: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub argv: Option<Vec<String>>,
    #[serde(default)]
    pub env: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub stdin: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum InvokeError {
    #[error("unauthenticated: bad agent credentials")]
    Unauthenticated,
    #[error("denied")]
    Denied,
    #[error("unknown target")]
    UnknownTarget,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("internal: {0}")]
    Internal(String),
}

pub fn execute_invoke(bunker: &Bunker, payload: InvokePayload) -> Result<Vec<u8>, InvokeError> {
    let authed = bunker
        .agents
        .get(&payload.agent_id)
        .map(|s| s == &payload.agent_secret)
        .unwrap_or(false);
    if !authed {
        return Err(InvokeError::Unauthenticated);
    }

    let allowed = bunker
        .permissions
        .get(&payload.agent_id)
        .map(|s| s.contains(&payload.target))
        .unwrap_or(false);
    if !allowed {
        return Err(InvokeError::Denied);
    }

    let def = bunker
        .targets
        .get(&payload.target)
        .ok_or(InvokeError::UnknownTarget)?;

    let (command, argv, env_map, stdin_bytes) = conform_payload(def, payload, &bunker.secrets)
        .map_err(InvokeError::BadRequest)?;

    run_target(&command, &argv, &env_map, &stdin_bytes).map_err(InvokeError::Internal)
}

fn conform_payload(
    def: &TargetDef,
    payload: InvokePayload,
    secrets: &BTreeMap<String, String>,
) -> Result<(String, Vec<String>, BTreeMap<String, String>, Vec<u8>), String> {
    let has_command = payload.command.is_some();
    let has_argv = payload.argv.is_some();
    let has_env = payload.env.is_some();
    let has_stdin = payload.stdin.is_some();

    let present = [
        ("command", has_command),
        ("argv", has_argv),
        ("env", has_env),
        ("stdin", has_stdin),
    ];

    for (name, is_present) in present {
        if is_present && !def.shape.allow.contains(name) {
            return Err(format!("non-conforming payload: field '{name}' is not allowed"));
        }
        if is_present && def.shape.forbid.contains(name) {
            return Err(format!("non-conforming payload: field '{name}' is forbidden"));
        }
        if !is_present && def.shape.require.contains(name) {
            return Err(format!("non-conforming payload: field '{name}' is required"));
        }
    }

    if let Some(expect) = def.shape.argv_placeholders {
        let argv = payload
            .argv
            .as_ref()
            .ok_or_else(|| "non-conforming payload: argv required for placeholder check".to_string())?;
        let actual = argv.iter().map(|s| count_placeholders(s)).sum::<usize>();
        if actual != expect {
            return Err(format!(
                "non-conforming payload: argv placeholder count is {actual}, expected {expect}"
            ));
        }
    }

    let command = render_secret_tokens(&def.transform.out_command, secrets)?;
    if command.trim().is_empty() {
        return Err("non-conforming payload: command resolved empty".to_string());
    }

    let mut argv = payload.argv.unwrap_or_default();
    for item in &mut argv {
        for (from, to_tmpl) in &def.transform.out_argv_replace {
            let to = render_secret_tokens(to_tmpl, secrets)?;
            *item = item.replace(from, &to);
        }
    }

    let mut env = payload.env.unwrap_or_default();
    for (k_tmpl, v_tmpl) in &def.transform.out_env {
        let k = render_secret_tokens(k_tmpl, secrets)?;
        let v = render_secret_tokens(v_tmpl, secrets)?;
        env.insert(k, v);
    }

    let mut stdin_s = payload.stdin.unwrap_or_default();
    for (from, to_tmpl) in &def.transform.out_stdin_replace {
        let to = render_secret_tokens(to_tmpl, secrets)?;
        stdin_s = stdin_s.replace(from, &to);
    }

    Ok((command, argv, env, stdin_s.into_bytes()))
}

fn render_secret_tokens(tmpl: &str, secrets: &BTreeMap<String, String>) -> Result<String, String> {
    let mut out = tmpl.to_string();
    let mut pos = 0usize;
    loop {
        let Some(start_rel) = out[pos..].find('{') else {
            break;
        };
        let start = pos + start_rel;
        let Some(end_rel) = out[start..].find('}') else {
            return Err("non-conforming payload: malformed template token".to_string());
        };
        let end = start + end_rel;
        let name = &out[start + 1..end];
        let Some(value) = secrets.get(name) else {
            return Err(format!("non-conforming payload: unknown secret '{name}'"));
        };
        out.replace_range(start..=end, value);
        pos = start + value.len();
    }
    Ok(out)
}

fn count_placeholders(s: &str) -> usize {
    let mut count = 0usize;
    let mut pos = 0usize;
    while let Some(start_rel) = s[pos..].find('{') {
        let start = pos + start_rel;
        let Some(end_rel) = s[start..].find('}') else {
            break;
        };
        let end = start + end_rel;
        let token = &s[start + 1..end];
        if !token.is_empty() {
            count += 1;
        }
        pos = end + 1;
    }
    count
}

fn run_target(
    command: &str,
    argv: &[String],
    env: &BTreeMap<String, String>,
    stdin_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    if command.is_empty() {
        return Err("empty command".to_string());
    }

    let mut cmd = Command::new(command);
    cmd.args(argv);
    cmd.env_clear();
    cmd.env("PATH", "/run/current-system/sw/bin:/usr/bin:/bin");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("spawn failed: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(stdin_bytes)
            .map_err(|e| format!("write stdin failed: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait failed: {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            return Err("command failed".to_string());
        }
        return Err(stderr.to_string());
    }

    Ok(out.stdout)
}
