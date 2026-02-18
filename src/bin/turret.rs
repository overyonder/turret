use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use base64::Engine;
use serde::{Deserialize, Serialize};

use turret::bunker::Bunker;
use turret::bunker::TargetDef;
use turret::invoke::{execute_invoke, InvokeError, InvokePayload};
use turret::rage;

#[derive(Parser, Debug)]
#[command(name = "turret")]
struct Cli {
    bunker_name: String,
    #[command(subcommand)]
    cmd: CommandGroup,
}

#[derive(Subcommand, Debug)]
enum CommandGroup {
    /// Create a bunker file.
    Dig {
        #[arg(long)]
        weak: bool,
        #[arg(long)]
        operator: Option<String>,
        #[arg(long, default_value = "/run/secrets/homelab_ssh_key")]
        host_ssh_key: PathBuf,
    },

    /// Add entities.
    In {
        #[command(subcommand)]
        cmd: InCmd,
    },

    /// Remove entities.
    Out {
        #[command(subcommand)]
        cmd: OutCmd,
    },

    /// Grant target permission to rookie.
    Allow {
        #[arg(long)]
        rookie: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        operator: PathBuf,
    },

    /// Revoke target permission from rookie.
    Deny {
        #[arg(long)]
        rookie: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        operator: PathBuf,
    },

    /// Start daemon and hold bunker in memory.
    Engage {
        #[arg(long)]
        operator: PathBuf,
        #[arg(long, default_value = "/run/secrets/homelab_ssh_key")]
        host_ssh_key: PathBuf,
    },

    /// Invoke daemon with rookie request.
    Fire {
        #[arg(long)]
        rookie: String,
        #[arg(long)]
        params: Option<String>,
        #[arg(long)]
        params_file: Option<PathBuf>,
    },

    /// Stop daemon.
    Disengage {
        #[arg(long)]
        operator: PathBuf,
        #[arg(long, default_value = "/run/secrets/homelab_ssh_key")]
        host_ssh_key: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum InCmd {
    Operator {
        ident: String,
        #[arg(long)]
        operator: PathBuf,
    },
    Recruit {
        ident: String,
        secret: String,
        #[arg(long)]
        operator: PathBuf,
    },
    Target {
        ident: String,
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        operator: PathBuf,
    },
    Secret {
        ident: String,
        value: String,
        #[arg(long)]
        operator: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum OutCmd {
    Operator {
        ident: String,
        #[arg(long)]
        operator: PathBuf,
    },
    Recruit {
        ident: String,
        #[arg(long)]
        operator: PathBuf,
    },
    Target {
        ident: String,
        #[arg(long)]
        operator: PathBuf,
    },
    Secret {
        ident: String,
        #[arg(long)]
        operator: PathBuf,
    },
}

#[derive(Serialize, Deserialize)]
struct FireResponse {
    ok: bool,
    result_b64: Option<String>,
    code: Option<String>,
    message: Option<String>,
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("turret: {e}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let bunker_path = bunker_path(&cli.bunker_name);
    let sock_path = socket_path(&cli.bunker_name);
    let pid_path = pid_path(&cli.bunker_name);

    match cli.cmd {
        CommandGroup::Dig {
            weak,
            operator,
            host_ssh_key,
        } => {
            if !weak && operator.is_none() {
                return Err("either --weak, --operator, or both are required".into());
            }
            let mut b = Bunker::new();
            let mut ops: BTreeSet<String> = BTreeSet::new();
            if weak {
                ops.insert(ssh_public_key_from_private(&host_ssh_key)?);
            }
            if let Some(op) = operator {
                ops.insert(read_operator_pubkey(&op)?);
            }
            b.operators = ops;
            b.validate()?;
            write_bunker_encrypted(&bunker_path, &b)?;
            eprintln!("turret: wrote bunker {}", bunker_path.display());
            Ok(())
        }

        CommandGroup::In { cmd } => match cmd {
            InCmd::Operator { ident, operator } => {
                let mut b = open_with_identity(&bunker_path, &operator, "operator")?;
                b.operators.insert(read_operator_pubkey(&ident)?);
                b.validate()?;
                write_bunker_encrypted(&bunker_path, &b)?;
                eprintln!("turret: operator added");
                Ok(())
            }
            InCmd::Recruit {
                ident,
                secret,
                operator,
            } => {
                let mut b = open_with_identity(&bunker_path, &operator, "operator")?;
                b.agents.insert(ident, secret);
                b.validate()?;
                write_bunker_encrypted(&bunker_path, &b)?;
                eprintln!("turret: recruit added");
                Ok(())
            }
            InCmd::Target {
                ident,
                from,
                operator,
            } => {
                let mut b = open_with_identity(&bunker_path, &operator, "operator")?;
                let def = read_target_from_file(&from, &ident)?;
                b.targets.insert(ident, def);
                b.validate()?;
                write_bunker_encrypted(&bunker_path, &b)?;
                eprintln!("turret: target added");
                Ok(())
            }
            InCmd::Secret {
                ident,
                value,
                operator,
            } => {
                let mut b = open_with_identity(&bunker_path, &operator, "operator")?;
                b.secrets.insert(ident, value);
                b.validate()?;
                write_bunker_encrypted(&bunker_path, &b)?;
                eprintln!("turret: secret added");
                Ok(())
            }
        },

        CommandGroup::Out { cmd } => match cmd {
            OutCmd::Operator { ident, operator } => {
                let mut b = open_with_identity(&bunker_path, &operator, "operator")?;
                let key = read_operator_pubkey(&ident)?;
                if !b.operators.remove(&key) {
                    return Err("operator not present".into());
                }
                if b.operators.is_empty() {
                    return Err("cannot remove final operator".into());
                }
                b.validate()?;
                write_bunker_encrypted(&bunker_path, &b)?;
                eprintln!("turret: operator removed");
                Ok(())
            }
            OutCmd::Recruit { ident, operator } => {
                let mut b = open_with_identity(&bunker_path, &operator, "operator")?;
                b.agents.remove(&ident);
                b.permissions.remove(&ident);
                b.validate()?;
                write_bunker_encrypted(&bunker_path, &b)?;
                eprintln!("turret: recruit removed");
                Ok(())
            }
            OutCmd::Target { ident, operator } => {
                let mut b = open_with_identity(&bunker_path, &operator, "operator")?;
                b.targets.remove(&ident);
                for allowed in b.permissions.values_mut() {
                    allowed.remove(&ident);
                }
                b.validate()?;
                write_bunker_encrypted(&bunker_path, &b)?;
                eprintln!("turret: target removed");
                Ok(())
            }
            OutCmd::Secret { ident, operator } => {
                let mut b = open_with_identity(&bunker_path, &operator, "operator")?;
                b.secrets.remove(&ident);
                b.validate()?;
                write_bunker_encrypted(&bunker_path, &b)?;
                eprintln!("turret: secret removed");
                Ok(())
            }
        },

        CommandGroup::Allow {
            rookie,
            target,
            operator,
        } => {
            let mut b = open_with_identity(&bunker_path, &operator, "operator")?;
            b.permissions.entry(rookie).or_default().insert(target);
            b.validate()?;
            write_bunker_encrypted(&bunker_path, &b)?;
            eprintln!("turret: permission granted");
            Ok(())
        }

        CommandGroup::Deny {
            rookie,
            target,
            operator,
        } => {
            let mut b = open_with_identity(&bunker_path, &operator, "operator")?;
            if let Some(allowed) = b.permissions.get_mut(&rookie) {
                allowed.remove(&target);
            }
            b.validate()?;
            write_bunker_encrypted(&bunker_path, &b)?;
            eprintln!("turret: permission revoked");
            Ok(())
        }

        CommandGroup::Engage {
            operator,
            host_ssh_key,
        } => {
            if sock_path.exists() || pid_path.exists() {
                return Err("daemon already running (socket/pid exists)".into());
            }
            let bunker = fire_up(&bunker_path, &host_ssh_key, Some(&operator))?;
            std::fs::write(&pid_path, std::process::id().to_string())?;
            run_daemon(&sock_path, bunker)?;
            let _ = std::fs::remove_file(&sock_path);
            let _ = std::fs::remove_file(&pid_path);
            Ok(())
        }

        CommandGroup::Fire {
            rookie,
            params,
            params_file,
        } => {
            let raw = read_fire_params(params, params_file)?;
            let mut v: serde_json::Value =
                serde_json::from_slice(&raw).map_err(|e| format!("invalid fire payload json: {e}"))?;
            let obj = v
                .as_object_mut()
                .ok_or("invalid fire payload json: expected object")?;
            obj.insert("agent_id".to_string(), serde_json::Value::String(rookie));
            let payload: InvokePayload = serde_json::from_value(v)
                .map_err(|e| format!("invalid fire payload json: {e}"))?;

            let mut stream = UnixStream::connect(&sock_path)
                .map_err(|e| format!("connect {}: {e}", sock_path.display()))?;
            let req = serde_json::to_vec(&payload)?;
            stream.write_all(&req)?;
            stream.shutdown(std::net::Shutdown::Write)?;
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp)?;
            let parsed: FireResponse = serde_json::from_slice(&resp)
                .map_err(|e| format!("invalid daemon response: {e}"))?;
            if parsed.ok {
                if let Some(b64) = parsed.result_b64 {
                    let out = base64::engine::general_purpose::STANDARD.decode(b64)?;
                    std::io::stdout().write_all(&out)?;
                    return Ok(());
                }
                return Ok(());
            }
            let code = parsed.code.unwrap_or_else(|| "error".to_string());
            let msg = parsed.message.unwrap_or_else(|| "request failed".to_string());
            return Err(format!("{code}: {msg}").into());
        }

        CommandGroup::Disengage {
            operator,
            host_ssh_key,
        } => {
            let _ = fire_up(&bunker_path, &host_ssh_key, Some(&operator))?;
            let pid_txt = std::fs::read_to_string(&pid_path)
                .map_err(|e| io::Error::new(e.kind(), format!("read {}: {e}", pid_path.display())))?;
            let pid: i32 = pid_txt.trim().parse().map_err(|_| "invalid pid file")?;
            let status = std::process::Command::new("kill")
                .arg(pid.to_string())
                .status()?;
            if !status.success() {
                return Err("failed to stop daemon".into());
            }
            let _ = std::fs::remove_file(&sock_path);
            let _ = std::fs::remove_file(&pid_path);
            eprintln!("turret: disengaged");
            Ok(())
        }
    }
}

fn run_daemon(sock_path: &Path, bunker: Bunker) -> Result<(), Box<dyn std::error::Error>> {
    let listener = UnixListener::bind(sock_path)?;
    eprintln!("turret: engaged on {}", sock_path.display());
    loop {
        let (mut stream, _) = listener.accept()?;
        let mut req = Vec::new();
        stream.read_to_end(&mut req)?;
        let resp = match serde_json::from_slice::<InvokePayload>(&req) {
            Ok(p) => match execute_invoke(&bunker, p) {
                Ok(bytes) => FireResponse {
                    ok: true,
                    result_b64: Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
                    code: None,
                    message: None,
                },
                Err(e) => map_invoke_error(e),
            },
            Err(e) => FireResponse {
                ok: false,
                result_b64: None,
                code: Some("bad_request".to_string()),
                message: Some(format!("invalid json: {e}")),
            },
        };
        let payload = serde_json::to_vec(&resp)?;
        stream.write_all(&payload)?;
    }
}

fn map_invoke_error(e: InvokeError) -> FireResponse {
    let (code, msg) = match e {
        InvokeError::Unauthenticated => ("unauthenticated", "bad agent credentials".to_string()),
        InvokeError::Denied => ("denied", "denied".to_string()),
        InvokeError::UnknownTarget => ("unknown_target", "unknown target".to_string()),
        InvokeError::BadRequest(m) => ("bad_request", m),
        InvokeError::Internal(m) => ("internal", m),
    };
    FireResponse {
        ok: false,
        result_b64: None,
        code: Some(code.to_string()),
        message: Some(msg),
    }
}

fn read_fire_params(
    params: Option<String>,
    params_file: Option<PathBuf>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match (params, params_file) {
        (Some(v), None) => Ok(v.into_bytes()),
        (None, Some(p)) => Ok(std::fs::read(&p)
            .map_err(|e| io::Error::new(e.kind(), format!("read {}: {e}", p.display())))?),
        (Some(_), Some(_)) => Err("provide only one of --params or --params-file".into()),
        (None, None) => Err("missing fire params: use --params or --params-file".into()),
    }
}

fn bunker_path(name: &str) -> PathBuf {
    PathBuf::from(format!("{name}.bnkr"))
}

fn socket_path(name: &str) -> PathBuf {
    PathBuf::from(format!("{name}.sock"))
}

fn pid_path(name: &str) -> PathBuf {
    PathBuf::from(format!("{name}.pid"))
}

fn fire_up(path: &Path, host_ssh_key: &Path, operator_ssh_key: Option<&Path>) -> Result<Bunker, Box<dyn std::error::Error>> {
    eprintln!("turret: opening bunker {}", path.display());
    let enc = std::fs::read(path)
        .map_err(|e| io::Error::new(e.kind(), format!("failed to read bunker {}: {e}", path.display())))?;
    if !rage::looks_like_age_file(&enc) {
        return Err("bunker is not an age file".into());
    }

    eprintln!(
        "turret: attempting host-key decrypt via rage (identity={})",
        host_ssh_key.display()
    );
    let host_pt = rage::decrypt_with_identity_file(&enc, host_ssh_key);
    let pt = match host_pt {
        Ok(p) => p,
        Err(e) => {
            eprintln!("turret: host-key decrypt failed: {e}");
            let Some(op) = operator_ssh_key else {
                return Err("this bunker requires an operator; could not decrypt with host key".into());
            };
            eprintln!(
                "turret: attempting operator decrypt via rage (identity={})",
                op.display()
            );
            rage::decrypt_with_identity_file(&enc, op)
                .map_err(|_| "this operator is not permitted to open this bunker")?
        }
    };
    Ok(Bunker::decode(&pt)?)
}

fn open_with_identity(path: &Path, identity: &Path, label: &str) -> Result<Bunker, Box<dyn std::error::Error>> {
    eprintln!("turret: opening bunker {}", path.display());
    let enc = std::fs::read(path)
        .map_err(|e| io::Error::new(e.kind(), format!("failed to read bunker {}: {e}", path.display())))?;
    if !rage::looks_like_age_file(&enc) {
        return Err("bunker is not an age file".into());
    }
    eprintln!(
        "turret: attempting {label} decrypt via rage (identity={})",
        identity.display()
    );
    let pt = rage::decrypt_with_identity_file(&enc, identity).map_err(|e| format!("decrypt failed: {e}"))?;
    Ok(Bunker::decode(&pt)?)
}

fn write_bunker_encrypted(path: &Path, bunker: &Bunker) -> Result<(), Box<dyn std::error::Error>> {
    let pt = bunker.encode()?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_recips = dir.join(".turret.recipients.tmp");
    let mut recips = String::new();
    for op in &bunker.operators {
        recips.push_str(op);
        recips.push('\n');
    }
    std::fs::write(&tmp_recips, recips)?;
    let tmp_out = dir.join(".turret.bunker.tmp");
    rage::encrypt_to_recipients_file(&pt, &tmp_recips, &tmp_out).map_err(|e| format!("encrypt: {e}"))?;
    std::fs::rename(&tmp_out, path)?;
    let _ = std::fs::remove_file(&tmp_recips);
    Ok(())
}

fn read_operator_pubkey(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    if s.starts_with("ssh-") || s.starts_with("age1") {
        return Ok(s.to_string());
    }
    let p = PathBuf::from(s);
    let txt = std::fs::read_to_string(&p)
        .map_err(|e| io::Error::new(e.kind(), format!("read {}: {e}", p.display())))?;
    Ok(txt.lines().next().unwrap_or("").trim().to_string())
}

fn ssh_public_key_from_private(privkey: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let out = std::process::Command::new("ssh-keygen")
        .args(["-y", "-f"])
        .arg(privkey)
        .output()?;
    if !out.status.success() {
        return Err(
            format!("ssh-keygen -y failed: {}", String::from_utf8_lossy(&out.stderr).trim()).into(),
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[derive(serde::Deserialize)]
struct TargetFile {
    targets: std::collections::BTreeMap<String, TargetDef>,
}

fn read_targets_file(path: &Path) -> Result<std::collections::BTreeMap<String, TargetDef>, Box<dyn std::error::Error>> {
    let txt = std::fs::read_to_string(path)
        .map_err(|e| io::Error::new(e.kind(), format!("read {}: {e}", path.display())))?;
    let tf: TargetFile = toml::from_str(&txt)?;
    if tf.targets.is_empty() {
        return Err("target file has no [targets] entries".into());
    }
    Ok(tf.targets)
}

fn read_target_from_file(path: &Path, ident: &str) -> Result<TargetDef, Box<dyn std::error::Error>> {
    let targets = read_targets_file(path)?;
    targets
        .get(ident)
        .cloned()
        .ok_or_else(|| format!("target '{ident}' not found in {}", path.display()).into())
}
