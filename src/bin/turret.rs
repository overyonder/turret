use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use turret::bunker::Bunker;
use turret::rage;

#[derive(Parser, Debug)]
#[command(name = "turret")]
struct Cli {
    #[command(subcommand)]
    cmd: CommandGroup,
}

#[derive(Subcommand, Debug)]
enum CommandGroup {
    /// Start Turret using the encrypted bunker at PATH.
    Start {
        path: PathBuf,
        #[arg(long, default_value = "/run/secrets/homelab_ssh_key")]
        host_ssh_key: PathBuf,
        #[arg(long)]
        operator_ssh_key: Option<PathBuf>,
        /// Fire-up only (decrypt + decode) and exit 0 on success.
        #[arg(long)]
        check: bool,
    },

    /// Bunker maintenance commands.
    Bunker {
        #[command(subcommand)]
        cmd: BunkerCmd,
    },

    /// Development-only commands.
    Develop {
        #[command(subcommand)]
        cmd: DevelopCmd,
    },
}

#[derive(Subcommand, Debug)]
enum BunkerCmd {
    /// Create a new bunker at PATH.
    ///
    /// Either --weak, --operator, or both are required.
    Init {
        path: PathBuf,
        /// Adds the host SSH key recipient as an operator.
        #[arg(long)]
        weak: bool,
        /// SSH public key (file path or literal) for the initial operator.
        #[arg(long)]
        operator: Option<String>,
        #[arg(long, default_value = "/run/secrets/homelab_ssh_key")]
        host_ssh_key: PathBuf,
    },

    /// Add an operator recipient by re-encrypting the bunker.
    OperatorAdd {
        path: PathBuf,
        #[arg(long)]
        existing: PathBuf,
        #[arg(long)]
        new: String,
    },

    /// Remove an operator recipient by re-encrypting the bunker.
    /// Refuses to remove the final operator.
    OperatorRemove {
        path: PathBuf,
        #[arg(long)]
        existing: PathBuf,
        #[arg(long)]
        remove: String,
    },
}

#[derive(Subcommand, Debug)]
enum DevelopCmd {
    Bunker {
        #[command(subcommand)]
        cmd: DevelopBunkerCmd,
    },
}

#[derive(Subcommand, Debug)]
enum DevelopBunkerCmd {
    /// Dump decrypted bunker plaintext (TOML) to stdout.
    Dump {
        path: PathBuf,
        /// Operator identity file (SSH private key). If omitted, uses host key.
        operator_ssh_key: Option<PathBuf>,
        #[arg(long, default_value = "/run/secrets/homelab_ssh_key")]
        host_ssh_key: PathBuf,
    },
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("turret: {e}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        CommandGroup::Start {
            path,
            host_ssh_key,
            operator_ssh_key,
            check,
        } => {
            let bunker = fire_up(&path, &host_ssh_key, operator_ssh_key.as_deref())?;
            if check {
                eprintln!("turret: fire-up ok");
                return Ok(());
            }

            let cfg = turret::server::ServerConfig::default();
            let server = turret::server::Server::new(cfg, bunker);
            eprintln!("turret: listening on turret-agent.sock and turret-repeater.sock");
            server.run()?;
            Ok(())
        }

        CommandGroup::Bunker { cmd } => match cmd {
            BunkerCmd::Init {
                path,
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
                    let host_pub = ssh_public_key_from_private(&host_ssh_key)?;
                    ops.insert(host_pub);
                }

                if let Some(op) = operator {
                    let op_pub = read_operator_pubkey(&op)?;
                    ops.insert(op_pub);
                }

                b.operators = ops;
                b.validate()?;

                write_bunker_encrypted(&path, &b)?;
                eprintln!("turret: wrote bunker {}", path.display());
                Ok(())
            }

            BunkerCmd::OperatorAdd { path, existing, new } => {
                let mut b = open_with_identity(&path, &existing, "existing")?;
                let op_pub = read_operator_pubkey(&new)?;
                b.operators.insert(op_pub);
                b.validate()?;
                write_bunker_encrypted(&path, &b)?;
                eprintln!("turret: operator added");
                Ok(())
            }

            BunkerCmd::OperatorRemove {
                path,
                existing,
                remove,
            } => {
                let mut b = open_with_identity(&path, &existing, "existing")?;
                let op_pub = read_operator_pubkey(&remove)?;
                let removed = b.operators.remove(&op_pub);
                if !removed {
                    return Err("operator not present".into());
                }
                if b.operators.is_empty() {
                    return Err("cannot remove final operator".into());
                }
                b.validate()?;
                write_bunker_encrypted(&path, &b)?;
                eprintln!("turret: operator removed");
                Ok(())
            }
        },

        CommandGroup::Develop { cmd } => {
            if !cfg!(debug_assertions) {
                return Err("develop commands require debug/test build".into());
            }

            match cmd {
                DevelopCmd::Bunker { cmd } => match cmd {
                    DevelopBunkerCmd::Dump {
                        path,
                        operator_ssh_key,
                        host_ssh_key,
                    } => {
                        let identity = operator_ssh_key.as_deref().unwrap_or(&host_ssh_key);
                        let enc = std::fs::read(&path)?;
                        if !rage::looks_like_age_file(&enc) {
                            return Err("bunker is not an age file".into());
                        }
                        let pt = rage::decrypt_with_identity_file(&enc, identity)
                            .map_err(|e| format!("decrypt: {e}"))?;
                        use std::io::Write;
                        let mut stdout = std::io::stdout().lock();
                        stdout.write_all(&pt)?;
                        Ok(())
                    }
                },
            }
        }
    }
}

fn fire_up(path: &Path, host_ssh_key: &Path, operator_ssh_key: Option<&Path>) -> Result<Bunker, Box<dyn std::error::Error>> {
    eprintln!("turret: opening bunker {}", path.display());
    let enc = std::fs::read(path).map_err(|e| {
        io::Error::new(e.kind(), format!("failed to read bunker {}: {e}", path.display()))
    })?;

    if !rage::looks_like_age_file(&enc) {
        return Err("bunker is not an age file".into());
    }

    eprintln!(
        "turret: attempting host-key decrypt via rage (identity={})",
        host_ssh_key.display()
    );
    let host_pt = rage::decrypt_with_identity_file(&enc, host_ssh_key);
    let (pt, used_operator) = match host_pt {
        Ok(p) => (p, false),
        Err(e) => {
            eprintln!("turret: host-key decrypt failed: {e}");
            let Some(op) = operator_ssh_key else {
                return Err(
                    "this bunker requires an operator; could not decrypt with host key".into(),
                );
            };
            eprintln!(
                "turret: attempting operator decrypt via rage (identity={})",
                op.display()
            );
            match rage::decrypt_with_identity_file(&enc, op) {
                Ok(p) => (p, true),
                Err(e2) => {
                    eprintln!("turret: operator decrypt failed: {e2}");
                    return Err("this operator is not permitted to open this bunker".into());
                }
            }
        }
    };

    if operator_ssh_key.is_some() && !used_operator {
        eprintln!("turret: warning: operator key provided but bunker does not require operator");
    }

    let b = Bunker::decode(&pt)?;
    Ok(b)
}

fn open_with_identity(path: &Path, identity: &Path, label: &str) -> Result<Bunker, Box<dyn std::error::Error>> {
    eprintln!("turret: opening bunker {}", path.display());
    let enc = std::fs::read(path).map_err(|e| {
        io::Error::new(e.kind(), format!("failed to read bunker {}: {e}", path.display()))
    })?;
    if !rage::looks_like_age_file(&enc) {
        return Err("bunker is not an age file".into());
    }

    eprintln!(
        "turret: attempting {label} decrypt via rage (identity={})",
        identity.display()
    );
    let pt = rage::decrypt_with_identity_file(&enc, identity)
        .map_err(|e| format!("decrypt failed: {e}"))?;
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
    rage::encrypt_to_recipients_file(&pt, &tmp_recips, &tmp_out)
        .map_err(|e| format!("encrypt: {e}"))?;

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
        return Err(format!(
            "ssh-keygen -y failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
