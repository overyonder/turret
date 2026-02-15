use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

fn turret_bin() -> &'static str {
    env!("CARGO_BIN_EXE_turret")
}

fn run_turret(args: &[&str]) -> (i32, String) {
    let out = Command::new(turret_bin())
        .args(args)
        .output()
        .expect("run turret");
    let code = out.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (code, stderr)
}

fn assert_contains(hay: &str, needle: &str) {
    assert!(
        hay.contains(needle),
        "expected stderr to contain {needle:?}, got:\n{hay}"
    );
}

fn gen_ssh_keypair(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    std::fs::create_dir_all(dir).unwrap();
    let privk = dir.join(name);
    let pubk = dir.join(format!("{name}.pub"));
    let out = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f"])
        .arg(&privk)
        .output()
        .expect("run ssh-keygen");
    assert!(out.status.success(), "ssh-keygen failed");
    assert!(privk.exists());
    assert!(pubk.exists());
    (privk, pubk)
}

#[test]
fn bunker_init_strong_requires_operator() {
    let tmp = TempDir::new().unwrap();
    let bunker_age = tmp.path().join("bunker.age");

    // Generate an isolated host identity.
    let (host_priv, _host_pub) = gen_ssh_keypair(tmp.path(), "host_ed25519");

    // Strong bunker: only operator recipient, so host decrypt should fail.
    let (op_priv, op_pub) = gen_ssh_keypair(tmp.path(), "op_ed25519");
    let op_recipient = std::fs::read_to_string(&op_pub).unwrap();

    let (code, stderr) = run_turret(&[
        "bunker",
        "init",
        bunker_age.to_str().unwrap(),
        "--operator",
        op_recipient.trim(),
        "--host-ssh-key",
        host_priv.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "init failed: {stderr}");

    let (code, stderr) = run_turret(&[
        "start",
        bunker_age.to_str().unwrap(),
        "--check",
        "--host-ssh-key",
        host_priv.to_str().unwrap(),
    ]);
    assert!(code != 0);
    assert_contains(
        &stderr,
        "this bunker requires an operator; could not decrypt with host key",
    );

    let (code, stderr) = run_turret(&[
        "start",
        bunker_age.to_str().unwrap(),
        "--check",
        "--host-ssh-key",
        host_priv.to_str().unwrap(),
        "--operator-ssh-key",
        op_priv.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "start --check failed: {stderr}");
    assert_contains(&stderr, "fire-up ok");
}

#[test]
fn bunker_operator_add_and_remove_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let bunker_age = tmp.path().join("bunker.age");
    let (host_priv, _host_pub) = gen_ssh_keypair(tmp.path(), "host_ed25519");

    // Initial strong bunker with operator-1.
    let (op1_priv, op1_pub) = gen_ssh_keypair(tmp.path(), "op1_ed25519");
    let op1_recipient = std::fs::read_to_string(&op1_pub).unwrap();

    let (code, stderr) = run_turret(&[
        "bunker",
        "init",
        bunker_age.to_str().unwrap(),
        "--operator",
        op1_recipient.trim(),
        "--host-ssh-key",
        host_priv.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "init failed: {stderr}");

    // Add operator-2.
    let (op2_priv, op2_pub) = gen_ssh_keypair(tmp.path(), "op2_ed25519");
    let op2_recipient = std::fs::read_to_string(&op2_pub).unwrap();
    let (code, stderr) = run_turret(&[
        "bunker",
        "operator-add",
        bunker_age.to_str().unwrap(),
        "--existing",
        op1_priv.to_str().unwrap(),
        "--new",
        op2_recipient.trim(),
    ]);
    assert_eq!(code, 0, "operator-add failed: {stderr}");
    assert_contains(&stderr, "operator added");

    // Verify operator-2 can fire-up.
    let (code, stderr) = run_turret(&[
        "start",
        bunker_age.to_str().unwrap(),
        "--check",
        "--host-ssh-key",
        host_priv.to_str().unwrap(),
        "--operator-ssh-key",
        op2_priv.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "operator-2 start failed: {stderr}");
    assert_contains(&stderr, "fire-up ok");

    // Remove operator-1; operator-2 should remain.
    let (code, stderr) = run_turret(&[
        "bunker",
        "operator-remove",
        bunker_age.to_str().unwrap(),
        "--existing",
        op2_priv.to_str().unwrap(),
        "--remove",
        op1_recipient.trim(),
    ]);
    assert_eq!(code, 0, "operator-remove failed: {stderr}");
    assert_contains(&stderr, "operator removed");

    // Refuse to remove the final operator.
    let (code, stderr) = run_turret(&[
        "bunker",
        "operator-remove",
        bunker_age.to_str().unwrap(),
        "--existing",
        op2_priv.to_str().unwrap(),
        "--remove",
        op2_recipient.trim(),
    ]);
    assert!(code != 0);
    assert_contains(&stderr, "cannot remove final operator");
}
