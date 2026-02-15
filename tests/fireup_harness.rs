use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tempfile::TempDir;

use turret::bunker::Bunker;

fn host_ssh_key() -> PathBuf {
    PathBuf::from("/run/secrets/homelab_ssh_key")
}

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

fn ssh_public_key_from_private(identity: &Path) -> String {
    // Returns "ssh-ed25519 AAAA..." (or similar) suitable for `age -r`.
    let out = Command::new("ssh-keygen")
        .args(["-y", "-f"])
        .arg(identity)
        .output()
        .expect("run ssh-keygen -y -f");
    assert!(out.status.success(), "ssh-keygen -y failed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn rage_encrypt_to_recipient(plaintext: &[u8], recipient: &str, out_path: &Path) {
    let mut child = Command::new("rage")
        .args(["-r", recipient, "-o"])
        .arg(out_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn rage encrypt");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(plaintext).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "rage encrypt failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn make_bunker_plaintext() -> Vec<u8> {
    let mut rng = OsRng;
    let agent_sk = SigningKey::generate(&mut rng);
    let repeater_sk = SigningKey::generate(&mut rng);
    let mut bunker = Bunker::new();
    bunker.operators.insert("ssh-ed25519 AAAA".to_string());
    bunker
        .agents
        .insert("agent-1".to_string(), agent_sk.verifying_key().to_bytes());
    bunker.repeaters.insert(
        "rep-1".to_string(),
        repeater_sk.verifying_key().to_bytes(),
    );
    bunker
        .actions
        .insert("echo".to_string(), "rep-1".to_string());
    bunker.permissions.insert(
        "agent-1".to_string(),
        BTreeSet::from(["echo".to_string()]),
    );
    bunker.validate().unwrap();
    bunker.encode().unwrap()
}

fn gen_operator_ssh_keypair(dir: &Path) -> (PathBuf, PathBuf) {
    std::fs::create_dir_all(dir).unwrap();
    let privk = dir.join("op_ed25519");
    let pubk = dir.join("op_ed25519.pub");
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
fn minimum_arguments_requires_bunker() {
    let (code, stderr) = run_turret(&["start", "--check"]);
    assert!(code != 0);
    assert_contains(&stderr, "required");
}

#[test]
fn strong_bunker_no_operator_fails_host_decrypt() {
    let tmp = TempDir::new().unwrap();
    let plaintext = make_bunker_plaintext();

    let (op_priv, _op_pub) = gen_operator_ssh_keypair(tmp.path());
    let op_recipient = ssh_public_key_from_private(&op_priv);

    let bunker_age = tmp.path().join("bunker.age");
    rage_encrypt_to_recipient(&plaintext, &op_recipient, &bunker_age);

    let (code, stderr) = run_turret(&[
        "start",
        bunker_age.to_str().unwrap(),
        "--check",
        "--host-ssh-key",
        host_ssh_key().to_str().unwrap(),
    ]);
    assert!(code != 0);
    assert_contains(&stderr, "opening bunker");
    assert_contains(&stderr, "attempting host-key decrypt");
    assert_contains(
        &stderr,
        "this bunker requires an operator; could not decrypt with host key",
    );
}

#[test]
fn weak_bunker_correct_operator_warns_and_continues() {
    let tmp = TempDir::new().unwrap();
    let plaintext = make_bunker_plaintext();

    let host_recipient = ssh_public_key_from_private(&host_ssh_key());
    let bunker_age = tmp.path().join("bunker.age");
    rage_encrypt_to_recipient(&plaintext, &host_recipient, &bunker_age);

    let (op_priv, _op_pub) = gen_operator_ssh_keypair(tmp.path());

    let (code, stderr) = run_turret(&[
        "start",
        bunker_age.to_str().unwrap(),
        "--check",
        "--host-ssh-key",
        host_ssh_key().to_str().unwrap(),
        "--operator-ssh-key",
        op_priv.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert_contains(&stderr, "attempting host-key decrypt");
    assert_contains(&stderr, "warning: operator key provided");
    assert_contains(&stderr, "fire-up ok");
}

#[test]
fn strong_bunker_wrong_operator_fails() {
    let tmp = TempDir::new().unwrap();
    let plaintext = make_bunker_plaintext();

    let (op_priv, _op_pub) = gen_operator_ssh_keypair(tmp.path());
    let op_recipient = ssh_public_key_from_private(&op_priv);

    let bunker_age = tmp.path().join("bunker.age");
    rage_encrypt_to_recipient(&plaintext, &op_recipient, &bunker_age);

    let (wrong_priv, _wrong_pub) = gen_operator_ssh_keypair(&tmp.path().join("wrong"));

    let (code, stderr) = run_turret(&[
        "start",
        bunker_age.to_str().unwrap(),
        "--check",
        "--host-ssh-key",
        host_ssh_key().to_str().unwrap(),
        "--operator-ssh-key",
        wrong_priv.to_str().unwrap(),
    ]);
    assert!(code != 0);
    assert_contains(&stderr, "attempting host-key decrypt");
    assert_contains(&stderr, "attempting operator decrypt");
    assert_contains(&stderr, "this operator is not permitted to open this bunker");
}

#[test]
fn strong_bunker_correct_operator_succeeds() {
    let tmp = TempDir::new().unwrap();
    let plaintext = make_bunker_plaintext();

    let (op_priv, _op_pub) = gen_operator_ssh_keypair(tmp.path());
    let op_recipient = ssh_public_key_from_private(&op_priv);

    let bunker_age = tmp.path().join("bunker.age");
    rage_encrypt_to_recipient(&plaintext, &op_recipient, &bunker_age);

    let (code, stderr) = run_turret(&[
        "start",
        bunker_age.to_str().unwrap(),
        "--check",
        "--host-ssh-key",
        host_ssh_key().to_str().unwrap(),
        "--operator-ssh-key",
        op_priv.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert_contains(&stderr, "host-key decrypt failed");
    assert_contains(&stderr, "attempting operator decrypt");
    assert_contains(&stderr, "fire-up ok");
}

#[test]
fn bunker_path_missing_errors() {
    let tmp = TempDir::new().unwrap();
    let missing = tmp.path().join("missing.age");
    let (code, stderr) = run_turret(&["start", missing.to_str().unwrap(), "--check"]);
    assert!(code != 0);
    assert_contains(&stderr, "failed to read bunker");
}

#[test]
fn bunker_not_age_file_errors() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("bunker.notage");
    std::fs::write(&p, b"not-age").unwrap();
    let (code, stderr) = run_turret(&["start", p.to_str().unwrap(), "--check"]);
    assert!(code != 0);
    assert_contains(&stderr, "bunker is not an age file");
}
