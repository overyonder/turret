use std::io;
use std::path::Path;
use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum RageError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("rage failed: {0}")]
    RageFailed(String),
}

pub fn decrypt_with_identity_file(enc: &[u8], identity: &Path) -> Result<Vec<u8>, RageError> {
    let mut child = Command::new("rage")
        .arg("--decrypt")
        .arg("-i")
        .arg(identity)
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    {
        use std::io::Write;
        let mut stdin = child.stdin.take().ok_or_else(|| io::Error::other("rage stdin unavailable"))?;
        stdin.write_all(enc)?;
    }

    let out = child.wait_with_output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(RageError::RageFailed(stderr.trim().to_string()));
    }
    Ok(out.stdout)
}

pub fn encrypt_to_recipients_file(plaintext: &[u8], recipients_file: &Path, out_path: &Path) -> Result<(), RageError> {
    let mut child = Command::new("rage")
        .arg("--encrypt")
        .arg("-R")
        .arg(recipients_file)
        .arg("-o")
        .arg(out_path)
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    {
        use std::io::Write;
        let mut stdin = child.stdin.take().ok_or_else(|| io::Error::other("rage stdin unavailable"))?;
        stdin.write_all(plaintext)?;
    }

    let out = child.wait_with_output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(RageError::RageFailed(stderr.trim().to_string()));
    }
    Ok(())
}

pub fn looks_like_age_file(enc: &[u8]) -> bool {
    enc.starts_with(b"age-encryption.org/")
}
