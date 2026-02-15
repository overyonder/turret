use std::io;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;

use turret::crypto;
use turret::framing;
use turret::protocol::{Envelope, InvokeBody, MessageType, RegisterBody, ResultBody};

fn main() {
    if let Err(e) = real_main() {
        eprintln!("echo-repeater: {e}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let repeater_id = std::env::var("TURRET_REPEATER_ID").unwrap_or_else(|_| "echo".to_string());
    let sock = std::env::var_os("TURRET_REPEATER_SOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("turret-repeater.sock"));

    let sk = load_signing_key()?;

    let mut stream = std::os::unix::net::UnixStream::connect(&sock).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("connect {}: {e}", sock.display()),
        )
    })?;
    let mut stream_w = stream.try_clone()?;

    // Register supported actions.
    let reg_body = RegisterBody {
        repeater_id: repeater_id.as_bytes().to_vec(),
        actions: vec![b"echo".to_vec()],
    }
    .encode()?;
    let reg_env = signed_env(&sk, MessageType::Register, repeater_id.as_bytes(), reg_body);
    framing::write_frame(&mut stream_w, &reg_env.encode()?)?;

    eprintln!("echo-repeater: registered as {repeater_id} on {}", sock.display());

    loop {
        let payload = framing::read_frame(&mut stream)?;
        let env = Envelope::decode(&payload)?;

        if env.msg_type != MessageType::Invoke {
            continue;
        }

        let inv = InvokeBody::decode(&env.body)?;
        // Deterministic echo: return params as result.
        let res_body = ResultBody {
            request_id: inv.request_id,
            result: inv.params,
        }
        .encode()?;

        let res_env = signed_env(&sk, MessageType::Result, repeater_id.as_bytes(), res_body);
        framing::write_frame(&mut stream_w, &res_env.encode()?)?;
    }
}

fn signed_env(sk: &SigningKey, msg_type: MessageType, principal: &[u8], body: Vec<u8>) -> Envelope {
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);

    let sig = crypto::sign(sk, principal, ts_ms, &nonce, &body);

    Envelope {
        msg_type,
        principal: principal.to_vec(),
        ts_ms,
        nonce: nonce.to_vec(),
        body,
        sig: sig.to_bytes(),
    }
}

fn load_signing_key() -> Result<SigningKey, Box<dyn std::error::Error>> {
    // v0: load from raw 32-byte seed file.
    let seed_path = std::env::var_os("TURRET_REPEATER_SEED")
        .ok_or("missing TURRET_REPEATER_SEED (path to 32-byte seed file)")
        .map(PathBuf::from)?;
    let seed = std::fs::read(&seed_path)
        .map_err(|e| io::Error::new(e.kind(), format!("read {}: {e}", seed_path.display())))?;
    if seed.len() != 32 {
        return Err(format!("seed must be 32 bytes, got {}", seed.len()).into());
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&seed);
    Ok(SigningKey::from_bytes(&b))
}
