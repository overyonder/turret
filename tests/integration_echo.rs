use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tempfile::TempDir;

use turret::bunker::Bunker;
use turret::crypto;
use turret::framing;
use turret::protocol::{Envelope, InvokeBody, MessageType, RegisterBody, ResultBody};
use turret::server::{Server, ServerConfig};

fn ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

fn make_env(sk: &SigningKey, msg_type: MessageType, principal: &[u8], body: Vec<u8>) -> Envelope {
    let ts_ms = ms();
    // Nonce must be unique per (principal, window) to avoid replay rejection.
    let mut nonce = Vec::with_capacity(16);
    nonce.extend_from_slice(&ts_ms.to_be_bytes());
    nonce.extend_from_slice(&(msg_type as u16).to_be_bytes());
    nonce.extend_from_slice(&(body.len() as u16).to_be_bytes());
    while nonce.len() < 16 {
        nonce.push(0);
    }
    let sig = crypto::sign(sk, principal, ts_ms, &nonce, &body);
    Envelope {
        msg_type,
        principal: principal.to_vec(),
        ts_ms,
        nonce,
        body,
        sig: sig.to_bytes(),
    }
}

#[test]
fn integration_echo_repeater_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let agent_sock = tmp.path().join("turret-agent.sock");
    let repeater_sock = tmp.path().join("turret-repeater.sock");

    // Keys
    let mut rng = OsRng;
    let agent_sk = SigningKey::generate(&mut rng);
    let repeater_sk = SigningKey::generate(&mut rng);

    // Bunker
    let mut bunker = Bunker::new();
    // Operators are required in v2 bunker.
    bunker
        .operators
        .insert("ssh-ed25519 AAAA".to_string());
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

    let cfg = ServerConfig {
        agent_sock: PathBuf::from(&agent_sock),
        repeater_sock: PathBuf::from(&repeater_sock),
        replay_window_ms: 120_000,
    };
    let server = Server::new(cfg, bunker);
    let stop = server.stop_flag();

    let th = std::thread::spawn(move || server.run().unwrap());

    // Connect repeater and register.
    let mut rep = loop {
        match std::os::unix::net::UnixStream::connect(&repeater_sock) {
            Ok(s) => break s,
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    let mut rep_w = rep.try_clone().unwrap();

    let reg_body = RegisterBody {
        repeater_id: b"rep-1".to_vec(),
        actions: vec![b"echo".to_vec()],
    }
    .encode()
    .unwrap();
    let reg_env = make_env(&repeater_sk, MessageType::Register, b"rep-1", reg_body);
    framing::write_frame(&mut rep, &reg_env.encode().unwrap()).unwrap();

    // Start a simple echo repeater loop: read invoke, respond with result.
    let rep_th = std::thread::spawn(move || {
        let payload = framing::read_frame(&mut rep).unwrap();
        let env = Envelope::decode(&payload).unwrap();
        assert_eq!(env.msg_type, MessageType::Invoke);
        let inv = InvokeBody::decode(&env.body).unwrap();

        let res_body = ResultBody {
            request_id: inv.request_id,
            result: inv.params,
        }
        .encode()
        .unwrap();
        let res_env = make_env(&repeater_sk, MessageType::Result, b"rep-1", res_body);
        framing::write_frame(&mut rep_w, &res_env.encode().unwrap()).unwrap();
    });

    // Connect agent and invoke.
    let mut agent = std::os::unix::net::UnixStream::connect(&agent_sock).unwrap();
    let inv_body = InvokeBody {
        request_id: b"req-1".to_vec(),
        action: b"echo".to_vec(),
        params: b"payload".to_vec(),
    }
    .encode()
    .unwrap();
    let inv_env = make_env(&agent_sk, MessageType::Invoke, b"agent-1", inv_body);
    framing::write_frame(&mut agent, &inv_env.encode().unwrap()).unwrap();

    let reply = framing::read_frame(&mut agent).unwrap();
    let env = Envelope::decode(&reply).unwrap();
    assert_eq!(env.msg_type, MessageType::Result);
    let res = ResultBody::decode(&env.body).unwrap();
    assert_eq!(res.request_id, b"req-1".to_vec());
    assert_eq!(res.result, b"payload".to_vec());

    rep_th.join().unwrap();

    stop.store(true, Ordering::Relaxed);
    th.join().unwrap();
}
