use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;

use crate::bunker::Bunker;
use crate::crypto;
use crate::framing;
use crate::protocol::{Envelope, MessageType, RegisterBody, InvokeBody, ResultBody, ErrorBody};
use crate::replay::{ReplayCache, ReplayError};

use std::os::unix::net::{UnixListener, UnixStream};
use std::io;

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("protocol: {0}")]
    Protocol(#[from] crate::protocol::ProtocolError),
    #[error("frame: {0}")]
    Frame(#[from] crate::framing::FrameError),
    #[error("bunker: {0}")]
    Bunker(#[from] crate::bunker::BunkerError),
    #[error("crypto: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
}

#[derive(Clone)]
pub struct ServerConfig {
    pub agent_sock: PathBuf,
    pub repeater_sock: PathBuf,
    pub replay_window_ms: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            agent_sock: PathBuf::from("turret-agent.sock"),
            repeater_sock: PathBuf::from("turret-repeater.sock"),
            replay_window_ms: 120_000,
        }
    }
}

#[derive(Clone)]
struct AgentHandle {
    write: Arc<Mutex<UnixStream>>,
}

#[derive(Clone)]
struct RepeaterSession {
    write: Arc<Mutex<UnixStream>>,
    registered_actions: Arc<Mutex<HashSet<Vec<u8>>>>,
}

#[derive(Clone)]
struct SharedState {
    bunker: Arc<Bunker>,
    replay: Arc<Mutex<ReplayCache>>,

    // repeater_id -> session
    repeaters: Arc<Mutex<HashMap<Vec<u8>, RepeaterSession>>>,
    // request_id -> agent writer
    pending: Arc<Mutex<HashMap<Vec<u8>, AgentHandle>>>,
}

pub struct Server {
    cfg: ServerConfig,
    state: SharedState,
    stop: Arc<AtomicBool>,
}

impl Server {
    pub fn new(cfg: ServerConfig, bunker: Bunker) -> Self {
        let state = SharedState {
            bunker: Arc::new(bunker),
            replay: Arc::new(Mutex::new(ReplayCache::new(cfg.replay_window_ms))),
            repeaters: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
        };
        Self {
            cfg,
            state,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    pub fn run(&self) -> Result<(), ServerError> {
        remove_if_exists(&self.cfg.agent_sock)?;
        remove_if_exists(&self.cfg.repeater_sock)?;

        let agent = UnixListener::bind(&self.cfg.agent_sock)?;
        let repeater = UnixListener::bind(&self.cfg.repeater_sock)?;

        agent.set_nonblocking(true)?;
        repeater.set_nonblocking(true)?;

        let state_a = self.state.clone();
        let stop_a = self.stop.clone();
        let agent_thread = std::thread::spawn(move || accept_loop(agent, stop_a, state_a, PeerKind::Agent));

        let state_r = self.state.clone();
        let stop_r = self.stop.clone();
        let repeater_thread = std::thread::spawn(move || {
            accept_loop(repeater, stop_r, state_r, PeerKind::Repeater)
        });

        let _ = agent_thread.join();
        let _ = repeater_thread.join();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerKind {
    Agent,
    Repeater,
}

fn accept_loop(listener: UnixListener, stop: Arc<AtomicBool>, state: SharedState, kind: PeerKind) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let state2 = state.clone();
                std::thread::spawn(move || {
                    if let Err(e) = peer_read_loop(stream, state2, kind) {
                        eprintln!("peer loop ended: {e}");
                    }
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                eprintln!("accept error: {e}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn peer_read_loop(mut stream: UnixStream, state: SharedState, kind: PeerKind) -> Result<(), ServerError> {
    let write = Arc::new(Mutex::new(stream.try_clone()?));

    // For repeaters, we want to remember which repeater_id this connection became after registration.
    let mut repeater_id_for_conn: Option<Vec<u8>> = None;

    loop {
        let payload = match framing::read_frame(&mut stream) {
            Ok(p) => p,
            Err(crate::framing::FrameError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        };

        let env = Envelope::decode(&payload)?;
        let now_ms = now_ms();

        // Verify principal is known + signature valid + anti-replay.
        let vk = lookup_vk(&state.bunker, &env.principal)
            .ok_or(crate::crypto::CryptoError::BadSignature)?;

        {
            let mut replay = state.replay.lock().unwrap();
            match replay.check_and_record(now_ms, env.ts_ms, &env.principal, &env.nonce) {
                Ok(()) => {}
                Err(ReplayError::OutsideWindow) | Err(ReplayError::Replay) => {
                    // Best-effort: if this is an agent invoke, reply with error.
                    if kind == PeerKind::Agent {
                        let req_id = if env.msg_type == MessageType::Invoke {
                            InvokeBody::decode(&env.body).ok().map(|b| b.request_id)
                        } else {
                            None
                        };
                        if let Some(request_id) = req_id {
                            send_error(&write, &request_id, crate::protocol::ErrorCode::Replay, b"replay")?;
                        }
                    }
                    continue;
                }
            }
        }

        crypto::verify(&vk, &env.principal, env.ts_ms, &env.nonce, &env.body, &env.signature())?;

        match (kind, env.msg_type) {
            (PeerKind::Repeater, MessageType::Register) => {
                let body = RegisterBody::decode(&env.body)?;
                if env.principal != body.repeater_id {
                    continue;
                }
                let rep_id = match std::str::from_utf8(&body.repeater_id) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if !state.bunker.repeaters.contains_key(rep_id) {
                    continue;
                }

                // Check each advertised action belongs to this repeater in the action registry.
                let mut reg_actions = HashSet::new();
                for a in body.actions {
                    let a_str = match std::str::from_utf8(&a) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    if let Some(owner) = state.bunker.actions.get(a_str) {
                        if owner.as_bytes() == body.repeater_id.as_slice() {
                            reg_actions.insert(a);
                        }
                    }
                }

                let session = RepeaterSession {
                    write: write.clone(),
                    registered_actions: Arc::new(Mutex::new(reg_actions)),
                };

                {
                    let mut reps = state.repeaters.lock().unwrap();
                    reps.insert(body.repeater_id.clone(), session);
                }
                repeater_id_for_conn = Some(body.repeater_id);
            }
            (PeerKind::Agent, MessageType::Invoke) => {
                let body = InvokeBody::decode(&env.body)?;

                let agent_id = match std::str::from_utf8(&env.principal) {
                    Ok(s) => s,
                    Err(_) => {
                        send_error(&write, &body.request_id, crate::protocol::ErrorCode::Unauthenticated, b"bad principal")?;
                        continue;
                    }
                };
                let action_str = match std::str::from_utf8(&body.action) {
                    Ok(s) => s,
                    Err(_) => {
                        send_error(&write, &body.request_id, crate::protocol::ErrorCode::BadRequest, b"bad action")?;
                        continue;
                    }
                };

                // Permission checks.
                let allowed = state
                    .bunker
                    .permissions
                    .get(agent_id)
                    .map(|s| s.contains(action_str))
                    .unwrap_or(false);
                if !allowed {
                    send_error(&write, &body.request_id, crate::protocol::ErrorCode::Denied, b"denied")?;
                    continue;
                }

                let repeater_id = match state.bunker.actions.get(action_str) {
                    Some(id) => id.as_bytes().to_vec(),
                    None => {
                        send_error(
                            &write,
                            &body.request_id,
                            crate::protocol::ErrorCode::UnknownAction,
                            b"unknown action",
                        )?;
                        continue;
                    }
                };

                let session = {
                    let reps = state.repeaters.lock().unwrap();
                    reps.get(&repeater_id).cloned()
                };
                let Some(session) = session else {
                    send_error(
                        &write,
                        &body.request_id,
                        crate::protocol::ErrorCode::NoRepeater,
                        b"no repeater",
                    )?;
                    continue;
                };

                let has_action = session
                    .registered_actions
                    .lock()
                    .unwrap()
                    .contains(&body.action);
                if !has_action {
                    send_error(
                        &write,
                        &body.request_id,
                        crate::protocol::ErrorCode::NoRepeater,
                        b"repeater not registered for action",
                    )?;
                    continue;
                }

                // Track pending request so repeater results can be routed.
                {
                    let mut pending = state.pending.lock().unwrap();
                    pending.insert(
                        body.request_id.clone(),
                        AgentHandle {
                            write: write.clone(),
                        },
                    );
                }

                // Forward the *original* signed envelope bytes to the repeater.
                {
                    let mut w = session.write.lock().unwrap();
                    framing::write_frame(&mut *w, &payload)?;
                }
            }
            (PeerKind::Repeater, MessageType::Result) => {
                let body = ResultBody::decode(&env.body)?;
                route_reply(&state, &body.request_id, &payload);
            }
            (PeerKind::Repeater, MessageType::Error) => {
                let body = ErrorBody::decode(&env.body)?;
                route_reply(&state, &body.request_id, &payload);
            }
            _ => {
                // Ignore unsupported message types for this peer kind for now.
            }
        }
    }

    // Best-effort: on repeater disconnect, drop session.
    if let Some(rep_id) = repeater_id_for_conn {
        let mut reps = state.repeaters.lock().unwrap();
        reps.remove(&rep_id);
    }
    Ok(())
}

fn route_reply(state: &SharedState, request_id: &[u8], payload: &[u8]) {
    let agent = {
        let mut pending = state.pending.lock().unwrap();
        pending.remove(request_id)
    };
    let Some(agent) = agent else { return; };
    let mut w = agent.write.lock().unwrap();
    let _ = framing::write_frame(&mut *w, payload);
}

fn send_error(
    write: &Arc<Mutex<UnixStream>>,
    request_id: &[u8],
    code: crate::protocol::ErrorCode,
    message: &[u8],
) -> Result<(), ServerError> {
    let body = crate::protocol::ErrorBody {
        request_id: request_id.to_vec(),
        code,
        message: message.to_vec(),
    }
    .encode()?;

    // For scaffolding: unsigned error envelope (sig = 64x0). Agents should treat
    // these as best-effort until Turret has its own principal/key.
    let env = Envelope {
        msg_type: MessageType::Error,
        principal: b"turret".to_vec(),
        ts_ms: now_ms(),
        nonce: vec![0u8; 16],
        body,
        sig: [0u8; 64],
    };
    let payload = env.encode()?;
    let mut w = write.lock().unwrap();
    framing::write_frame(&mut *w, &payload)?;
    Ok(())
}

fn lookup_vk(bunker: &Bunker, principal: &[u8]) -> Option<VerifyingKey> {
    let p = std::str::from_utf8(principal).ok()?;
    if let Some(pk) = bunker.agents.get(p) {
        return VerifyingKey::from_bytes(pk).ok();
    }
    if let Some(pk) = bunker.repeaters.get(p) {
        return VerifyingKey::from_bytes(pk).ok();
    }
    None
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

fn remove_if_exists(p: &Path) -> io::Result<()> {
    match std::fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}
