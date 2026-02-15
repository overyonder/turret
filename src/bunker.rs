use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bunker {
    pub operators: BTreeSet<String>,
    pub agents: BTreeMap<String, [u8; 32]>,
    pub repeaters: BTreeMap<String, [u8; 32]>,
    pub actions: BTreeMap<String, String>,
    pub permissions: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, thiserror::Error)]
pub enum BunkerError {
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("toml ser: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("bad bunker: {0}")]
    Bad(&'static str),
    #[error("bad bunker: {0}")]
    BadOwned(String),
}

impl Bunker {
    pub fn new() -> Self {
        Self {
            operators: BTreeSet::new(),
            agents: BTreeMap::new(),
            repeaters: BTreeMap::new(),
            actions: BTreeMap::new(),
            permissions: BTreeMap::new(),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BunkerError> {
        let s = std::str::from_utf8(bytes).map_err(|_| BunkerError::Bad("bunker plaintext is not utf-8"))?;
        let t: TomlBunker = toml::from_str(s)?;
        t.try_into()
    }

    pub fn encode(&self) -> Result<Vec<u8>, BunkerError> {
        let t: TomlBunker = self.clone().into();
        let s = toml::to_string_pretty(&t)?;
        Ok(s.into_bytes())
    }

    pub fn validate(&self) -> Result<(), BunkerError> {
        if self.operators.is_empty() {
            return Err(BunkerError::Bad("no operators"));
        }

        for rep in self.actions.values() {
            if !self.repeaters.contains_key(rep) {
                return Err(BunkerError::Bad("action references unknown repeater"));
            }
        }

        for (agent, allowed) in &self.permissions {
            if !self.agents.contains_key(agent) {
                return Err(BunkerError::Bad("permission references unknown agent"));
            }
            for action in allowed {
                if !self.actions.contains_key(action) {
                    return Err(BunkerError::Bad("permission references unknown action"));
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TomlBunker {
    version: u32,
    operators: Operators,

    #[serde(default)]
    agents: BTreeMap<String, KeyEntry>,
    #[serde(default)]
    repeaters: BTreeMap<String, KeyEntry>,
    #[serde(default)]
    actions: BTreeMap<String, String>,
    #[serde(default)]
    permissions: BTreeMap<String, PermissionEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Operators {
    recipients: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct KeyEntry {
    ed25519_pubkey_b64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PermissionEntry {
    allow: Vec<String>,
}

impl From<Bunker> for TomlBunker {
    fn from(b: Bunker) -> Self {
        let operators = Operators {
            recipients: b.operators.into_iter().collect(),
        };

        let agents = b
            .agents
            .into_iter()
            .map(|(id, pk)| {
                (
                    id,
                    KeyEntry {
                        ed25519_pubkey_b64: B64.encode(pk),
                    },
                )
            })
            .collect();

        let repeaters = b
            .repeaters
            .into_iter()
            .map(|(id, pk)| {
                (
                    id,
                    KeyEntry {
                        ed25519_pubkey_b64: B64.encode(pk),
                    },
                )
            })
            .collect();

        let permissions = b
            .permissions
            .into_iter()
            .map(|(agent, allowed)| {
                (
                    agent,
                    PermissionEntry {
                        allow: allowed.into_iter().collect(),
                    },
                )
            })
            .collect();

        Self {
            version: 1,
            operators,
            agents,
            repeaters,
            actions: b.actions,
            permissions,
        }
    }
}

impl TryFrom<TomlBunker> for Bunker {
    type Error = BunkerError;

    fn try_from(t: TomlBunker) -> Result<Self, Self::Error> {
        if t.version != 1 {
            return Err(BunkerError::Bad("unsupported bunker version"));
        }

        let operators: BTreeSet<String> = t.operators.recipients.into_iter().collect();

        let agents = decode_keys(t.agents)?;
        let repeaters = decode_keys(t.repeaters)?;

        let permissions: BTreeMap<String, BTreeSet<String>> = t
            .permissions
            .into_iter()
            .map(|(agent, p)| (agent, p.allow.into_iter().collect()))
            .collect();

        let b = Bunker {
            operators,
            agents,
            repeaters,
            actions: t.actions,
            permissions,
        };
        b.validate()?;
        Ok(b)
    }
}

fn decode_keys(m: BTreeMap<String, KeyEntry>) -> Result<BTreeMap<String, [u8; 32]>, BunkerError> {
    let mut out = BTreeMap::new();
    for (id, e) in m {
        let bytes = B64
            .decode(e.ed25519_pubkey_b64.as_bytes())
            .map_err(|_| BunkerError::BadOwned(format!("bad base64 pubkey for {id}")))?;
        if bytes.len() != 32 {
            return Err(BunkerError::BadOwned(format!("pubkey for {id} must be 32 bytes")));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&bytes);
        out.insert(id, pk);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bunker_toml_roundtrip() {
        let mut b = Bunker::new();
        b.operators.insert("ssh-ed25519 AAAA".to_string());
        b.agents.insert("agent".to_string(), [1u8; 32]);
        b.repeaters.insert("rep".to_string(), [2u8; 32]);
        b.actions.insert("echo".to_string(), "rep".to_string());
        b.permissions
            .insert("agent".to_string(), BTreeSet::from(["echo".to_string()]));

        let enc = b.encode().unwrap();
        let dec = Bunker::decode(&enc).unwrap();
        assert_eq!(dec, b);
    }
}
