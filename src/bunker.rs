use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetShape {
    #[serde(default)]
    pub allow: BTreeSet<String>,
    #[serde(default)]
    pub forbid: BTreeSet<String>,
    #[serde(default)]
    pub require: BTreeSet<String>,
    #[serde(default)]
    pub argv_placeholders: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetTransform {
    pub out_command: String,
    #[serde(default)]
    pub out_argv_replace: BTreeMap<String, String>,
    #[serde(default)]
    pub out_env: BTreeMap<String, String>,
    #[serde(default)]
    pub out_stdin_replace: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetDef {
    pub shape: TargetShape,
    pub transform: TargetTransform,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bunker {
    pub operators: BTreeSet<String>,
    pub agents: BTreeMap<String, String>,
    pub targets: BTreeMap<String, TargetDef>,
    pub permissions: BTreeMap<String, BTreeSet<String>>,
    pub secrets: BTreeMap<String, String>,
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
            targets: BTreeMap::new(),
            permissions: BTreeMap::new(),
            secrets: BTreeMap::new(),
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

        for (agent, allowed) in &self.permissions {
            if !self.agents.contains_key(agent) {
                return Err(BunkerError::Bad("permission references unknown agent"));
            }
            for target in allowed {
                if !self.targets.contains_key(target) {
                    return Err(BunkerError::Bad("permission references unknown target"));
                }
            }
        }

        for (target_name, def) in &self.targets {
            if target_name.is_empty() {
                return Err(BunkerError::Bad("empty target name"));
            }
            if def.transform.out_command.trim().is_empty() {
                return Err(BunkerError::Bad("target out_command is empty"));
            }

            for field in def
                .shape
                .allow
                .iter()
                .chain(def.shape.forbid.iter())
                .chain(def.shape.require.iter())
            {
                if !matches!(field.as_str(), "command" | "argv" | "env" | "stdin") {
                    return Err(BunkerError::Bad("target shape has unknown field"));
                }
            }

            for field in &def.shape.require {
                if def.shape.forbid.contains(field) {
                    return Err(BunkerError::Bad("target shape conflicts: field both required and forbidden"));
                }
            }

            for s in collect_secret_refs(def) {
                if !self.secrets.contains_key(&s) {
                    return Err(BunkerError::BadOwned(format!("target references unknown secret '{s}'")));
                }
            }
        }

        Ok(())
    }
}

fn collect_secret_refs(def: &TargetDef) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    collect_refs_from_string(&def.transform.out_command, &mut out);
    for v in def.transform.out_argv_replace.values() {
        collect_refs_from_string(v, &mut out);
    }
    for (k, v) in &def.transform.out_env {
        collect_refs_from_string(k, &mut out);
        collect_refs_from_string(v, &mut out);
    }
    for v in def.transform.out_stdin_replace.values() {
        collect_refs_from_string(v, &mut out);
    }
    out
}

fn collect_refs_from_string(s: &str, out: &mut BTreeSet<String>) {
    let mut pos = 0usize;
    while let Some(start_rel) = s[pos..].find('{') {
        let start = pos + start_rel;
        let Some(end_rel) = s[start..].find('}') else { break };
        let end = start + end_rel;
        let token = &s[start + 1..end];
        if !token.is_empty()
            && token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            out.insert(token.to_string());
        }
        pos = end + 1;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TomlBunker {
    version: u32,
    operators: Operators,
    #[serde(default)]
    agents: BTreeMap<String, String>,
    #[serde(default)]
    targets: BTreeMap<String, TargetDef>,
    #[serde(default)]
    permissions: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    secrets: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Operators {
    recipients: Vec<String>,
}

impl From<Bunker> for TomlBunker {
    fn from(b: Bunker) -> Self {
        let operators = Operators {
            recipients: b.operators.into_iter().collect(),
        };

        let permissions = b
            .permissions
            .into_iter()
            .map(|(agent, allowed)| (agent, allowed.into_iter().collect()))
            .collect();

        Self {
            version: 1,
            operators,
            agents: b.agents,
            targets: b.targets,
            permissions,
            secrets: b.secrets,
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
        let permissions: BTreeMap<String, BTreeSet<String>> = t
            .permissions
            .into_iter()
            .map(|(agent, p)| (agent, p.into_iter().collect()))
            .collect();

        let b = Bunker {
            operators,
            agents: t.agents,
            targets: t.targets,
            permissions,
            secrets: t.secrets,
        };
        b.validate()?;
        Ok(b)
    }
}
