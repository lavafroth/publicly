use std::collections::HashSet;
use std::fmt::Display;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

use russh::keys::PublicKey;
use russh::keys::ssh_key::public::KeyData;

pub fn sanitize_name(s: &str) -> String {
    let mut sanitized = String::with_capacity(s.len());
    for c in s.chars() {
        let ok = c.is_ascii_alphanumeric() || "@_-.".contains(c);
        if !ok {
            continue;
        }
        sanitized.push(c);
    }
    sanitized
}

pub async fn read(path: &Path) -> Result<AuthFile, Error> {
    let handle = std::fs::File::open(path)?;
    let reader = BufReader::new(handle);
    let mut entities = vec![];
    for line in reader.lines() {
        let line = line?;
        let entity: Entity = line.as_str().try_into()?;
        entities.push(entity);
    }
    let key_pool = build_key_data_pool(&entities);
    let entities = entities
        .into_iter()
        .map(|entity| Arc::new(RwLock::new(entity)))
        .collect();
    Ok(AuthFile { entities, key_pool })
}

impl TryFrom<&str> for Entity {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let key = PublicKey::from_openssh(value)?;

        let comment = key.comment();
        let (name, role) = match comment.rsplit_once(":") {
            Some((name, "admin")) => (name, Role::Admin),
            None => (comment, Role::Normal),
            _ => {
                return Err(Error::InvalidRole(comment.to_string()));
            }
        };

        Ok(Entity {
            name: sanitize_name(name),
            role,
            key,
        })
    }
}

fn build_key_data_pool(entities: &[Entity]) -> HashSet<KeyData> {
    entities.iter().map(|e| e.key_data()).collect()
}

pub struct AuthFile {
    pub entities: Vec<Arc<RwLock<Entity>>>,
    pub key_pool: HashSet<KeyData>,
}

#[derive(Clone)]
pub struct Entity {
    name: String,
    role: Role,
    key: PublicKey,
}

impl Entity {
    pub fn set_role(&mut self, role: Role) {
        self.role = role;
    }

    pub fn set_name(&mut self, name: &str) {
        self.name = name.to_string();
    }

    pub fn to_pubkey(&self) -> PublicKey {
        let mut original_key = self.key.clone();
        let name = &self.name;
        let role = if self.role == Role::Admin {
            ":admin"
        } else {
            ""
        };
        original_key.set_comment(format!("{name}{role}"));
        original_key
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn role(&self) -> Role {
        self.role
    }

    pub fn key_data(&self) -> KeyData {
        self.key.key_data().clone()
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("unable to read authorization file")]
    FileNotReadable(#[from] std::io::Error),
    #[error("failed to parse public key")]
    PublicKeyParsing(#[from] russh::keys::ssh_key::Error),
    #[error("invalid role specified in authorization file at line: {0}")]
    InvalidRole(String),
}

#[derive(Clone, Debug, PartialEq, Copy)]
pub enum Role {
    Admin,
    Normal,
}

impl Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let role = match self {
            Role::Admin => "admin",
            Role::Normal => "normal",
        };
        write!(f, "{role}")
    }
}
