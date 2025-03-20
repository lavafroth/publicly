use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

use russh::keys::PublicKey;
use russh::keys::ssh_key::public::KeyData;

pub fn sanitize_name(s: &str) -> String {
    let mut sanitized = String::with_capacity(s.len());
    for c in s.chars() {
        let ok = c.is_ascii_alphanumeric() || c == '@';
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
        let key = PublicKey::from_openssh(&line)?;

        let comment = key.comment();
        let (name, role) = match comment.rsplit_once(":") {
            Some((name, "admin")) => (name, Role::Admin),
            None => (comment, Role::Normal),
            _ => {
                return Err(Error::InvalidRole(comment.to_string()));
            }
        };

        let authorized_entity = Entity {
            name: sanitize_name(name),
            role,
            key,
        };
        entities.push(authorized_entity.into());
    }
    let key_pool = build_key_data_pool(&entities);
    Ok(AuthFile { entities, key_pool })
}

fn build_key_data_pool(entities: &[Arc<Entity>]) -> HashSet<KeyData> {
    entities.iter().map(|e| e.key_data()).collect()
}

pub struct AuthFile {
    pub entities: Vec<Arc<Entity>>,
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
    PublicKeyParsingError(#[from] russh::keys::ssh_key::Error),
    #[error("invalid role specified in authorization file at line: {0}")]
    InvalidRole(String),
}

#[derive(Clone, Debug, PartialEq, Copy)]
pub enum Role {
    Admin,
    Normal,
}
