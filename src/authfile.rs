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
    let entities = entities.into_iter().map(Arc::new).collect();
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

        let persona = Persona {
            name: sanitize_name(name),
            role,
        };
        let persona = Arc::new(RwLock::new(persona));
        Ok(Entity { persona, key })
    }
}

fn build_key_data_pool(entities: &[Entity]) -> HashSet<KeyData> {
    entities.iter().map(|e| e.key_data()).collect()
}

pub struct AuthFile {
    pub entities: Vec<Arc<Entity>>,
    pub key_pool: HashSet<KeyData>,
}

#[derive(Clone, Debug)]
pub struct Persona {
    name: String,
    role: Role,
}

impl Persona {
    pub fn title(&self) -> String {
        format!("[{} {}]", self.name, self.role)
    }

    pub fn name(&self) -> String {
        self.name.to_owned()
    }

    pub fn role(&self) -> Role {
        self.role
    }
}

pub type ArcPersona = Arc<RwLock<Persona>>;

#[derive(Clone, Debug)]
pub struct Entity {
    // Requires interior mutability for changing name and role
    persona: ArcPersona,
    // The public key does not change for an entity over
    // the lifetime of the app
    key: PublicKey,
}

impl Entity {
    /// NOTE: interior mutation on persona
    pub async fn set_role(&mut self, role: Role) {
        self.persona.write().await.role = role;
    }

    /// NOTE: interior mutation on persona
    pub async fn set_name(&self, name: &str) {
        self.persona.write().await.name = name.to_string();
    }

    pub async fn to_pubkey(&self) -> PublicKey {
        let mut original_key = self.key.clone();
        let persona = self.persona.read().await;
        let name = &persona.name;
        let role = if persona.role == Role::Admin {
            ":admin"
        } else {
            ""
        };
        original_key.set_comment(format!("{name}{role}"));
        original_key
    }

    pub async fn name(&self) -> String {
        self.persona.read().await.name.to_string()
    }
    pub async fn role(&self) -> Role {
        self.persona.read().await.role
    }

    pub async fn title(&self) -> String {
        self.persona.read().await.title()
    }

    pub fn key_data(&self) -> KeyData {
        self.key.key_data().clone()
    }

    pub fn fingerprint(&self) -> String {
        self.key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string()
    }

    pub fn persona(&self) -> Arc<RwLock<Persona>> {
        self.persona.clone()
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
