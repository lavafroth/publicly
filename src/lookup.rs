use crate::Error;
use crate::entity::Entity;
use std::str::FromStr;
pub enum EntityLookup {
    Name(String),
    Sha256(String),
}

impl FromStr for EntityLookup {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let lookup = match s.split_once(':') {
            Some(("SHA256", digest)) if !digest.is_empty() && !digest.contains(':') => {
                EntityLookup::Sha256(s.to_string())
            }
            None => EntityLookup::Name(s.to_string()),
            _ => return Err(Error::EntityLookup(s.to_string())),
        };
        Ok(lookup)
    }
}

impl EntityLookup {
    pub async fn matches<T: AsRef<Entity>>(&self, entity: T) -> bool {
        let entity = entity.as_ref();
        match self {
            EntityLookup::Name(name) => {
                if entity.name().await.eq(name.as_str()) {
                    return true;
                }
            }
            EntityLookup::Sha256(digest) => {
                if entity.fingerprint().eq(digest.as_str()) {
                    return true;
                }
            }
        }
        false
    }
}
