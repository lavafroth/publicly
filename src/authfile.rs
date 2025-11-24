use crate::entity::Entity;
use russh::keys::ssh_key::public::KeyData;
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

pub async fn read(path: &Path) -> Result<AuthFile, Error> {
    let handle = std::fs::File::open(path)?;
    let reader = BufReader::new(handle);
    let mut entities = vec![];
    for line in reader.lines() {
        let line = line?;
        entities.push(line.parse()?);
    }
    let key_pool = build_key_data_pool(&entities);
    let entities = entities.into_iter().map(Arc::new).collect();
    Ok(AuthFile { entities, key_pool })
}

fn build_key_data_pool(entities: &[Entity]) -> HashSet<KeyData> {
    entities.iter().map(|e| e.key_data()).collect()
}

pub struct AuthFile {
    pub entities: Vec<Arc<Entity>>,
    pub key_pool: HashSet<KeyData>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("unable to read authorization file")]
    FileNotReadable(#[from] std::io::Error),
    #[error("failed to parse entity: {0}")]
    PublicKeyParsing(#[from] crate::entity::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_read_nonexistent_file() {
        let nonexistent = Path::new("tests/fixtures/nonexistent.txt");
        match read(nonexistent).await {
            Err(Error::FileNotReadable(_)) => {}
            _ => panic!("reading nonexistent authfile succeded: should have failed"),
        };
    }

    #[tokio::test]
    async fn test_valid_authfile() {
        read(Path::new("tests/fixtures/valid_authfile"))
            .await
            .expect("failed to read valid authfile fixture");
    }
}
