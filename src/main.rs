use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;

use russh::keys::{PublicKey, ssh_key, ssh_key::rand_core::OsRng};
use russh::server::{self, Msg, Server as _, Session};
use russh::{Channel, ChannelId, CryptoVec};
use thiserror::Error;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let mut methods = russh::MethodSet::empty();
    methods.push(russh::MethodKind::PublicKey);

    let keychain = read_authfile(Path::new("./authfile")).await.unwrap();

    let config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        methods,
        keys: vec![
            russh::keys::PrivateKey::random(&mut OsRng, russh::keys::Algorithm::Ed25519).unwrap(),
        ],
        ..Default::default()
    };
    let config = Arc::new(config);
    let mut sh = Server {
        keychain,
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: 0,
        user_map: Arc::new(Mutex::new(HashMap::default())),
    };
    sh.run_on_address(config, ("0.0.0.0", 2222)).await.unwrap();
}

#[derive(Error, Debug)]
pub enum AuthFileError {
    #[error("unable to read authorization file")]
    FileNotReadable(#[from] std::io::Error),
    #[error("failed to parse public key")]
    PublicKeyParsingError(#[from] russh::keys::ssh_key::Error),
    #[error("invalid role specified in authorization file at line: {0}")]
    InvalidRole(String),
}

#[derive(Clone, Debug)]
pub enum Role {
    Normal,
    Super,
}

#[derive(Clone)]
pub struct AuthorizedEntity {
    name: String,
    role: Role,
    key: PublicKey,
}

async fn read_authfile(path: &Path) -> Result<Vec<Arc<AuthorizedEntity>>, AuthFileError> {
    let handle = std::fs::File::open(path)?;
    let reader = BufReader::new(handle);
    let mut keys = vec![];
    for line in reader.lines() {
        let line = line?;
        let key = PublicKey::from_openssh(&line)?;

        let comment = key.comment();
        let (name, role) = match comment.rsplit_once(":") {
            Some((name, "admin")) => (name, Role::Super),
            None => (comment, Role::Normal),
            _ => {
                return Err(AuthFileError::InvalidRole(comment.to_string()));
            }
        };

        let authorized_entity = AuthorizedEntity {
            name: name.to_string(),
            role,
            key,
        };
        keys.push(authorized_entity.into());
    }
    Ok(keys)
}

#[derive(Clone)]
struct Server {
    keychain: Vec<Arc<AuthorizedEntity>>,
    clients: Arc<Mutex<HashMap<usize, (ChannelId, russh::server::Handle)>>>,
    user_map: Arc<Mutex<HashMap<usize, Arc<AuthorizedEntity>>>>,
    id: usize,
}

impl Server {
    async fn post(&mut self, data: CryptoVec) {
        let mut clients = self.clients.lock().await;
        for (id, (channel, s)) in clients.iter_mut() {
            if *id != self.id {
                let _ = s.data(*channel, data.clone()).await;
            }
        }
    }

    async fn entity(&mut self) -> Arc<AuthorizedEntity> {
        self.user_map.lock().await.get(&self.id).cloned().unwrap()
    }

    async fn announce(&mut self) {
        let entity = self.entity().await;
        let data = CryptoVec::from(format!(
            "{} with {:?} privileges has joined the lounge\r\n",
            entity.name, entity.role
        ));
        self.post(data.clone()).await;
    }
}

impl server::Server for Server {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        let s = self.clone();
        self.id += 1;
        s
    }
    fn handle_session_error(&mut self, _error: <Self::Handler as russh::server::Handler>::Error) {
        eprintln!("Session error: {:#?}", _error);
    }
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        {
            let mut clients = self.clients.lock().await;
            clients.insert(self.id, (channel.id(), session.handle()));
        }
        self.announce().await;
        Ok(true)
    }

    async fn auth_publickey(
        &mut self,
        _: &str,
        key: &ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        // Search for the key in our keychain
        if let Some(entity) = self
            .keychain
            .iter()
            .find(|entity| entity.key.key_data() == key.key_data())
        {
            {
                let mut user_map = self.user_map.lock().await;
                user_map.insert(self.id, entity.clone());
            }
            return Ok(server::Auth::Accept);
        }
        Ok(server::Auth::reject())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Sending Ctrl+C ends the session and disconnects the client
        if data == [3] {
            return Err(russh::Error::Disconnect);
        }

        let data = CryptoVec::from(format!(
            "[{}]: {}\r\n",
            self.entity().await.name,
            String::from_utf8_lossy(data)
        ));
        self.post(data.clone()).await;
        session.data(channel, data)?;
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let id = self.id;
        let clients = self.clients.clone();
        tokio::spawn(async move {
            let mut clients = clients.lock().await;
            clients.remove(&id);
        });
    }
}
