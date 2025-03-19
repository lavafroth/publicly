use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use authfile::Entity;
use russh::keys::{PublicKey, ssh_key::public::KeyData, ssh_key::rand_core::OsRng};
use russh::server::{self, Auth, Handle, Msg, Server as _, Session};
use russh::{Channel, ChannelId, CryptoVec};
use tokio::sync::Mutex;
mod authfile;

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let mut methods = russh::MethodSet::empty();
    methods.push(russh::MethodKind::PublicKey);

    let keychain = authfile::read(Path::new("./authfile")).await.unwrap();
    let key_data_pool = new_atomic(build_key_data_pool(&keychain));
    let key_data_to_id = new_atomic(HashMap::new());
    let id_to_user = new_atomic(HashMap::new());
    let clients = new_atomic(HashMap::new());
    let key_data_to_user = new_atomic(keychain.iter().map(|e| (e.key_data(), e.clone())).collect());
    let keychain = new_atomic(keychain);

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
        id_to_user,
        key_data_to_id,
        key_data_pool,
        key_data_to_user,
        clients,
        id: 0,
    };
    sh.run_on_address(config, ("0.0.0.0", 2222)).await.unwrap();
}

fn build_key_data_pool(entities: &[Arc<Entity>]) -> HashSet<KeyData> {
    entities.iter().map(|e| e.key_data()).collect()
}

// wraps a type T as Arc<Mutex<T>> so that it can be locked
// in asynchronous coroutines
fn new_atomic<T>(object: T) -> Atomic<T> {
    Arc::new(Mutex::new(object))
}

type Atomic<T> = Arc<Mutex<T>>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to disconnect client with id {0}")]
    ClientDisconnectFailed(usize),
    #[error("russh error")]
    Russh(#[from] russh::Error),
    #[error("failed to read authorization file")]
    Authfile(#[from] authfile::Error),
}

pub struct Client {
    channel: ChannelId,
    handle: Handle,
    // entity: Arc<Entity>,
}

#[derive(Clone)]
struct Server {
    keychain: Atomic<Vec<Arc<Entity>>>,
    key_data_pool: Atomic<HashSet<KeyData>>,
    key_data_to_user: Atomic<HashMap<KeyData, Arc<Entity>>>,
    key_data_to_id: Atomic<HashMap<KeyData, Vec<usize>>>,
    id_to_user: Atomic<HashMap<usize, Arc<Entity>>>,
    clients: Atomic<HashMap<usize, Client>>,

    id: usize,
}

impl Server {
    async fn reload(&mut self) -> Result<(), Error> {
        let new_keychain = authfile::read(Path::new("./authfile")).await?;
        let new_key_data_pool = build_key_data_pool(&new_keychain);

        // freeze all maps in the server state
        {
            let mut keychain = self.keychain.lock().await;
            let mut key_data_pool = self.key_data_pool.lock().await;
            let mut key_data_to_id = self.key_data_to_id.lock().await;
            let mut key_data_to_user = self.key_data_to_user.lock().await;
            let mut clients = self.clients.lock().await;
            let mut id_to_user = self.id_to_user.lock().await;

            // find all strays
            for stray in key_data_pool.difference(&new_key_data_pool) {
                let Some(ids) = key_data_to_id.get(stray) else {
                    continue;
                };

                // these IDs are now invalid
                for id in ids.iter() {
                    let client = &clients[id];
                    if let Err(()) = client.handle.close(client.channel).await {
                        return Err(Error::ClientDisconnectFailed(*id));
                    }
                    clients.remove(id);
                    id_to_user.remove(id);
                }
                key_data_to_id.remove(stray);
            }

            *key_data_to_user = new_keychain
                .iter()
                .map(|e| (e.key_data(), e.clone()))
                .collect();
            *keychain = new_keychain;
            *key_data_pool = new_key_data_pool;
        }
        Ok(())
    }

    async fn post(&mut self, data: CryptoVec) {
        let mut clients = self.clients.lock().await;
        for (id, client) in clients.iter_mut() {
            if *id != self.id {
                let _ = client.handle.data(client.channel, data.clone()).await;
            }
        }
    }

    async fn entity(&mut self) -> Arc<Entity> {
        self.id_to_user.lock().await[&self.id].clone()
    }

    async fn announce(&mut self) {
        let entity = self.entity().await;
        let data = CryptoVec::from(format!(
            "{} with {:?} privileges has joined the lounge\r\n",
            entity.name(),
            entity.role()
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
    type Error = Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        {
            // let entity = self.entity().await;
            let channel = channel.id();
            let handle = session.handle();

            let mut clients = self.clients.lock().await;
            clients.insert(
                self.id,
                Client {
                    channel,
                    handle,
                    // entity,
                },
            );
        }
        self.announce().await;
        Ok(true)
    }

    async fn auth_publickey(&mut self, _: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        // Search for the key in our keychain
        if let Some(entity) = self.key_data_to_user.lock().await.get(key.key_data()) {
            // freeze everything, again
            let mut id_to_user = self.id_to_user.lock().await;
            let mut key_data_to_id = self.key_data_to_id.lock().await;

            id_to_user.insert(self.id, entity.clone());

            key_data_to_id
                .entry(key.key_data().clone())
                .or_default()
                .push(self.id);

            return Ok(Auth::Accept);
        }
        Ok(Auth::reject())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Sending Ctrl+C ends the session and disconnects the client
        if data == [3] {
            return Err(russh::Error::Disconnect.into());
        }

        // Press `r` to reload the authorization file
        if data == [114] {
            self.reload().await?;
        }

        let data = CryptoVec::from(format!(
            "[{}]: {}\r\n",
            self.entity().await.name(),
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
