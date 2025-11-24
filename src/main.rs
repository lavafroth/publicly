use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use ratatui::backend::TermionBackend;
use ratatui::layout::Rect;
use ratatui::termion::event::{Event, Key};
use ratatui::widgets::{Block, BorderType, Clear, List};
use ratatui::{Terminal, TerminalOptions, Viewport};
use ringbuffer::{AllocRingBuffer, RingBuffer};
use russh::keys::{PublicKey, ssh_key::public::KeyData, ssh_key::rand_core::OsRng};
use russh::server::{Auth, Config, Handle, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, Pty};
use tokio::sync::RwLock;
use tui_textarea::TextArea;

mod authfile;
mod entity;
mod error;
mod lookup;
mod message;
mod terminal_handle;
mod ui;

use entity::Entity;
use error::Error;
use message::Message;
use terminal_handle::TerminalHandle;

type SshTerminal = Terminal<TermionBackend<TerminalHandle>>;

// wraps a type T as Arc<Mutex<T>> so that it can be locked
// in asynchronous coroutines
fn new_atomic<T>(object: T) -> Atomic<T> {
    Arc::new(RwLock::new(object))
}

type Atomic<T> = Arc<RwLock<T>>;

/// App contains data strictly related to the chat.
/// It is not responsible for authorization.
struct App {
    pub history: AllocRingBuffer<Message>,
}

pub struct Client {
    channel: ChannelId,
    handle: Handle,
    terminal: SshTerminal,
    textarea: TextArea<'static>,
    statusline: String,
}

#[derive(Clone)]
struct AppServer {
    keychain: Atomic<Vec<Arc<Entity>>>,
    key_data_pool: Atomic<HashSet<KeyData>>,
    key_data_to_user: Atomic<HashMap<KeyData, Arc<Entity>>>,
    key_data_to_id: Atomic<HashMap<KeyData, Vec<usize>>>,
    id_to_user: Atomic<HashMap<usize, Arc<Entity>>>,
    clients: Atomic<HashMap<usize, Client>>,

    id: usize,
    args: Args,
    app: Atomic<App>,
}

impl AppServer {
    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        let mut methods = russh::MethodSet::empty();
        methods.push(russh::MethodKind::PublicKey);

        let config = Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
            auth_rejection_time: std::time::Duration::from_secs(3),
            auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
            methods,
            keys: vec![russh::keys::PrivateKey::random(
                &mut OsRng,
                russh::keys::Algorithm::Ed25519,
            )?],
            ..Default::default()
        };
        self.run_on_address(Arc::new(config), (self.args.host.clone(), self.args.port))
            .await?;
        Ok(())
    }

    async fn reload(&mut self) -> Result<(), Error> {
        let new_keychain = authfile::read(Path::new(&self.args.authfile)).await?;

        // freeze all maps in the server state
        {
            let mut keychain = self.keychain.write().await;
            let mut key_data_pool = self.key_data_pool.write().await;
            let mut key_data_to_id = self.key_data_to_id.write().await;
            let mut key_data_to_user = self.key_data_to_user.write().await;
            let mut clients = self.clients.write().await;
            let mut id_to_user = self.id_to_user.write().await;

            // find all strays
            for stray in key_data_pool.difference(&new_keychain.key_pool) {
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

                // kick em out
                key_data_to_id.remove(stray);
            }

            let mut new_key_data_to_user = HashMap::new();

            for entity in new_keychain.entities.iter() {
                new_key_data_to_user.insert(entity.key_data(), entity.clone());
            }

            *key_data_to_user = new_key_data_to_user;
            *keychain = new_keychain.entities;
            *key_data_pool = new_keychain.key_pool;
        }
        log::info!("authfile synchronized to memory");
        Ok(())
    }

    async fn entity(&self) -> Arc<Entity> {
        self.id_to_user.read().await[&self.id].clone()
    }

    async fn announce(&mut self, action: message::Announcement) {
        let persona = self.entity().await.persona();
        let message = Message::Announce { action, persona };
        self.app.write().await.history.enqueue(message);
    }

    async fn render(&self) {
        let clients = self.clients.clone();
        let history: Vec<Message> = self.app.read().await.history.to_vec();

        tokio::spawn(async move {
            for (id, client) in clients.write().await.iter_mut() {
                // build the message history paragraphs for each client
                let mut paragraphs = Vec::with_capacity(history.len());
                for message in history.iter() {
                    if let Message::Dossier { requested_by, .. } = message
                        && requested_by != id
                    {
                        // show a dossier only to the admin requesting it
                        continue;
                    }
                    let text_content = message.text_content().await;
                    paragraphs.push(text_content);
                }
                paragraphs.reverse();
                let paragraphs =
                    List::new(paragraphs).direction(ratatui::widgets::ListDirection::BottomToTop);

                let res = client.terminal.draw(|f| {
                    // clear the screen
                    let layout = ui::layout(f);

                    f.render_widget(paragraphs.clone(), layout[0]);
                    f.render_widget(&client.textarea, layout[1]);
                    f.render_widget(&client.statusline, layout[2]);
                });
                if let Err(error) = res {
                    log::error!(
                        "failed to render the chat interface for client {}: {:#?}",
                        client.channel,
                        error
                    )
                }
            }
        });
    }

    async fn run_command(&mut self, command: Command) -> Result<(), Error> {
        match command {
            Command::Add(entity) => {
                log::debug!("attempting to add {entity:#?}");
                let mut keychain = self.keychain.write().await;
                let mut key_data_pool = self.key_data_pool.write().await;
                let mut key_data_to_user = self.key_data_to_user.write().await;

                let key_data = entity.key_data();

                let entity = Arc::new(entity);
                keychain.push(entity.clone());
                key_data_pool.insert(key_data.clone());
                key_data_to_user.insert(key_data, entity);
            }
            Command::Rename { from, to } => {
                for ent in self.keychain.read().await.iter() {
                    if ent.name().await != from {
                        continue;
                    }

                    ent.set_name(&to).await;

                    let Some(ids) = self
                        .key_data_to_id
                        .read()
                        .await
                        .get(&ent.key_data())
                        .cloned()
                    else {
                        log::warn!(
                            "while updating client display name in textareas: found no client id with the key: {}",
                            ent.fingerprint()
                        );
                        return Ok(());
                    };

                    let title = ent.title().await;
                    let block = Block::bordered()
                        .border_type(BorderType::Rounded)
                        .title(title);

                    let mut clients = self.clients.write().await;

                    for id in ids {
                        let Some(client) = clients.get_mut(&id) else {
                            log::warn!(
                                "failed to get handle on client with id: {id}, considering them disconnected"
                            );
                            continue;
                        };
                        client.textarea.set_block(block.clone());
                    }
                }
            }
            Command::Commit => {
                let keychain = self.keychain.read().await;
                let mut pubkeys = vec![];
                for entity in keychain.iter() {
                    let ent_str = entity.to_pubkey().await.to_string();
                    pubkeys.push(ent_str);
                }
                let pubkeys = pubkeys.join("\n");
                let mut tmpfile = self.args.authfile.clone();
                tmpfile.push('~');
                if let Err(e) = std::fs::write(&tmpfile, pubkeys) {
                    log::error!(
                        "failed to create temporary file to commit in-memory authorized keys: {e:#?}"
                    );
                    return Ok(());
                };
                if let Err(e) = std::fs::rename(tmpfile, &self.args.authfile) {
                    log::error!(
                        "failed to move temporary file to original authfile: {e:#?}: do we have write permissions to it?"
                    );
                    return Ok(());
                };
            }
            Command::Info(entity_lookup) => {
                let keychain = self.keychain.read().await;
                let mut maybe_found_entity = None;
                for entity in keychain.iter() {
                    if entity_lookup.matches(entity).await {
                        maybe_found_entity.replace(entity);
                        break;
                    }
                }
                // wow so much to query a user huh? anyways
                let Some(entity) = maybe_found_entity else {
                    return Ok(());
                };

                let dossier = format!(
                    "
name: {}
role: {}
fingerprint: {}

",
                    entity.name().await,
                    entity.role().await,
                    entity.fingerprint()
                );

                self.app.write().await.history.enqueue(Message::Dossier {
                    contents: dossier,
                    requested_by: self.id,
                });
            }
            Command::Ban(entity_lookup) => {
                let keychain = self.keychain.read().await;
                let mut maybe_found_entity = None;
                for entity in keychain.iter() {
                    if entity_lookup.matches(entity).await {
                        maybe_found_entity.replace(entity);
                        break;
                    }
                }
                let Some(entity) = maybe_found_entity else {
                    return Ok(());
                };

                let key_data = entity.key_data();
                if self.entity().await.key_data() == entity.key_data() {
                    // prevent user from banning themselves
                    return Err(Error::NoBanSelf);
                }

                let mut key_data_to_user = self.key_data_to_user.write().await;
                let mut key_data_pool = self.key_data_pool.write().await;

                key_data_to_user.remove(&key_data);
                key_data_pool.remove(&key_data);

                let mut key_data_to_id = self.key_data_to_id.write().await;
                let Some(ids) = key_data_to_id.remove(&key_data) else {
                    return Ok(());
                };

                let mut clients = self.clients.write().await;
                for id in ids {
                    let Some(client) = clients.get(&id) else {
                        continue;
                    };
                    if let Err(()) = client.handle.close(client.channel).await {
                        return Err(Error::ClientDisconnectFailed(id));
                    }
                    clients.remove(&id);
                }
            }
            Command::Reload => self.reload().await?,
        }
        Ok(())
    }

    async fn handle_message(&mut self) -> Result<(), Error> {
        let text = {
            let mut clients = self.clients.write().await;
            let Some(current_client) = clients.get_mut(&self.id) else {
                log::warn!(
                    "failed to get handle on the current client with id: {}",
                    self.id
                );
                return Ok(());
            };
            let text = current_client.textarea.lines().join("\n");

            // HACK: Clear the textarea on send. Select all, delete.
            current_client.textarea.select_all();
            current_client
                .textarea
                .input(ratatui::termion::event::Event::Key(Key::Delete));
            text
        };
        let role = self.entity().await.role().await;
        let name = self.entity().await.name().await;
        let maybe_command = match Command::parse(&text, role, name.to_string()) {
            Ok(c) => c,
            Err(e) => {
                let mut clients = self.clients.write().await;
                let Some(current_client) = clients.get_mut(&self.id) else {
                    log::warn!(
                        "failed to get handle on the current client with id: {}",
                        self.id
                    );
                    return Ok(());
                };
                current_client.statusline = e.to_string();
                return Ok(());
            }
        };

        let Some(command) = maybe_command else {
            let message = format!("[{name}]: {text}");
            self.app
                .write()
                .await
                .history
                .enqueue(Message::Plain(message));
            self.render().await;
            return Ok(());
        };
        if let Err(e) = self.run_command(command).await {
            let mut clients = self.clients.write().await;
            let Some(current_client) = clients.get_mut(&self.id) else {
                log::warn!(
                    "failed to get handle on the current client with id: {}",
                    self.id
                );
                return Ok(());
            };
            current_client.statusline = e.to_string();
            return Ok(());
        }
        Ok(())
    }
}

impl Server for AppServer {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        let s = self.clone();
        self.id += 1;
        s
    }
    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        log::error!("session error: {error:#?}");
    }
}

impl Handler for AppServer {
    type Error = Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        {
            let channel = channel.id();
            let handle = session.handle();
            let terminal_handle = TerminalHandle::start(handle.clone(), channel).await;

            let backend = TermionBackend::new(terminal_handle);

            // the correct viewport area will be set when the client request a pty
            let options = TerminalOptions {
                viewport: Viewport::Fixed(Rect::default()),
            };

            let terminal = Terminal::with_options(backend, options).map_err(|source| {
                Error::TerminalSessionSpawn {
                    source,
                    id: self.id,
                }
            })?;

            let mut textarea = TextArea::default();
            let title = self.entity().await.title().await;
            let surrounding_block = Block::bordered()
                .border_type(BorderType::Rounded)
                .title(title);
            textarea.set_block(surrounding_block);

            let client = Client {
                textarea,
                channel,
                handle,
                terminal,
                statusline: String::default(),
            };

            self.clients.write().await.insert(self.id, client);
        }
        self.announce(message::Announcement::Joined).await;
        Ok(true)
    }

    async fn auth_publickey(&mut self, _: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        // Search for the key in our keychain
        if let Some(entity) = self.key_data_to_user.read().await.get(key.key_data()) {
            // freeze everything, again
            let mut id_to_user = self.id_to_user.write().await;
            let mut key_data_to_id = self.key_data_to_id.write().await;

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
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        match data {
            // Sending Ctrl+C ends the session and disconnects the client
            [3] => {
                self.announce(message::Announcement::Left).await;
                self.render().await;
                {
                    let mut key_data_to_id = self.key_data_to_id.write().await;
                    let mut id_to_user = self.id_to_user.write().await;

                    let Some(entity) = id_to_user.get(&self.id) else {
                        log::warn!(
                            "could not look up the entity corresponding to the current id: {}",
                            self.id
                        );
                        return Err(russh::Error::Disconnect.into());
                    };
                    let stray_key_data = entity.key_data();
                    key_data_to_id.remove(&stray_key_data);

                    id_to_user.remove(&self.id);
                    if let Some(mut leaving_client) = self.clients.write().await.remove(&self.id)
                        && let Err(e) = leaving_client
                            .terminal
                            .draw(|f| f.render_widget(Clear, f.area()))
                    {
                        log::error!("failed to clear the screen of leaving client: {e:?}");
                    };
                }
                return Err(russh::Error::Disconnect.into());
            }
            // Press Return to send a message
            [13] => {
                if let Err(error) = self.handle_message().await {
                    log::error!(
                        "failed to handle message or potential command sent by client {}: {:?}",
                        self.id,
                        error
                    );
                };
                // re-render
                self.render().await;
            }
            // Alt-Return for multiline
            [27, 13] => {
                {
                    let mut clients = self.clients.write().await;
                    let Some(client) = clients.get_mut(&self.id) else {
                        log::warn!(
                            "failed to get handle on the current client with id: {}",
                            self.id
                        );
                        return Ok(());
                    };
                    client.textarea.input(Event::Key(Key::Char('\n')));
                }
                self.render().await;
            }
            data if !data.is_empty() => {
                let mut iterator = data.iter().map(|d| Ok(*d));
                loop {
                    let Some(Ok(first)) = iterator.next() else {
                        break;
                    };

                    match ratatui::termion::event::parse_event(first, &mut iterator) {
                        Ok(keycode) => {
                            let mut clients = self.clients.write().await;
                            let Some(client) = clients.get_mut(&self.id) else {
                                log::warn!(
                                    "failed to get handle on the current client with id: {}",
                                    self.id
                                );
                                return Ok(());
                            };
                            client.textarea.input(keycode);
                        }
                        Err(e) => {
                            log::warn!("failed to parse keyboard input data: {data:?}: {e}");
                        }
                    }
                }
                self.render().await;
            }
            _ => {}
        }

        Ok(())
    }

    /// The client requests a pseudo-terminal with the given specifications.
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _: &str,
        col_width: u32,
        row_height: u32,
        _: u32,
        _: u32,
        _: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let rect = Rect {
            x: 0,
            y: 0,
            width: col_width as u16,
            height: row_height as u16,
        };

        {
            let mut clients = self.clients.write().await;
            let Some(client) = clients.get_mut(&self.id) else {
                log::warn!(
                    "failed to get handle on the current client with id: {}",
                    self.id
                );
                return Ok(());
            };
            if let Err(error) = client.terminal.resize(rect) {
                log::error!(
                    "failed to respond to terminal resize for client {}: {:#?}",
                    self.id,
                    error
                );
            };

            session.channel_success(channel)?;
        }
        self.render().await;

        Ok(())
    }

    /// The client's pseudo-terminal window size has changed.
    async fn window_change_request(
        &mut self,
        _: ChannelId,
        col_width: u32,
        row_height: u32,
        _: u32,
        _: u32,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        let rect = Rect {
            x: 0,
            y: 0,
            width: col_width as u16,
            height: row_height as u16,
        };

        {
            let mut clients = self.clients.write().await;
            let Some(client) = clients.get_mut(&self.id) else {
                log::warn!(
                    "failed to get handle on the current client with id: {}",
                    self.id
                );
                return Ok(());
            };

            client
                .terminal
                .resize(rect)
                .map_err(|source| Error::FrameResize {
                    source,
                    id: self.id,
                })?;
        }
        self.render().await;

        Ok(())
    }
}

impl Drop for AppServer {
    fn drop(&mut self) {
        let id = self.id;
        let clients = self.clients.clone();
        tokio::spawn(async move {
            let mut clients = clients.write().await;
            clients.remove(&id);
        });
    }
}

pub enum Command {
    Add(Entity),
    Rename { from: String, to: String },
    Commit,
    Info(lookup::EntityLookup),
    Ban(lookup::EntityLookup),
    Reload,
}

impl Command {
    fn parse(text: &str, role: entity::Role, name: String) -> Result<Option<Self>, Error> {
        let split: Vec<&str> = text.split(char::is_whitespace).collect();
        let is_admin = role == entity::Role::Admin;

        Ok(Some(match &split[..] {
            ["/info", payload] => Self::Info(payload.parse()?),
            ["/add" | "/rename" | "/ban" | "/commit" | "/reload", ..] if !is_admin => {
                return Err(Error::NotAnAdmin(name));
            }
            ["/add", payload] => Self::Add(payload.parse()?),
            ["/ban", payload] => Self::Ban(payload.parse()?),
            ["/commit"] => Self::Commit,
            ["/reload"] => Self::Reload,
            ["/rename", from, to] => Self::Rename {
                to: to.to_string(),
                from: from.to_string(),
            },
            [
                "/info" | "/add" | "/rename" | "/ban" | "/commit" | "/reload",
                ..,
            ] => {
                return Err(Error::CommandParse(text.to_string()));
            }
            _ => return Ok(None),
        }))
    }
}

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
struct Args {
    /// The number of messages to store in chat history before the first disappears
    #[arg(long, default_value = "128")]
    history_size: usize,

    /// Path to the Authfile or the SSH authorized_keys file
    #[arg(long, short, default_value = "./Authfile")]
    authfile: String,

    /// Port to listen on for incoming connections
    #[arg(long, short, default_value = "2222")]
    port: u16,

    /// Interface on the host to listen on
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let args = Args::parse();

    let keychain = authfile::read(Path::new(&args.authfile)).await?;
    let key_data_pool = new_atomic(keychain.key_pool);
    let key_data_to_id = new_atomic(HashMap::new());
    let id_to_user = new_atomic(HashMap::new());
    let clients = new_atomic(HashMap::new());

    let mut raw_key_data_to_user = HashMap::new();
    for entity in keychain.entities.iter() {
        raw_key_data_to_user.insert(entity.key_data(), entity.clone());
    }

    let key_data_to_user = new_atomic(raw_key_data_to_user);
    let keychain = new_atomic(keychain.entities);

    let app = App {
        history: AllocRingBuffer::new(args.history_size),
    };

    let app = new_atomic(app);

    let mut sh = AppServer {
        app,
        keychain,
        id_to_user,
        key_data_to_id,
        key_data_pool,
        key_data_to_user,
        clients,
        args,
        id: 0,
    };
    sh.run().await?;
    Ok(())
}
