use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use ratatui::backend::TermionBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::termion::event::{Event, Key};
use ratatui::text::Text;
use ratatui::widgets::{Block, BorderType, Clear, List};
use ratatui::{Terminal, TerminalOptions, Viewport};
use ringbuffer::{AllocRingBuffer, RingBuffer};
use russh::keys::{PublicKey, ssh_key::public::KeyData, ssh_key::rand_core::OsRng};
use russh::server::{Auth, Config, Handle, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, Pty};
use tokio::sync::RwLock;
use tui_textarea::TextArea;

mod authfile;
mod terminal_handle;
use authfile::Entity;
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
    pub history: AllocRingBuffer<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to disconnect client with id {0}")]
    ClientDisconnectFailed(usize),
    #[error("russh error")]
    Russh(#[from] russh::Error),
    #[error("failed to read authorization file")]
    Authfile(#[from] authfile::Error),
    #[error("failed to resize frame as requested by client {id}")]
    FrameResize { source: std::io::Error, id: usize },
}

pub struct Client {
    channel: ChannelId,
    handle: Handle,
    terminal: SshTerminal,
    textarea: TextArea<'static>,
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
        self.run_on_address(Arc::new(config), ("0.0.0.0", self.args.port))
            .await?;
        Ok(())
    }

    async fn check_role_and_reload(&mut self) -> Result<(), Error> {
        if self.entity().await.role() == authfile::Role::Admin {
            self.reload().await?;
        } else {
            // TODO: write a helpful message to the bottom most statusline
        }
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

            *key_data_to_user = new_keychain
                .entities
                .iter()
                .map(|e| (e.key_data(), e.clone()))
                .collect();
            *keychain = new_keychain.entities;
            *key_data_pool = new_keychain.key_pool;
        }
        log::info!("authfile synchronized to memory");
        Ok(())
    }

    async fn entity(&mut self) -> Arc<Entity> {
        self.id_to_user.read().await[&self.id].clone()
    }

    async fn announce(&mut self) {
        let entity = self.entity().await;
        self.app.write().await.history.push(format!(
            "{} with {:?} privileges has joined",
            entity.name(),
            entity.role()
        ));
    }

    async fn render(&mut self) {
        let clients = self.clients.clone();
        let history: Vec<String> = self.app.read().await.history.to_vec();
        tokio::spawn(async move {
            for (_, client) in clients.write().await.iter_mut() {
                let res = client.terminal.draw(|f| {
                    // clear the screen
                    f.render_widget(Clear, f.area());

                    let layout = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints(vec![Constraint::Fill(1), Constraint::Length(4)])
                        .split(f.area());
                    let style = Style::default().fg(Color::Green);

                    let paragraphs: Vec<_> = history
                        .iter()
                        .map(|message| Text::styled(message.to_string(), style))
                        .collect();

                    let paragraphs = List::new(paragraphs);
                    f.render_widget(paragraphs, layout[0]);
                    f.render_widget(&client.textarea, layout[1]);
                });
                if let Err(e) = res {
                    log::error!(
                        "failed to render the chat interface for client {}: {}",
                        client.channel,
                        e
                    )
                }
            }
        });
    }

    // Render textarea only for the client who sent
    // a keystroke
    async fn render_textarea(&mut self) {
        let clients = self.clients.clone();
        let id = self.id;
        tokio::spawn(async move {
            let mut clients = clients.write().await;
            let Client {
                terminal, textarea, ..
            } = clients.get_mut(&id).unwrap();

            terminal
                .draw(|f| {
                    let buf = f.buffer_mut();
                    let area = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints(vec![Constraint::Fill(1), Constraint::Length(4)])
                        .split(buf.area)[1];
                    for i in 0..(area.width * area.y) as usize {
                        buf.content[i].set_skip(true);
                    }
                    f.render_widget(&*textarea, area);
                })
                .unwrap();
        });
    }
}

impl Server for AppServer {
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

impl Handler for AppServer {
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
            let terminal_handle = TerminalHandle::start(handle.clone(), channel.clone()).await;

            let backend = TermionBackend::new(terminal_handle);

            // the correct viewport area will be set when the client request a pty
            let options = TerminalOptions {
                viewport: Viewport::Fixed(Rect::default()),
            };

            let terminal = Terminal::with_options(backend, options).unwrap();
            let title = {
                let entity = self.entity().await;
                format!("[{} {}]", entity.name(), entity.role().to_string())
            };

            let mut textarea = TextArea::default();
            textarea.set_block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .title(title),
            );

            let mut clients = self.clients.write().await;
            clients.insert(
                self.id,
                Client {
                    textarea,
                    channel,
                    handle,
                    terminal,
                },
            );
        }
        self.announce().await;
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
            [3] => return Err(russh::Error::Disconnect.into()),
            // Press Return to send a message
            [13] => {
                let text = {
                    let mut clients = self.clients.write().await;
                    let current_client = clients.get_mut(&self.id).unwrap();
                    let text = current_client.textarea.lines().to_vec().join("\n");

                    // HACK: Clear the textarea on send.
                    // Select all, delete.
                    current_client.textarea.select_all();
                    current_client
                        .textarea
                        .input(ratatui::termion::event::Event::Key(
                            ratatui::termion::event::Key::Delete,
                        ));
                    text
                };
                let name = self.entity().await.name().to_string();
                let message = format!("[{name}]: {text}");
                self.app.write().await.history.push(message);
                self.render().await;
            }
            // Alt-Return for multiline
            [27, 13] => {
                self.clients
                    .write()
                    .await
                    .get_mut(&self.id)
                    .unwrap()
                    .textarea
                    .input(Event::Key(Key::Char('\n')));
                self.render_textarea().await;
            }

            data if !data.is_empty() => {
                let mut iterator = data.iter().skip(1).map(|d| Ok(*d));
                match ratatui::termion::event::parse_event(data[0], &mut iterator) {
                    // Press `Ctrl-r` to reload the authorization file
                    Ok(Event::Key(Key::Ctrl('r'))) => {
                        self.check_role_and_reload().await?;
                    }
                    Ok(keycode) => {
                        self.clients
                            .write()
                            .await
                            .get_mut(&self.id)
                            .unwrap()
                            .textarea
                            .input(keycode);
                    }
                    Err(e) => {
                        log::warn!("failed to parse keyboard input data: {:?}: {e}", data);
                    }
                }
                self.render_textarea().await;
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
            let client = clients.get_mut(&self.id).unwrap();
            client.terminal.resize(rect).unwrap();

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
            match clients.get_mut(&self.id).unwrap().terminal.resize(rect) {
                Ok(_) => {}
                Err(e) => {
                    return Err(Error::FrameResize {
                        source: e,
                        id: self.id,
                    });
                }
            };
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
    let key_data_to_user = new_atomic(
        keychain
            .entities
            .iter()
            .map(|e| (e.key_data(), e.clone()))
            .collect(),
    );
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
