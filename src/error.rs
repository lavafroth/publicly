use crate::authfile;
use crate::entity;

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
    #[error("failed to parse command {0:#?}")]
    CommandParse(String),
    #[error("unable to spawn a terminal for client {id}")]
    TerminalSessionSpawn { source: std::io::Error, id: usize },
    #[error("failed to parse entity lookup: {0}")]
    EntityLookup(String),
    #[error("user {0:?} is not an admin")]
    NotAnAdmin(String),
    #[error("failed to parse SSH key string to an entity")]
    EntityParsing(#[from] entity::Error),
    #[error("users cannot ban themselves")]
    NoBanSelf,
}
