use russh::{ChannelId, server::Handle};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

pub struct TerminalHandle {
    sender: UnboundedSender<Vec<u8>>,
    // The sink collects the data which is finally sent to sender.
    sink: Vec<u8>,
}

impl TerminalHandle {
    pub async fn start(handle: Handle, channel_id: ChannelId) -> Self {
        let (sender, mut receiver) = unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            while let Some(data) = receiver.recv().await {
                if let Err(error) = handle.data(channel_id, data.into()).await {
                    log::error!("Failed to send data: {error:?}");
                }
            }
        });
        Self {
            sender,
            sink: Vec::new(),
        }
    }
}

// The crossterm backend writes to the terminal handle.
impl std::io::Write for TerminalHandle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sink.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let result = self.sender.send(self.sink.clone());
        if let Err(err) = result {
            return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, err));
        }

        self.sink.clear();
        Ok(())
    }
}
