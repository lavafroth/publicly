use crate::entity::ArcPersona;
use ratatui::style::Color;
use ratatui::style::Style;
use ratatui::text::Text;

#[derive(Clone, Copy)]
pub enum Announcement {
    Joined,
    Left,
}

#[derive(Clone)]
pub(crate) enum Message {
    Announce {
        action: Announcement,
        persona: ArcPersona,
    },
    Plain(String),
    Dossier {
        contents: String,
        requested_by: usize,
    },
}

impl Message {
    pub async fn text_content(&self) -> Text {
        match self {
            Message::Announce { action, persona } => {
                let persona = persona.read().await;
                let announcement = match action {
                    Announcement::Joined => format!(
                        "{} has joined the chat with {} privileges",
                        persona.name(),
                        persona.role()
                    ),
                    Announcement::Left => format!(
                        "{} with {} privileges has left the chat",
                        persona.name(),
                        persona.role()
                    ),
                };
                Text::styled(announcement, Style::default().fg(Color::Green))
            }
            Message::Dossier { contents, .. } => {
                Text::styled(contents, Style::default().fg(Color::LightCyan))
            }
            Message::Plain(s) => Text::raw(s),
        }
    }
}
