use std::rc::Rc;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    widgets::Clear,
};

const UI_LAYOUT: [ratatui::layout::Constraint; 3] = [
    Constraint::Fill(1),   // message history
    Constraint::Length(4), // input textarea
    Constraint::Length(1), // statusline
];

pub fn layout(f: &mut Frame) -> Rc<[Rect]> {
    f.render_widget(Clear, f.area());

    Layout::default()
        .direction(Direction::Vertical)
        .constraints(UI_LAYOUT)
        .split(f.area())
}
