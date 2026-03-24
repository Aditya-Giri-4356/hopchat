// =============================================================================
// HOPCHAT — TUI Module: Layout
// =============================================================================
//
// Defines the terminal UI layout using ratatui's constraint-based system.
// Matches the ASCII layout specification:
//   - Header bar
//   - Middle row: Friends panel (left) + Network Map panel (right)
//   - Network Status bar
//   - Chat window
//   - Input prompt

use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Contains all the computed layout rectangles for each UI panel.
pub struct AppLayout {
    pub header: Rect,
    pub friends: Rect,
    pub network_map: Rect,
    pub network_status: Rect,
    pub chat: Rect,
    pub input: Rect,
}

/// Computes the layout for the entire terminal area.
pub fn compute_layout(area: Rect) -> AppLayout {
    // Main vertical split: header, middle, status, chat, input
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(8),    // Middle (friends + network map)
            Constraint::Length(3),  // Network status
            Constraint::Min(8),    // Chat window
            Constraint::Length(3),  // Input prompt
        ])
        .split(area);

    // Middle horizontal split: friends (left) + network map (right)
    let middle_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(35),
            Constraint::Percentage(65),
        ])
        .split(main_chunks[1]);

    AppLayout {
        header: main_chunks[0],
        friends: middle_chunks[0],
        network_map: middle_chunks[1],
        network_status: main_chunks[2],
        chat: main_chunks[3],
        input: main_chunks[4],
    }
}
