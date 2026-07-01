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
#[derive(Clone)]
pub struct AppLayout {
    pub header: Rect,
    pub friends: Rect,
    pub network_map: Rect,
    pub network_status: Rect,
    pub chat: Rect,
    pub input: Rect,
    /// [UI-MOB-3] Left portion of the mobile quit row — used for compact status
    pub mobile_status: Option<Rect>,
    pub quit_button: Option<Rect>,
}

pub fn compute_layout(area: Rect) -> AppLayout {
    // [UI-MOB-1] Mobile layout for terminals under 100 columns (iSH ~80, Termux ~85-90).
    // Uses width as the sole discriminant. The previous `area.height >= area.width`
    // condition incorrectly triggered on tall desktop terminals (common on 16:9 monitors).
    if area.width < 100 {
        // --- Mobile Layout ---
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Length(3),  // Quit Button row + mobile status
                Constraint::Percentage(30), // Friends
                Constraint::Percentage(70), // Chat window
                Constraint::Length(3),  // Input prompt
            ])
            .split(area);

        // [UI-MOB-3] Split the quit row into status (left) and quit button (right)
        let quit_row = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(70),
                Constraint::Percentage(30), // Quit button width
            ])
            .split(main_chunks[1]);

        AppLayout {
            header: main_chunks[0],
            friends: main_chunks[2],
            network_map: Rect::new(0, 0, 0, 0), // Hidden on mobile
            network_status: Rect::new(0, 0, 0, 0), // Hidden on mobile
            chat: main_chunks[3],
            input: main_chunks[4],
            mobile_status: Some(quit_row[0]),
            quit_button: Some(quit_row[1]),
        }
    } else {
        // --- Desktop Layout ---
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
            mobile_status: None,
            quit_button: None,
        }
    }
}

