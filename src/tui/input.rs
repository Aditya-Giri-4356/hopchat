// =============================================================================
// HOPCHAT — TUI Module: Input Handling
// =============================================================================
//
// Processes keyboard events from crossterm and translates them into
// actions on the application state.

use crossterm::event::{Event, KeyCode, KeyEventKind, EventStream};
use futures::StreamExt;
use std::time::Duration;
use tokio::time::timeout;

/// Actions that can result from keyboard input.
pub enum InputAction {
    /// A character was typed into the input buffer
    Character(char),
    /// Backspace was pressed
    Backspace,
    /// Enter was pressed (send the message)
    Send,
    /// Move selection up in the friends list
    SelectUp,
    /// Move selection down in the friends list
    SelectDown,
    /// Quit the application
    Quit,
    /// No action (timeout or irrelevant event)
    None,
}

/// Asynchronously polls for keyboard input with a timeout.
///
/// Returns an InputAction describing what the user did.
/// The timeout ensures the event loop can process other tasks
/// (incoming messages, discovery, etc.) between input polls without blocking the thread.
pub async fn next_input_event(stream: &mut EventStream, max_wait: Duration) -> InputAction {
    if let Ok(Some(Ok(Event::Key(key)))) = timeout(max_wait, stream.next()).await {
        // Only handle Press events (crossterm may fire Release too)
        if key.kind != KeyEventKind::Press {
            return InputAction::None;
        }

        return match key.code {
            KeyCode::Char('c')
                if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) =>
            {
                InputAction::Quit
            }
            KeyCode::Esc => InputAction::Quit,
            KeyCode::Enter => InputAction::Send,
            KeyCode::Backspace => InputAction::Backspace,
            KeyCode::Up => InputAction::SelectUp,
            KeyCode::Down => InputAction::SelectDown,
            KeyCode::Char(c) => InputAction::Character(c),
            _ => InputAction::None,
        };
    }
    InputAction::None
}
