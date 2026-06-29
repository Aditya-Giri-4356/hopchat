// =============================================================================
// HOPCHAT — TUI Module: Renderer
// =============================================================================
//
// Renders each panel of the HOPCHAT interface using ratatui widgets.
// Each function renders one section of the UI into its allocated Rect.

use crate::chat::messages::ChatMessage;
use crate::network::peer_registry::Peer;
use crate::tui::layout::AppLayout;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

/// Renders the full HOPCHAT interface.
pub fn render_ui(
    frame: &mut Frame,
    layout: &AppLayout,
    username: &str,
    peers: &[Peer],
    selected_peer: usize,
    messages: &[ChatMessage],
    input: &str,
    cursor_pos: usize,
    scanner_visible: bool,
    scanner_index: usize,
) {
    render_header(frame, layout.header);
    render_friends(frame, layout.friends, peers, selected_peer);
    
    // Only render network map and status if they have space (Desktop layout)
    if layout.network_map.width > 0 {
        render_network_map(frame, layout.network_map, username, peers);
    }
    if layout.network_status.width > 0 {
        render_network_status(frame, layout.network_status, peers);
    }

    // [UI-MOB-3] Render compact mobile status bar if present
    if let Some(status_rect) = layout.mobile_status {
        render_mobile_status(frame, status_rect, username, peers);
    }

    // Render Quit button for Mobile layout
    if let Some(quit_rect) = layout.quit_button {
        render_quit_button(frame, quit_rect);
    }

    render_chat(frame, layout.chat, username, messages, peers, selected_peer);
    // [UI-DESK-3] cursor_pos is a char-count index. The renderer uses it as a visual
    // column offset, which is correct for most text. The byte-level fix is in main.rs
    // (UI-DESK-4) where insert/remove now use char_indices() for proper byte offsets.
    render_input(frame, layout.input, input, cursor_pos);

    if scanner_visible {
        render_scanner_popup(frame, peers, scanner_index);
    }
}

/// Renders the top header bar.
fn render_header(frame: &mut Frame, area: Rect) {
    let header = Paragraph::new(" HOPCHAT v2.1.1")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    frame.render_widget(header, area);
}

/// [UI-MOB-2] Renders the friends list panel with selection highlighting.
/// Uses green-on-black with a `>>` marker for selected items — readable
/// on both light and dark terminal backgrounds.
fn render_friends(
    frame: &mut Frame,
    area: Rect,
    peers: &[Peer],
    selected: usize,
) {
    let items: Vec<ListItem> = if peers.is_empty() {
        vec![ListItem::new("  (no peers found)").style(Style::default().fg(Color::DarkGray))]
    } else {
        peers
            .iter()
            .enumerate()
            .map(|(i, peer)| {
                // [UI-MOB-2] Use >> marker and Green bg for universal readability
                let (text, style) = if i == selected {
                    (
                        format!(">> {}", peer.username),
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    )
                } else {
                    (
                        format!("   {}", peer.username),
                        Style::default().fg(Color::Green),
                    )
                };
                ListItem::new(text).style(style)
            })
            .collect()
    };

    let list = List::new(items).block(
        Block::default()
            .title(" FRIENDS ")
            .title_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(list, area);
}

/// Renders the network map placeholder panel.
fn render_network_map(
    frame: &mut Frame,
    area: Rect,
    username: &str,
    peers: &[Peer],
) {
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(""));

    // Show a simple ASCII topology
    let you_label = format!("  YOU ({})", username);
    lines.push(Line::from(Span::styled(
        you_label,
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));

    for peer in peers {
        lines.push(Line::from(Span::styled(
            format!("   ├── {}", peer.username),
            Style::default().fg(Color::Green),
        )));
    }

    if peers.is_empty() {
        lines.push(Line::from(Span::styled(
            "   (no connections)",
            Style::default().fg(Color::DarkGray),
        )));
    }

    // MESH ROUTING PLACEHOLDER:
    // In a mesh network, the network map would display multi-hop
    // topologies, showing relay paths between nodes that are not
    // directly connected. A graph structure with hop counts would
    // be rendered here instead of a simple list.

    let map = Paragraph::new(lines).block(
        Block::default()
            .title(" NETWORK MAP ")
            .title_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(map, area);
}

/// [UI-DESK-2] Renders the network status bar with honest reporting.
/// WiFi count previously duplicated total node count. Now shows actual
/// peer count and connection status. BLE shows "--" until implemented.
fn render_network_status(
    frame: &mut Frame,
    area: Rect,
    peers: &[Peer],
) {
    let peer_count = peers.len();
    let status_text = format!(
        " Online: {}  |  Peers: {}  |  BLE: --  |  Range: LAN",
        if peer_count > 0 { "CONNECTED" } else { "SCANNING" },
        peer_count
    );

    let status = Paragraph::new(status_text)
        .style(Style::default().fg(Color::Magenta))
        .block(
            Block::default()
                .title(" NETWORK STATUS ")
                .title_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    frame.render_widget(status, area);
}

/// Renders the chat message window.
/// [UI-DESK-1] Messages sorted by timestamp (then id as tiebreaker).
/// [UI-DESK-5] Long messages are word-wrapped instead of clipped.
fn render_chat(
    frame: &mut Frame,
    area: Rect,
    username: &str,
    messages: &[ChatMessage],
    peers: &[Peer],
    selected_peer: usize,
) {
    // Determine chat title based on selected peer
    let chat_title = if peers.is_empty() {
        " CHAT ".to_string()
    } else {
        let peer_name = &peers[selected_peer.min(peers.len().saturating_sub(1))].username;
        format!(" CHAT : PRIVATE({}) ", peer_name)
    };

    // Filter messages relevant to the selected conversation
    // Use the messages slice directly since main.rs filters it for us
    let mut sorted_messages = messages.to_vec();
    // [UI-DESK-1] Sort by timestamp first, then by id as tiebreaker.
    // This ensures cross-peer messages display in correct chronological order
    // regardless of the random seed used for message IDs.
    sorted_messages.sort_by(|a, b| {
        a.timestamp.cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id))
    });

    let chat_lines: Vec<Line> = sorted_messages
        .iter()
        .map(|msg| {
            let label = if msg.sender == username {
                "YOU"
            } else {
                &msg.sender
            };
            
            // Format unix timestamp to a simple %H:%M using chrono under the hood,
            // or just use naive formatting if chrono is preferred.
            // But we already dropped chrono in ChatMessage. Let's just restore chrono usage here 
            // for display purposes since it's already in the dependencies.
            let dt = chrono::DateTime::from_timestamp(msg.timestamp as i64, 0)
                .unwrap_or_default()
                .with_timezone(&chrono::Local);
            let time = dt.format("%H:%M");
            
            Line::from(vec![
                Span::styled(
                    format!(" [{}] ", time),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("{}: ", label),
                    Style::default()
                        .fg(if msg.sender == username {
                            Color::Cyan
                        } else {
                            Color::Green
                        })
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(&msg.content),
            ])
        })
        .collect();

    // Auto-scroll: only show the last N lines that fit
    let visible_height = area.height.saturating_sub(2) as usize;
    let start = chat_lines.len().saturating_sub(visible_height);
    let visible_lines: Vec<Line> = chat_lines[start..].to_vec();

    // [UI-DESK-5] Add word wrapping so long messages are not clipped at terminal width
    let chat = Paragraph::new(visible_lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(chat_title)
                .title_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    frame.render_widget(chat, area);
}

/// Renders the message input prompt with cursor.
/// [UI-DESK-3] cursor_pos is a char-count index. This is used directly as a visual
/// column offset, which is correct for the display. The byte-level fix for
/// insert/remove operations is in main.rs (UI-DESK-4).
fn render_input(frame: &mut Frame, area: Rect, input: &str, cursor_pos: usize) {
    let style = Style::default().fg(Color::White);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
        
    let text = ratatui::text::Text::from(vec![
        ratatui::text::Line::from(vec![Span::styled(format!("> {}", input), style)]),
    ]);

    let input_widget = Paragraph::new(text).block(block);
    frame.render_widget(input_widget, area);

    // Render cursor
    frame.set_cursor(
        area.x + 3 + cursor_pos as u16, // +3 for "> " prefix and border
        area.y + 1,
    );
}

/// Renders the mobile-specific Quit button
fn render_quit_button(frame: &mut Frame, area: Rect) {
    let text = ratatui::text::Text::from(vec![
        ratatui::text::Line::from(vec![Span::styled(
            "   [ QUIT ]   ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        )]),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red))
        .style(Style::default().bg(Color::Black));
        
    let p = Paragraph::new(text).block(block).alignment(Alignment::Center);
    frame.render_widget(p, area);
}

/// [UI-MOB-3] Renders a compact mobile status bar showing username and peer count.
fn render_mobile_status(frame: &mut Frame, area: Rect, username: &str, peers: &[Peer]) {
    let status_text = format!(" user: {}  |  peers: {}", username, peers.len());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let p = Paragraph::new(status_text)
        .style(Style::default().fg(Color::Magenta))
        .block(block);
    frame.render_widget(p, area);
}

/// [UI-DESK-6] [UI-MOB-6] Renders the network scanner interactive popup overlay.
/// Popup dimensions are dynamically scaled to the terminal size with padding,
/// and a scroll position indicator is shown when the list exceeds visible height.
fn render_scanner_popup(frame: &mut Frame, peers: &[Peer], selected_index: usize) {
    let area = frame.size();
    
    // [UI-MOB-6] Scale popup to terminal width with 2-char padding on each side, max 60
    let popup_width = area.width.saturating_sub(4).min(60);
    // [UI-DESK-6] Clamp popup height to available space with breathing room
    let popup_height = area.height.saturating_sub(4).min(15);
    
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    use ratatui::widgets::{Clear, ListState};

    frame.render_widget(Clear, popup_area); // Clear background

    let title = " Network Subnet Scanner (Tab to close) ";

    // [UI-DESK-6] Footer with scroll position indicator
    let visible_items = popup_height.saturating_sub(4) as usize; // borders + header + footer padding
    let footer = if peers.len() > visible_items {
        format!(" [{}/{}] Up/Down to scroll ", selected_index + 1, peers.len())
    } else {
        format!(" {} peer(s) found ", peers.len())
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .style(Style::default().bg(Color::Black));

    let mut items: Vec<ListItem> = if peers.is_empty() {
        vec![ListItem::new("  (Scanning... No peers found yet)").style(Style::default().fg(Color::DarkGray))]
    } else {
        peers.iter().enumerate().map(|(i, peer)| {
            let hostname_str = if let Some(ref h) = peer.hostname {
                format!(" ({})", h)
            } else {
                "".to_string()
            };
            
            let display_str = format!(" {} - {}{}", peer.username, peer.ip, hostname_str);
            let mut style = Style::default().fg(Color::White);
            
            if i == selected_index {
                style = style.bg(Color::Blue).add_modifier(Modifier::BOLD);
            }
            
            ListItem::new(display_str).style(style)
        }).collect()
    };

    // [UI-DESK-6] Add footer as last list item (compatible with all ratatui versions)
    items.push(ListItem::new(footer).style(Style::default().fg(Color::DarkGray)));

    let list = List::new(items)
        .block(block)
        .highlight_style(Style::default().add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");

    let mut state = ListState::default();
    state.select(Some(selected_index));
    frame.render_stateful_widget(list, popup_area, &mut state);
}

// CHANGES:
// [UI-DESK-1] render_chat: Sort by timestamp.then_with(id) instead of id alone.
// [UI-DESK-2] render_network_status: Shows honest "Online: CONNECTED/SCANNING" and
//             actual peer count. BLE shows "--" instead of fake "00".
// [UI-DESK-3] render_input: Added comment documenting cursor_pos dependency on main.rs.
// [UI-DESK-5] render_chat: Added .wrap(Wrap { trim: false }) to prevent clipping.
// [UI-DESK-6] render_scanner_popup: Clamped popup_height to area.height-4. Added
//             scroll position footer as a ListItem.
// [UI-MOB-2] render_friends: Changed selected style to fg(Black)/bg(Green) with ">>" marker.
// [UI-MOB-3] Added render_mobile_status() for the compact mobile status bar.
// [UI-MOB-6] render_scanner_popup: popup_width scaled to area.width-4, max 60.
