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
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

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
) {
    render_header(frame, layout.header);
    render_friends(frame, layout.friends, peers, selected_peer);
    render_network_map(frame, layout.network_map, username, peers);
    render_network_status(frame, layout.network_status, peers);
    render_chat(frame, layout.chat, username, messages, peers, selected_peer);
    render_input(frame, layout.input, input, cursor_pos);
}

/// Renders the top header bar.
fn render_header(frame: &mut Frame, area: Rect) {
    let header = Paragraph::new(" HOPCHAT v2.1.0")
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

/// Renders the friends list panel with selection highlighting.
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
                let style = if i == selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Green)
                };
                ListItem::new(format!("  {}", peer.username)).style(style)
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

/// Renders the network status bar.
fn render_network_status(
    frame: &mut Frame,
    area: Rect,
    peers: &[Peer],
) {
    let node_count = peers.len() + 1; // +1 for self
    let status_text = format!(
        " Nodes: {}     WiFi: {}     BLE: 00     Range: LAN",
        node_count, node_count
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
    sorted_messages.sort_by_key(|m| m.id);

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

    let chat = Paragraph::new(visible_lines).block(
        Block::default()
            .title(chat_title)
            .title_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(chat, area);
}

/// Renders the message input prompt with cursor.
fn render_input(frame: &mut Frame, area: Rect, input: &str, cursor_pos: usize) {
    let input_text = format!(" >>> {}", input);
    let input_widget = Paragraph::new(input_text)
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    frame.render_widget(input_widget, area);

    // Position the cursor in the input box
    // +5 accounts for the border (1) + " >>> " prefix (5)
    frame.set_cursor(
        area.x + 5 + cursor_pos as u16,
        area.y + 1,
    );
}
