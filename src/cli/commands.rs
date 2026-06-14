// =============================================================================
// HOPCHAT — CLI Commands Module
// =============================================================================
//
// Handles slash commands entered in the chat input.
// Returns `true` if the input was handled as a command, effectively
// swallowing the input so it isn't sent as a regular chat message.

use crate::AppState;
use crate::chat::messages::ChatMessage;

/// Parses and executes an input string if it starts with a `/`.
/// Returns `true` if it was a command, `false` otherwise.
pub async fn handle_command(state: &mut AppState, input: &str) -> bool {
    let cmd = input.trim();
    if !cmd.starts_with('/') {
        return false;
    }

    // Isolate the current selected peer to show system messages contextually
    // If no peers exist, we'll just push to a global/system log, but for
    // simplicity, MVP attaches system replies to the active window.
    let active_peer_username = {
        let peers_lock = state.peers.lock().await;
        let peers: Vec<_> = peers_lock.values().cloned().collect();
        if !peers.is_empty() && state.selected_peer < peers.len() {
            Some(peers[state.selected_peer].username.clone())
        } else {
            None
        }
    };

    let push_system_msg = |msg: &str| {
        let target = active_peer_username.clone().unwrap_or_else(|| "GLOBAL".to_string());
        let sys_msg = ChatMessage::new("SYSTEM", &target, msg);
        
        let history = state.chat_history.clone();
        let target_clone = target.clone();
        tokio::spawn(async move {
            let mut history_lock = history.lock().await;
            history_lock
                .entry(target_clone)
                .or_insert_with(Vec::new)
                .push(sys_msg);
        });
    };

    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let command_name = parts[0];

    match command_name {
        "/help" => {
            push_system_msg(
                "Commands:\n\
                /help         - Show this menu\n\
                /connect <ip> - Manually connect to an IP (Bypasses discovery)\n\
                /peers        - List all discovered peers and their IPs\n\
                /quit         - Exit HopChat"
            );
        }
        "/peers" => {
            let peers_lock = state.peers.lock().await;
            if peers_lock.is_empty() {
                push_system_msg("No peers discovered yet.");
            } else {
                let mut peer_list = String::from("Discovered Peers:\n");
                for peer in peers_lock.values() {
                    peer_list.push_str(&format!("- {} ({} : {})\n", peer.username, peer.ip, peer.port));
                }
                push_system_msg(peer_list.trim_end());
            }
        }
        "/quit" => {
            // Handled exclusively in main loop now.
            // When intercepting here, we don't do anything because
            // it's cleaner to let the input enum `InputAction::Quit` trigger it.
            // But we can throw a log just in case this gets trapped.
            push_system_msg("Type Ctrl-C or ESC to quit.");
        }
        "/connect" => {
            if parts.len() < 2 {
                push_system_msg("Usage: /connect <ip>");
            } else {
                let target_ip = parts[1];
                push_system_msg(&format!("Attempting manual connection to {}...", target_ip));

                // Send a direct unicast discovery packet
                // FORMAT: HOPCHAT|username|ip|port
                let target_addr = format!("{}:{}", target_ip, crate::network::discovery::DISCOVERY_PORT);
                
                let my_ip = local_ip_address::local_ip()
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|_| "127.0.0.1".to_string());
                let payload = format!("HOPCHAT|{}|{}|{}", state.username, my_ip, state.chat_port);

                let socket = state.outbound_socket.clone();
                tokio::spawn(async move {
                    let _ = socket.send_to(payload.as_bytes(), target_addr).await;
                });
            }
        }
        _ => {
            push_system_msg(&format!("Unknown command: {}", command_name));
        }
    }

    true
}
