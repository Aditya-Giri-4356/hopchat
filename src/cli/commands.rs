// =============================================================================
// HOPCHAT — CLI Commands Module
// =============================================================================
//
// Handles slash commands entered in the chat input.
// Returns `true` if the input was handled as a command, effectively
// swallowing the input so it isn't sent as a regular chat message.

use crate::AppState;
use crate::chat::messages::ChatMessage;

/// Represents the result of parsing a CLI command
pub enum CommandResult {
    /// Input was not a command or should be ignored
    Ignored,
    /// Command was handled successfully
    Handled,
    /// Command triggered the network scanner
    TriggerScan,
}

/// Parses and executes an input string if it starts with a `/`.
/// Returns `CommandResult` indicating how the main loop should proceed.
pub async fn handle_command(state: &mut AppState, input: &str) -> CommandResult {
    let cmd = input.trim();
    if !cmd.starts_with('/') {
        return CommandResult::Ignored;
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
            let list = history_lock
                .entry(target_clone)
                .or_insert_with(Vec::new);
            list.push(sys_msg);
            if list.len() > 1000 { list.remove(0); }
        });
    };

    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let command_name = parts[0];

    match command_name {
        "/help" => {
            push_system_msg(
                "Commands:\n\
                /help         - Show this menu\n\
                /scan         - Open the Interactive Subnet Scanner\n\
                /connect <ip> - Manually connect to an IP (Bypasses discovery)\n\
                /peers        - List all discovered peers and their IPs\n\
                /quit         - Exit HopChat"
            );
        }
        "/scan" => {
            return CommandResult::TriggerScan;
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
                let target_ip = parts[1].to_string();

                // Validate IP address before sending
                if target_ip.parse::<std::net::IpAddr>().is_err() {
                    push_system_msg(&format!("Invalid IP address: {}", target_ip));
                } else {
                    let my_ip = local_ip_address::local_ip()
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|_| "127.0.0.1".to_string());

                    // Build discovery payload
                    let discovery_payload = format!(
                        "HOPCHAT|{}|{}|{}",
                        state.username, my_ip, state.chat_port
                    );

                    // Build key exchange handshake payload
                    let pub_x25519 = state.keypair.public_key_hex();
                    let pub_ed25519 = state.identity.public_key_hex();
                    let sig = state.identity.sign_payload(pub_x25519.as_bytes());
                    let key_payload = format!(
                        "HOPCHAT_KEY|{}|{}|{}|{}",
                        state.username, pub_x25519, pub_ed25519, sig
                    );

                    // Target addresses: both discovery port AND chat port
                    let discovery_port = crate::network::discovery::DISCOVERY_PORT;
                    let chat_port = crate::PREFERRED_CHAT_PORT;
                    let target_discovery = format!("{}:{}", target_ip, discovery_port);
                    let target_chat = format!("{}:{}", target_ip, chat_port);

                    let socket = state.outbound_socket.clone();
                    let disc_payload = discovery_payload.clone();
                    let key_pay = key_payload.clone();
                    let t_disc = target_discovery.clone();
                    let t_chat = target_chat.clone();

                    // Send discovery + key exchange to BOTH ports
                    tokio::spawn(async move {
                        // Discovery to both ports
                        let _ = socket.send_to(disc_payload.as_bytes(), &t_disc).await;
                        let _ = socket.send_to(disc_payload.as_bytes(), &t_chat).await;
                        // Key exchange to both ports
                        let _ = socket.send_to(key_pay.as_bytes(), &t_chat).await;
                        let _ = socket.send_to(key_pay.as_bytes(), &t_disc).await;

                        // Retry after a short delay for reliability
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        let _ = socket.send_to(disc_payload.as_bytes(), &t_disc).await;
                        let _ = socket.send_to(disc_payload.as_bytes(), &t_chat).await;
                        let _ = socket.send_to(key_pay.as_bytes(), &t_chat).await;
                        let _ = socket.send_to(key_pay.as_bytes(), &t_disc).await;
                    });

                    push_system_msg(&format!(
                        "Handshake sent to {}. Peer will appear in FRIENDS once they respond.",
                        target_ip
                    ));
                }
            }
        }
        _ => {
            push_system_msg(&format!("Unknown command: {}", command_name));
        }
    }

    CommandResult::Handled
}
