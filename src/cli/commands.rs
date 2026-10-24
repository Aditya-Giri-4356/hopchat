// =============================================================================
// HOPCHAT — CLI Commands Module
// =============================================================================
//
// Handles slash commands entered in the chat input.
// Returns a CommandResult indicating how the main loop should proceed.

use crate::AppState;
use crate::chat::messages::ChatMessage;
use crate::network::messaging;
use std::collections::VecDeque;

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
pub async fn handle_command(state: &mut AppState, input: &str) -> CommandResult {
    let cmd = input.trim();
    if !cmd.starts_with('/') {
        return CommandResult::Ignored;
    }

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
                .or_insert_with(VecDeque::new);
            list.push_back(sys_msg);
            if list.len() > 1000 { list.pop_front(); }
        });
    };

    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let command_name = parts[0];

    match command_name {
        "/help" => {
            push_system_msg(
                "Commands:\n\
                /nearby       - Open the Nearby window (who is around you)\n\
                /peers        - List everyone on this network and their status\n\
                /trust        - Show the identity keys pinned for your peers\n\
                /unpin <name> - Forget a pinned key so a peer can pair again\n\
                /clear        - Clear this conversation\n\
                /connect <ip> [port] - Rarely needed: peers connect on their own\n\
                /quit         - Exit HopChat"
            );
        }
        "/nearby" | "/scan" => {
            return CommandResult::TriggerScan;
        }
        "/peers" => {
            let peers_lock = state.peers.lock().await;
            if peers_lock.is_empty() {
                push_system_msg(
                    "Nobody else found yet. You need to be on the same Wi-Fi or hotspot, \
                     and they need to be running HopChat.",
                );
            } else {
                let mut found: Vec<_> = peers_lock.values().collect();
                found.sort_by(|a, b| a.username.cmp(&b.username));
                let mut peer_list = String::from("Nearby:\n");
                for peer in found {
                    let label = if peer.connected {
                        "connected"
                    } else if peer.online {
                        "connecting"
                    } else {
                        "offline"
                    };
                    peer_list.push_str(&format!("- {} [{}] {}\n", peer.username, label, peer.ip));
                }
                push_system_msg(peer_list.trim_end());
            }
        }
        "/quit" => {
            state.quit_requested.store(true, std::sync::atomic::Ordering::Relaxed);
            return CommandResult::Handled;
        }
        "/trust" => {
            let entries = {
                let db = state.trust_db.lock().await;
                db.entries()
            };

            if entries.is_empty() {
                push_system_msg(
                    "No identities pinned yet. Peers are pinned automatically the \
                     first time they connect.",
                );
            } else {
                let mut out = String::from("Pinned identities:\n");
                for (user, key) in entries {
                    let short: String = key.chars().take(16).collect();
                    out.push_str(&format!("- {} {}\n", user, short));
                }
                out.push_str("Use /unpin <username> to forget one.");
                push_system_msg(out.trim_end());
            }
        }
        "/unpin" => {
            if parts.len() < 2 {
                push_system_msg("Usage: /unpin <username>");
            } else {
                let target = parts[1];
                let removed = {
                    let mut db = state.trust_db.lock().await;
                    db.unpin(target)
                };

                if removed {
                    push_system_msg(&format!(
                        "Forgot the pinned key for {}. It will be pinned again on next contact.",
                        target
                    ));
                } else {
                    push_system_msg(&format!("No pinned key stored for {}.", target));
                }
            }
        }
        "/clear" => {
            match active_peer_username.clone() {
                Some(peer) => {
                    {
                        let mut history = state.chat_history.lock().await;
                        history.remove(&peer);
                    }
                    push_system_msg(&format!("Cleared the conversation with {}.", peer));
                }
                None => {
                    {
                        let mut history = state.chat_history.lock().await;
                        history.clear();
                    }
                    push_system_msg("Cleared chat history.");
                }
            }
        }
        "/connect" => {
            if parts.len() < 2 {
                push_system_msg("Usage: /connect <ip> [port]");
            } else if parts.len() > 2 && parts[2].parse::<u16>().is_err() {
                push_system_msg(&format!(
                    "Invalid port: {}. Usage: /connect <ip> [port]",
                    parts[2]
                ));
            } else {
                let target_ip = parts[1].to_string();
                let explicit_port: Option<u16> = parts.get(2).and_then(|p| p.parse().ok());

                if target_ip.parse::<std::net::IpAddr>().is_err() {
                    push_system_msg(&format!("Invalid IP address: {}", target_ip));
                } else {
                    let my_ip = crate::get_local_ip();

                    // Signed discovery packet
                    let discovery_payload = messaging::create_signed_discovery(
                        &state.username, &my_ip, state.chat_port, &state.identity,
                    );

                    // Key exchange handshake payload
                    let pub_x25519 = state.keypair.public_key_hex();
                    let pub_ed25519 = state.identity.public_key_hex();
                    let sig = state.identity.sign_payload(pub_x25519.as_bytes());
                    let key_payload = format!(
                        "HOPCHAT_KEY|{}|{}|{}|{}",
                        state.username, pub_x25519, pub_ed25519, sig
                    );

                    let peer_chat_port = match explicit_port {
                        Some(port) => port,
                        None => {
                            let peers_lock = state.peers.lock().await;
                            peers_lock.values()
                                .find(|p| p.ip == target_ip)
                                .map(|p| p.port)
                                .unwrap_or(crate::PREFERRED_CHAT_PORT)
                        }
                    };

                    let discovery_port = crate::network::discovery::DISCOVERY_PORT;
                    let target_discovery = format!("{}:{}", target_ip, discovery_port);
                    let target_chat = format!("{}:{}", target_ip, peer_chat_port);

                    let socket = state.outbound_socket.clone();
                    let disc_payload = discovery_payload.clone();
                    let key_pay = key_payload.clone();
                    let t_disc = target_discovery.clone();
                    let t_chat = target_chat.clone();

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
