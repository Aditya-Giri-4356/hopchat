// =============================================================================
// HOPCHAT — CLI Commands Module
// =============================================================================
//
// Handles slash commands entered in the chat input.
// Returns a CommandResult indicating how the main loop should proceed.

use crate::chat::messages::ChatMessage;
use crate::network::{messaging, wifi};
use crate::AppState;
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
        // Must use the same ordering as the renderer, or `selected_peer`
        // points at a different person every time the HashMap is rehashed.
        let mut peers: Vec<_> = peers_lock.values().cloned().collect();
        peers.sort_by(|a, b| a.username.cmp(&b.username));
        if !peers.is_empty() && state.selected_peer < peers.len() {
            Some(peers[state.selected_peer].username.clone())
        } else {
            None
        }
    };

    let push_system_msg = |msg: &str| {
        let target = active_peer_username
            .clone()
            .unwrap_or_else(|| "GLOBAL".to_string());
        let sys_msg = ChatMessage::new("SYSTEM", &target, msg);

        let history = state.chat_history.clone();
        let target_clone = target.clone();
        tokio::spawn(async move {
            let mut history_lock = history.lock().await;
            let list = history_lock
                .entry(target_clone)
                .or_insert_with(VecDeque::new);
            list.push_back(sys_msg);
            if list.len() > 1000 {
                list.pop_front();
            }
        });
    };

    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let command_name = parts[0];

    match command_name {
        "/help" => {
            push_system_msg(
                "Commands:\n\
                /nearby       - Open the Nearby window (who is around you)\n\
                /peers        - List everyone nearby and how they are linked\n\
                /wifi         - Wi-Fi/LAN status; on, off, or scan\n\
                /bluetooth    - Bluetooth status; on, off, or scan\n\
                /trust        - Show the identity keys pinned for your peers\n\
                /unpin <name> - Forget a pinned key so a peer can pair again\n\
                /clear        - Clear this conversation\n\
                /connect <ip> [port] - Rarely needed: peers connect on their own\n\
                /quit         - Exit HopChat",
            );
        }
        "/wifi" => {
            let action = parts.get(1).copied().unwrap_or("status");
            match action {
                "on" | "off" => {
                    let on = action == "on";
                    state
                        .lan_enabled
                        .store(on, std::sync::atomic::Ordering::Relaxed);
                    push_system_msg(if on {
                        "Wi-Fi/LAN announcements on. Peers on this network will see you again within 10 seconds."
                    } else {
                        "Wi-Fi/LAN announcements off. You can still receive from peers who already know your address; /wifi on resumes broadcasts."
                    });
                }
                "scan" => {
                    return CommandResult::TriggerScan;
                }
                _ => {
                    let status = wifi::status(&crate::get_local_ip(), &state.lan_enabled);
                    let mut out = String::from("Wi-Fi / LAN\n");
                    out.push_str(&format!(
                        "  announcements: {}\n  primary address: {}\n",
                        if status.enabled { "on" } else { "off" },
                        status.ip
                    ));
                    if let Some(iface) = status.wifi_interface() {
                        out.push_str(&format!("  wi-fi interface: {} {}\n", iface.name, iface.ip));
                    }
                    if status.interfaces.is_empty() {
                        out.push_str("  interfaces: none (no IPv4 link)\n");
                    } else {
                        out.push_str("  interfaces:\n");
                        for iface in &status.interfaces {
                            out.push_str(&format!(
                                "  - {}  {}{}\n",
                                iface.name,
                                iface.ip,
                                if iface.private { " (private)" } else { "" }
                            ));
                        }
                    }
                    if status.subnets.is_empty() {
                        out.push_str("  sweep: broadcast/multicast only");
                    } else {
                        out.push_str(&format!("  sweep: {}.x", status.subnets.join(".x, ")));
                    }
                    push_system_msg(out.trim_end());
                }
            }
        }
        "/bluetooth" | "/ble" => {
            let action = parts.get(1).copied().unwrap_or("status");
            match action {
                "on" | "off" => {
                    let on = action == "on";
                    state.ble.set_enabled(on);
                    push_system_msg(if !state.ble.status().await.supported {
                        "Bluetooth is not available in this build. iSH cannot access Bluetooth hardware; Wi-Fi still works."
                    } else if on {
                        "Bluetooth on. Advertising and scanning resume within a couple of seconds."
                    } else {
                        "Bluetooth off. Existing links go idle and new peers will not be discovered over BLE; Wi-Fi is unaffected."
                    });
                }
                "scan" => {
                    let status = state.ble.status().await;
                    push_system_msg(&format!(
                        "Bluetooth {} — {}. Scanning is continuous while enabled.",
                        status.summary(),
                        status.detail
                    ));
                }
                _ => {
                    let status = state.ble.status().await;
                    let mut out = String::from("Bluetooth\n");
                    if !status.supported {
                        out.push_str(&format!("  {}", status.detail));
                    } else {
                        out.push_str(&format!(
                            "  state: {}\n  powered: {}\n  advertising: {}\n  scanning: {}\n  links: {}\n  {}",
                            status.summary(),
                            yes_no(status.powered),
                            yes_no(status.advertising),
                            yes_no(status.scanning),
                            status.links,
                            status.detail
                        ));
                        let peers = state.ble.linked_peers();
                        if !peers.is_empty() {
                            out.push_str(&format!("\n  linked peers: {}", peers.join(", ")));
                        }
                    }
                    push_system_msg(out.trim_end());
                }
            }
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
                    let label = match (peer.connected, peer.ble_connected) {
                        (true, true) => "connected: LAN + Bluetooth",
                        (true, false) => "connected: LAN",
                        (false, true) => "connected: Bluetooth",
                        (false, false) if peer.online => "connecting",
                        (false, false) => "offline",
                    };
                    peer_list.push_str(&format!("- {} [{}] {}\n", peer.username, label, peer.ip));
                }
                push_system_msg(peer_list.trim_end());
            }
        }
        "/quit" => {
            state
                .quit_requested
                .store(true, std::sync::atomic::Ordering::Relaxed);
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
        "/clear" => match active_peer_username.clone() {
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
                    history.remove("GLOBAL");
                }
                push_system_msg("Cleared the GLOBAL conversation.");
            }
        },
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
                        &state.username,
                        &my_ip,
                        state.chat_port,
                        &state.identity,
                    );

                    // Key exchange handshake payload (username is signed too)
                    let key_payload = messaging::build_key_packet(
                        &state.username,
                        &state.keypair.public_key_hex(),
                        &state.identity,
                    );

                    let peer_chat_port = match explicit_port {
                        Some(port) => port,
                        None => {
                            let peers_lock = state.peers.lock().await;
                            peers_lock
                                .values()
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

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
