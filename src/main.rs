// =============================================================================
// HOPCHAT v2.0.0 — Main Entry Point
// =============================================================================
//
// Orchestrates all subsystems:
//   1. Username login prompt
//   2. UDP discovery (broadcast + listen)
//   3. UDP messaging server (incoming encrypted messages)
//   4. TUI event loop (rendering + input + outgoing messages)
//
// Uses tokio for async runtime with concurrent tasks.

mod chat;
mod cli;
mod crypto;
mod network;
mod tui;
mod user;

use chat::messages::ChatMessage;
use crypto::key_exchange::X25519KeyPair;
use network::{discovery, messaging, peer_registry};
use network::messaging::{AckRegistry, ChatHistory, DedupCache, PeerKeyRegistry, TofuRegistry};
use tui::{input, layout, renderer};
use network::peer_registry::{Peer, PeerRegistry};
use user::identity::LocalIdentity;

use crossterm::{
    event::{EventStream, EnableMouseCapture, DisableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Default chat port (used as a preferred bind target).
/// If unavailable, a dynamic port is assigned automatically.
const PREFERRED_CHAT_PORT: u16 = 9878;

pub struct ScannerState {
    pub is_visible: bool,
    pub selected_index: usize,
    pub local_ip: String,
}

/// Shared application state accessible from multiple async tasks.
pub struct AppState {
    /// The local user's username
    pub username: String,
    /// Discovered peers registry
    pub peers: PeerRegistry,
    /// Chat message history by peer username
    pub chat_history: ChatHistory,
    /// Shared tracker for outbound messages awaiting ACKs
    ack_registry: AckRegistry,
    /// Registry mapping peer usernames to their 32-byte symmetric session key
    pub peer_keys: PeerKeyRegistry,
    /// The local keypair
    pub keypair: Arc<X25519KeyPair>,
    /// The local long-term Ed25519 identity
    pub identity: Arc<LocalIdentity>,
    /// Current text in the input buffer
    pub input_buffer: String,
    /// Cursor position within the input buffer (char index, not byte index)
    pub cursor_pos: usize,
    /// Shared UDP socket for ALL messaging (send + receive on same port)
    pub outbound_socket: Arc<UdpSocket>,
    /// The actual port we are listening on (may differ from PREFERRED_CHAT_PORT)
    pub chat_port: u16,
    /// Index of the currently selected peer in the friends list
    pub selected_peer: usize,
    /// State for the subnet scanner popup overlay
    pub scanner: ScannerState,
    /// [UI-MOB-5] Shared quit flag — set by /quit command, checked at loop top
    pub quit_requested: Arc<AtomicBool>,
    /// [UI-MOB-4] Cached quit button rect from last draw for reliable click detection
    pub last_quit_button_rect: Option<ratatui::layout::Rect>,
}

/// Prompts the user for their username via stdin (before TUI starts).
/// Sanitizes input to prevent pipe-injection attacks on the discovery protocol.
fn prompt_username() -> String {
    print!("\n  ╔══════════════════════════════════╗\n");
    print!("  ║        HOPCHAT v2.1.1            ║\n");
    print!("  ╠══════════════════════════════════╣\n");
    print!("  ║  Enter your username:            ║\n");
    print!("  ╚══════════════════════════════════╝\n");
    print!("  >>> ");
    io::stdout().flush().unwrap();

    let mut username = String::new();
    io::stdin().read_line(&mut username).unwrap();

    // Sanitize: strictly alphanumeric and underscores to prevent Path Traversal
    // (e.g., ../../../etc/shadow) and shell injection attacks. Enforce a max length of 32.
    let username: String = username
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(32)
        .collect();

    if username.is_empty() {
        "anon".to_string()
    } else {
        username
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Step 1: Login ---
    let username = prompt_username();

    // Detect local IP address robustly
    let local_ip = get_local_ip();

    println!("\n  Starting HOPCHAT as '{}' on {}:{}", username, local_ip, PREFERRED_CHAT_PORT);
    println!("  Press any key to enter the chat...");

    // Wait for a keypress before entering TUI
    let _ = io::stdin().read_line(&mut String::new());

    // --- Step 2: Set up shared state ---
    let local_identity = Arc::new(LocalIdentity::load_or_create(&username));
    let local_keypair = Arc::new(X25519KeyPair::generate());
    let peers: PeerRegistry = Arc::new(Mutex::new(HashMap::new()));
    let chat_history: ChatHistory = Arc::new(Mutex::new(HashMap::new()));
    let ack_registry: AckRegistry = Arc::new(Mutex::new(HashMap::new()));
    // [CONN-7] DedupCache is now HashSet<u64> for O(1) contains()
    let dedup_cache: DedupCache = Arc::new(Mutex::new(HashSet::new()));
    let peer_keys: PeerKeyRegistry = Arc::new(Mutex::new(HashMap::new()));
    // [CONN-4] TOFU registry lives on AppState, persists for process lifetime
    let tofu_registry: TofuRegistry = Arc::new(Mutex::new(HashMap::new()));

    // Create a SINGLE shared socket for all messaging (send + receive).
    // Try the preferred port first; fall back to a dynamic port if taken.
    let shared_socket = match tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", PREFERRED_CHAT_PORT)).await {
        Ok(s) => Arc::new(s),
        Err(_) => Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?),
    };
    let chat_port = shared_socket.local_addr()?.port();

    let mut state = AppState {
        username: username.clone(),
        peers: peers.clone(),
        chat_history: chat_history.clone(),
        ack_registry: ack_registry.clone(),
        peer_keys: peer_keys.clone(),
        outbound_socket: shared_socket.clone(),
        keypair: local_keypair.clone(),
        identity: local_identity.clone(),
        input_buffer: String::new(),
        cursor_pos: 0,
        chat_port,
        selected_peer: 0,
        scanner: ScannerState {
            is_visible: false,
            selected_index: 0,
            local_ip: local_ip.clone(),
        },
        quit_requested: Arc::new(AtomicBool::new(false)),
        last_quit_button_rect: None,
    };

    // --- Step 3: Spawn background network tasks ---

    // UDP discovery: broadcast our presence (with the actual bound port)
    let bcast_username = username.clone();
    let bcast_ip = local_ip.clone();
    let bcast_port = chat_port;
    tokio::spawn(async move {
        // Non-fatal: if broadcast fails (e.g. on iSH), directed scan is the fallback
        if let Err(e) = discovery::broadcast_presence(bcast_username, bcast_ip, bcast_port).await {
            eprintln!("[hopchat] broadcast_presence stopped: {}", e);
        }
    });

    // UDP discovery: listen for peers (binds to port 9877)
    let listen_ip = local_ip.clone();
    let listen_username = username.clone();
    let listen_peers = peers.clone();
    tokio::spawn(async move {
        // Non-fatal on iSH: the chat listener (port 9878) also handles discovery
        if let Err(e) = discovery::listen_for_peers(listen_ip, listen_username, listen_peers).await
        {
            eprintln!("[hopchat] listen_for_peers stopped: {} — chat port listener still active", e);
        }
    });

    // UDP server: receive structured encrypted incoming messages and keys
    // Uses the SAME shared_socket for both receiving and sending responses.
    // [CONN-4] Pass tofu_registry into listen_for_messages
    let listen_history = chat_history.clone();
    let listen_acks = ack_registry.clone();
    let listen_dedup = dedup_cache.clone();
    let listen_peer_keys = peer_keys.clone();
    let listen_keypair = local_keypair.clone();
    let listen_identity = local_identity.clone();
    let listen_username = username.clone();
    let listen_socket = shared_socket.clone();
    let listen_peers = peers.clone();
    let listen_tofu = tofu_registry.clone();
    tokio::spawn(async move {
        if let Err(e) = messaging::listen_for_messages(
            listen_socket, listen_username, listen_history, listen_acks, listen_dedup, listen_peer_keys, listen_keypair, listen_identity, listen_peers, listen_tofu
        ).await {
            eprintln!("Messaging listen error: {}", e);
        }
    });

    // Peer registry cleanup: drop peers inactive for > 15s
    let cleanup_peers = peers.clone();
    tokio::spawn(async move {
        peer_registry::cleanup_task(cleanup_peers).await;
    });

    // --- Step 4: Set up the TUI ---
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // --- Step 5: Main event loop ---
    let result = run_event_loop(&mut terminal, &mut state).await;

    // --- Step 6: Cleanup ---
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Error: {}", e);
    }

    Ok(())
}

/// Spawns an async task that scans the local subnet by sending both discovery
/// and key exchange packets to all 254 host IPs. This is the critical fallback
/// for iSH/Termux where broadcast/multicast are unreliable or unsupported.
fn spawn_subnet_scan(state: &AppState) {
    let parts: Vec<&str> = state.scanner.local_ip.split('.').collect();
    if parts.len() != 4 {
        return;
    }

    let prefix = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
    let socket = state.outbound_socket.clone();

    let discovery_payload = format!(
        "HOPCHAT|{}|{}|{}",
        state.username, state.scanner.local_ip, state.chat_port
    );

    // Build key exchange payload so peers can immediately derive session keys
    let pub_x25519 = state.keypair.public_key_hex();
    let pub_ed25519 = state.identity.public_key_hex();
    let sig = state.identity.sign_payload(pub_x25519.as_bytes());
    let key_payload = format!(
        "HOPCHAT_KEY|{}|{}|{}|{}",
        state.username, pub_x25519, pub_ed25519, sig
    );

    let disc_port = discovery::DISCOVERY_PORT;
    let chat_port = crate::PREFERRED_CHAT_PORT;

    tokio::spawn(async move {
        for i in 1..=254u8 {
            let target_ip = format!("{}.{}", prefix, i);
            let target_disc = format!("{}:{}", target_ip, disc_port);
            let target_chat = format!("{}:{}", target_ip, chat_port);

            // Send discovery to BOTH ports
            let _ = socket.send_to(discovery_payload.as_bytes(), &target_disc).await;
            let _ = socket.send_to(discovery_payload.as_bytes(), &target_chat).await;
            // Send key exchange to BOTH ports
            let _ = socket.send_to(key_payload.as_bytes(), &target_disc).await;
            let _ = socket.send_to(key_payload.as_bytes(), &target_chat).await;
        }
    });
}

/// Returns the device's local IP address robustly by querying the OS routing table.
/// This works on iSH where `local_ip_address` often fails or returns 127.0.0.1.
fn get_local_ip() -> String {
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    local_ip_address::local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

/// The main event loop that handles UI rendering, input, and outgoing messages.
async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut AppState,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut event_stream = EventStream::new();
    
    loop {
        // [UI-MOB-5] Check the shared quit flag at the top of every iteration
        if state.quit_requested.load(Ordering::Relaxed) {
            break;
        }

        // --- Get current peer list snapshot ---
        let peers_snapshot: Vec<Peer> = {
            let peers_lock = state.peers.lock().await;
            peers_lock.values().cloned().collect()
        };

        // Clamp selected_peer to valid range
        if !peers_snapshot.is_empty() && state.selected_peer >= peers_snapshot.len() {
            state.selected_peer = peers_snapshot.len() - 1;
        }

        // --- Get chat history snapshot for selected peer ---
        let selected_username = if !peers_snapshot.is_empty() {
            peers_snapshot[state.selected_peer].username.clone()
        } else {
            String::new()
        };

        let active_messages: Vec<ChatMessage> = {
            let history_lock = state.chat_history.lock().await;
            history_lock
                .get(&selected_username)
                .cloned()
                .unwrap_or_else(Vec::new)
        };

        // --- Render the UI ---
        // [UI-MOB-4] Cache the quit_button rect from the last successful draw
        terminal.draw(|frame| {
            let app_layout = layout::compute_layout(frame.size());
            renderer::render_ui(
                frame,
                &app_layout,
                &state.username,
                &peers_snapshot,
                state.selected_peer,
                &active_messages,
                &state.input_buffer,
                state.cursor_pos,
                state.scanner.is_visible,
                state.scanner.selected_index,
            );
            // Cache the quit button rect for click detection
            state.last_quit_button_rect = app_layout.quit_button;
        })?;

        // --- Asynchronously poll for keyboard input (50ms timeout) ---
        let action = input::next_input_event(&mut event_stream, Duration::from_millis(50)).await;

        match action {
            input::InputAction::Quit => break,

            input::InputAction::Click(x, y) => {
                // [UI-MOB-4] Use cached quit_button rect from last draw instead of
                // recomputing layout from terminal.size().unwrap_or_default()
                if let Some(quit_rect) = state.last_quit_button_rect {
                    if x >= quit_rect.x && x < quit_rect.x + quit_rect.width &&
                       y >= quit_rect.y && y < quit_rect.y + quit_rect.height {
                        break;
                    }
                }
            }

            input::InputAction::ToggleScanner => {
                state.scanner.is_visible = !state.scanner.is_visible;
                if state.scanner.is_visible {
                    state.scanner.selected_index = 0;
                    spawn_subnet_scan(state);
                }
            }

            input::InputAction::Character(c) => {
                if !state.scanner.is_visible {
                    // [UI-DESK-4] Translate cursor_pos (char index) to byte offset
                    // before String::insert to prevent panics on multibyte UTF-8 chars
                    let byte_pos = state.input_buffer
                        .char_indices()
                        .nth(state.cursor_pos)
                        .map(|(i, _)| i)
                        .unwrap_or_else(|| state.input_buffer.len());
                    state.input_buffer.insert(byte_pos, c);
                    state.cursor_pos += 1;
                }
            }

            input::InputAction::Backspace => {
                // [UI-DESK-4] Translate cursor_pos (char index) to byte offset
                // before String::remove to prevent panics on multibyte UTF-8 chars
                if !state.scanner.is_visible && state.cursor_pos > 0 {
                    state.cursor_pos -= 1;
                    let byte_pos = state.input_buffer
                        .char_indices()
                        .nth(state.cursor_pos)
                        .map(|(i, _)| i)
                        .unwrap_or_else(|| state.input_buffer.len());
                    state.input_buffer.remove(byte_pos);
                }
            }

            input::InputAction::SelectUp => {
                if state.scanner.is_visible {
                    if state.scanner.selected_index > 0 {
                        state.scanner.selected_index -= 1;
                    }
                } else {
                    if state.selected_peer > 0 {
                        state.selected_peer -= 1;
                    }
                }
            }

            input::InputAction::SelectDown => {
                if state.scanner.is_visible {
                    if state.scanner.selected_index < peers_snapshot.len().saturating_sub(1) {
                        state.scanner.selected_index += 1;
                    }
                } else {
                    if !peers_snapshot.is_empty()
                        && state.selected_peer < peers_snapshot.len() - 1
                    {
                        state.selected_peer += 1;
                    }
                }
            }

            input::InputAction::Send => {
                if state.scanner.is_visible {
                    if !peers_snapshot.is_empty() && state.scanner.selected_index < peers_snapshot.len() {
                        let target_ip = peers_snapshot[state.scanner.selected_index].ip.clone();
                        let cmd_input = format!("/connect {}", target_ip);
                        cli::commands::handle_command(state, &cmd_input).await;
                    }
                    state.scanner.is_visible = false;
                    continue;
                }
                
                if !state.input_buffer.is_empty() {
                    let cmd_input = state.input_buffer.clone();
                    
                    // 1. Intercept CLI Commands (e.g., /connect, /help)
                    match cli::commands::handle_command(state, &cmd_input).await {
                        cli::commands::CommandResult::Handled => {
                            state.input_buffer.clear();
                            state.cursor_pos = 0;
                            continue;
                        }
                        cli::commands::CommandResult::TriggerScan => {
                            state.input_buffer.clear();
                            state.cursor_pos = 0;
                            
                            // Trigger the scanner overlay manually
                            state.scanner.is_visible = true;
                            state.scanner.selected_index = 0;
                            spawn_subnet_scan(state);
                            continue;
                        }
                        cli::commands::CommandResult::Ignored => {}
                    }

                    // 2. Chat Message Flow
                    if !peers_snapshot.is_empty() {
                        let peer = &peers_snapshot[state.selected_peer];
                    
                    // Look up the specific session key
                    let session_key = {
                        let keys_lock = state.peer_keys.lock().await;
                        keys_lock.get(&peer.username).cloned()
                    };

                    if let Some(session_key) = session_key {
                        // Key exists, send encrypted chat message
                        let message = ChatMessage::new(
                            &state.username,
                            &peer.username,
                            &state.input_buffer,
                        );

                        // Add to our local chat history
                        {
                            let mut history_lock = state.chat_history.lock().await;
                            
                            let list = history_lock
                                .entry(peer.username.clone())
                                .or_insert_with(Vec::new);
                            list.push(message.clone());
                            if list.len() > 1000 { list.remove(0); }
                                
                            // Add a purely local UI indication of secure transit
                            let secure_ux_msg = ChatMessage::new(
                                "SYSTEM",
                                &peer.username,
                                "Sent (Encrypted ✓)",
                            );
                            list.push(secure_ux_msg);
                            if list.len() > 1000 { list.remove(0); }
                        }

                        // Send to the peer asynchronously via reliable encrypted structured UDP
                        if let Ok(addr) = peer.socket_addr() {
                            let msg = message;
                            let acks = state.ack_registry.clone();
                            let socket_clone = state.outbound_socket.clone();
                            tokio::spawn(async move {
                                if let Err(e) = messaging::send_message_with_retry(socket_clone, addr, &msg, acks, session_key).await {
                                    let _ = e;
                                }
                            });
                        }

                        // Clear the input buffer
                        state.input_buffer.clear();
                        state.cursor_pos = 0;
                    } else {
                        // We don't have a session key for this peer yet.
                        // Initiate Key Exchange!
                        if let Ok(addr) = peer.socket_addr() {
                            let pub_x25519 = state.keypair.public_key_hex();
                            let pub_ed25519 = state.identity.public_key_hex();
                            let sig = state.identity.sign_payload(pub_x25519.as_bytes());

                            let handshake_packet = format!(
                                "HOPCHAT_KEY|{}|{}|{}|{}",
                                state.username, pub_x25519, pub_ed25519, sig
                            );
                            
                            let socket_clone = state.outbound_socket.clone();
                            tokio::spawn(async move {
                                let _ = messaging::send_raw_packet(&socket_clone, addr, &handshake_packet).await;
                            });
                        }
                        
                        // Keep the user input so they don't have to retype it.
                        // Insert a local system warning into UI showing the TOFU Fingerprint
                        let tofu_code = state.identity.tofu_fingerprint();
                        let sys_msg = ChatMessage::new(
                            "SYSTEM",
                            &peer.username,
                            &format!("Key exchange initiated. Your TOFU Security Code is [{}]. Please wait a moment and press Enter again to resend.", tofu_code),
                        );
                        let mut history_lock = state.chat_history.lock().await;
                        let list = history_lock
                            .entry(peer.username.clone())
                            .or_insert_with(Vec::new);
                        list.push(sys_msg);
                        if list.len() > 1000 { list.remove(0); }
                    }
                    }
                }
            }

            input::InputAction::None => {}
        }
    }

    Ok(())
}

// CHANGES:
// [CONN-1] Scanner and TriggerScan now use discovery::DISCOVERY_PORT and
//          PREFERRED_CHAT_PORT correctly (scanner is discovery-only so this is fine).
// [CONN-2] ToggleScanner and TriggerScan: Removed HOPCHAT_KEY from scanner broadcasts.
//          Scanner now sends ONLY discovery payloads. Key exchange is deferred to
//          /connect after a user selects a peer.
// [CONN-4] Created tofu_registry (TofuRegistry) on AppState and passed it into
//          listen_for_messages as a parameter.
// [CONN-7] DedupCache initialized as HashSet::new() instead of VecDeque::new().
// [UI-DESK-4] Character and Backspace arms: cursor_pos translated to byte offset
//             via char_indices().nth() before String::insert/remove.
// [UI-MOB-4] Cached last_quit_button_rect from draw closure. Click handler uses
//            cached value instead of recomputing from terminal.size().unwrap_or_default().
// [UI-MOB-5] Added quit_requested: Arc<AtomicBool> to AppState. Checked at loop top.
//            /quit command sets it, enabling reliable exit on mobile.
