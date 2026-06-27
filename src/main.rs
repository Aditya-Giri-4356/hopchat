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
use network::messaging::{AckRegistry, ChatHistory, DedupCache, PeerKeyRegistry};
use tui::{input, layout, renderer};
use network::peer_registry::{Peer, PeerRegistry};
use user::identity::LocalIdentity;

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, EventStream},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Default chat port (used as a preferred bind target).
/// If unavailable, a dynamic port is assigned automatically.
const PREFERRED_CHAT_PORT: u16 = 9878;

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
    /// Cursor position within the input buffer
    pub cursor_pos: usize,
    /// Shared UDP socket for ALL messaging (send + receive on same port)
    pub outbound_socket: Arc<UdpSocket>,
    /// The actual port we are listening on (may differ from PREFERRED_CHAT_PORT)
    pub chat_port: u16,
    /// Index of the currently selected peer in the friends list
    pub selected_peer: usize,
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

    // Sanitize: strip pipe characters (would corrupt discovery packets),
    // remove whitespace, and enforce a max length of 32 characters.
    let username: String = username
        .trim()
        .replace('|', "")
        .chars()
        .filter(|c| !c.is_whitespace())
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

    // Detect local IP address
    let local_ip = local_ip_address::local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string());

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
    let dedup_cache: DedupCache = Arc::new(Mutex::new(VecDeque::new()));
    let peer_keys: PeerKeyRegistry = Arc::new(Mutex::new(HashMap::new()));

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
    };

    // --- Step 3: Spawn background network tasks ---

    // UDP discovery: broadcast our presence (with the actual bound port)
    let bcast_username = username.clone();
    let bcast_ip = local_ip.clone();
    let bcast_port = chat_port;
    tokio::spawn(async move {
        if let Err(e) = discovery::broadcast_presence(bcast_username, bcast_ip, bcast_port).await {
            eprintln!("Discovery broadcast error: {}", e);
        }
    });

    // UDP discovery: listen for peers
    let listen_ip = local_ip.clone();
    let listen_username = username.clone();
    let listen_peers = peers.clone();
    tokio::spawn(async move {
        if let Err(e) = discovery::listen_for_peers(listen_ip, listen_username, listen_peers).await
        {
            eprintln!("Discovery listen error: {}", e);
        }
    });

    // UDP server: receive structured encrypted incoming messages and keys
    // Uses the SAME shared_socket for both receiving and sending responses.
    let listen_history = chat_history.clone();
    let listen_acks = ack_registry.clone();
    let listen_dedup = dedup_cache.clone();
    let listen_peer_keys = peer_keys.clone();
    let listen_keypair = local_keypair.clone();
    let listen_identity = local_identity.clone();
    let listen_username = username.clone();
    let listen_socket = shared_socket.clone();
    let listen_peers = peers.clone();
    tokio::spawn(async move {
        if let Err(e) = messaging::listen_for_messages(
            listen_socket, listen_username, listen_history, listen_acks, listen_dedup, listen_peer_keys, listen_keypair, listen_identity, listen_peers
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
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // --- Step 5: Main event loop ---
    let result = run_event_loop(&mut terminal, &mut state).await;

    // --- Step 6: Cleanup ---
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Error: {}", e);
    }

    Ok(())
}

/// The main event loop that handles UI rendering, input, and outgoing messages.
async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut AppState,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut event_stream = EventStream::new();
    
    loop {

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
            );
        })?;

        // --- Asynchronously poll for keyboard input (50ms timeout) ---
        let action = input::next_input_event(&mut event_stream, Duration::from_millis(50)).await;

        match action {
            input::InputAction::Quit => break,

            input::InputAction::Character(c) => {
                state.input_buffer.insert(state.cursor_pos, c);
                state.cursor_pos += 1;
            }

            input::InputAction::Backspace => {
                if state.cursor_pos > 0 {
                    state.cursor_pos -= 1;
                    state.input_buffer.remove(state.cursor_pos);
                }
            }

            input::InputAction::SelectUp => {
                if state.selected_peer > 0 {
                    state.selected_peer -= 1;
                }
            }

            input::InputAction::SelectDown => {
                if !peers_snapshot.is_empty()
                    && state.selected_peer < peers_snapshot.len() - 1
                {
                    state.selected_peer += 1;
                }
            }

            input::InputAction::Send => {
                if !state.input_buffer.is_empty() {
                    let cmd_input = state.input_buffer.clone();
                    
                    // 1. Intercept CLI Commands (e.g., /connect, /help)
                    if cli::commands::handle_command(state, &cmd_input).await {
                        state.input_buffer.clear();
                        state.cursor_pos = 0;
                        continue;
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
