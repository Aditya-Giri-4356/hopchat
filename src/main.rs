// =============================================================================
// HOPCHAT v2.5.0 — Main Entry Point
// =============================================================================
//
// Orchestrates all subsystems:
//   1. CLI argument parsing + username login prompt
//   2. UDP discovery (broadcast + listen) with signed packets
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
use network::bluetooth::{self, BleConfig, BleHandle, SendOutcome};
use network::messaging::{AckRegistry, ChatHistory, PeerKeyRegistry, TrustRegistry};
use network::peer_registry::{Peer, PeerRegistry};
use network::{discovery, messaging, peer_registry, wifi};
use tui::{input, layout, renderer};
use user::identity::LocalIdentity;
use user::trust_db::TrustDb;

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, EventStream},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Default chat port (used as a preferred bind target).
/// If unavailable, a dynamic port is assigned automatically.
pub const PREFERRED_CHAT_PORT: u16 = 9878;

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
    /// Chat message history by peer username (VecDeque for O(1) pruning)
    pub chat_history: ChatHistory,
    /// Shared tracker for outbound messages awaiting ACKs
    ack_registry: AckRegistry,
    /// Persistent TOFU trust database (pinned peer identities)
    pub trust_db: TrustRegistry,
    /// Registry mapping peer usernames to their session (key + replay window)
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
    /// Shared quit flag — set by /quit command, checked at loop top
    pub quit_requested: Arc<AtomicBool>,
    /// Cached quit button rect from last draw for reliable click detection
    pub last_quit_button_rect: Option<ratatui::layout::Rect>,
    /// Bluetooth transport handle (reports "unavailable" on iSH)
    pub ble: BleHandle,
    /// Whether LAN/Wi-Fi announcements are enabled (`/wifi off` pauses them)
    pub lan_enabled: Arc<AtomicBool>,
    /// Guards against overlapping manual subnet scans (rapid Tab presses)
    pub scan_running: Arc<AtomicBool>,
}

/// Prompts the user for their username via stdin (before TUI starts).
/// Sanitizes input to prevent pipe-injection attacks on the discovery protocol.
fn prompt_username() -> String {
    print!("\n  ╔══════════════════════════════════╗\n");
    println!("  ║        HOPCHAT v2.5.0            ║");
    println!("  ╠══════════════════════════════════╣");
    println!("  ║  Enter your username:            ║");
    println!("  ╚══════════════════════════════════╝");
    print!("  >>> ");
    let _ = io::stdout().flush();

    let mut username = String::new();
    let _ = io::stdin().read_line(&mut username);

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
    // --- Step 1: Parse CLI arguments ---
    let config = cli::args::parse_args();

    // --- Step 2: Login ---
    // Remembered so the interactive pause is skipped when the username was
    // supplied with -u, which is what makes scripted and piped launches work.
    let interactive_prompt = config.username.is_none();
    let username = config.username.unwrap_or_else(prompt_username);

    // Detect local IP address robustly
    let local_ip = get_local_ip();
    let chat_port_target = config.port;

    println!(
        "\n  Starting HOPCHAT as '{}' on {}:{}",
        username, local_ip, chat_port_target
    );

    if interactive_prompt {
        println!("  Press any key to enter the chat...");
        let _ = io::stdin().read_line(&mut String::new());
    }

    // --- Step 3: Set up shared state ---
    let local_identity = Arc::new(LocalIdentity::load_or_create(&username));
    let local_keypair = Arc::new(X25519KeyPair::generate());
    let peers: PeerRegistry = Arc::new(Mutex::new(HashMap::new()));
    let chat_history: ChatHistory = Arc::new(Mutex::new(HashMap::new()));
    let ack_registry: AckRegistry = Arc::new(Mutex::new(HashMap::new()));
    let peer_keys: PeerKeyRegistry = Arc::new(Mutex::new(HashMap::new()));
    // Load persistent TOFU trust database from disk
    let trust_db: TrustRegistry = Arc::new(Mutex::new(TrustDb::load()));

    // Create a SINGLE shared socket for all messaging (send + receive).
    let shared_socket =
        match tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", chat_port_target)).await {
            Ok(s) => Arc::new(s),
            Err(_) => Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?),
        };
    let chat_port = shared_socket.local_addr()?.port();

    // --- Transport switches ---
    // Wi-Fi/LAN is the original UDP transport; Bluetooth is an additional
    // path for peers that are not on the same IP network. Both can be turned
    // off at startup and toggled at runtime with /wifi and /bluetooth.
    let lan_enabled = Arc::new(AtomicBool::new(config.lan));
    let ble = bluetooth::start(
        BleConfig {
            username: username.clone(),
            chat_port,
            identity: local_identity.clone(),
            keypair: local_keypair.clone(),
            peers: peers.clone(),
            peer_keys: peer_keys.clone(),
            history: chat_history.clone(),
            trust_db: trust_db.clone(),
        },
        Arc::new(AtomicBool::new(config.bluetooth)),
    )
    .await;

    let mut state = AppState {
        username: username.clone(),
        peers: peers.clone(),
        chat_history: chat_history.clone(),
        ack_registry: ack_registry.clone(),
        trust_db: trust_db.clone(),
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
        ble: ble.clone(),
        lan_enabled: lan_enabled.clone(),
        scan_running: Arc::new(AtomicBool::new(false)),
    };

    // Announce transport state in the global thread so a first-time user can
    // tell whether the radio came up before any peer appears.
    {
        let ble_status = ble.status().await;
        let wifi_status = wifi::status(&local_ip, &lan_enabled);
        let mut history = state.chat_history.lock().await;
        let global = history
            .entry("GLOBAL".to_string())
            .or_insert_with(VecDeque::new);
        global.push_back(ChatMessage::new(
            "SYSTEM",
            "GLOBAL",
            &format!(
                "Wi-Fi/LAN: {} ({}). Bluetooth: {} — {}.",
                wifi_status.summary(),
                wifi_status.ip,
                ble_status.summary(),
                ble_status.detail
            ),
        ));
        if global.len() > 1000 {
            global.pop_front();
        }
    }

    // --- Step 4: Spawn background network tasks ---

    // Shared context for every discovery path, so both listeners behave the
    // same way and either one can start a handshake.
    let discovery_ctx = Arc::new(messaging::DiscoveryCtx {
        socket: shared_socket.clone(),
        username: username.clone(),
        ip: local_ip.clone(),
        chat_port,
        identity: local_identity.clone(),
        keypair: local_keypair.clone(),
        peers: peers.clone(),
        peer_keys: peer_keys.clone(),
        trust_db: trust_db.clone(),
    });

    // UDP discovery: broadcast our signed presence
    {
        let u = username.clone();
        let id = local_identity.clone();
        let p = chat_port;
        let lan = lan_enabled.clone();
        tokio::spawn(async move {
            if let Err(e) = discovery::broadcast_presence(u, p, id, lan).await {
                eprintln!("[hopchat] broadcast_presence stopped: {}", e);
            }
        });
    }

    // UDP discovery: listen for peers (binds to port 9877)
    {
        let ctx = discovery_ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = discovery::listen_for_peers(ctx).await {
                eprintln!(
                    "[hopchat] listen_for_peers stopped: {} — chat port listener still active",
                    e
                );
            }
        });
    }

    // Liveness: re-announce to peers we already have a session with
    {
        let ctx = discovery_ctx.clone();
        tokio::spawn(async move {
            messaging::keepalive_task(ctx).await;
        });
    }

    // UDP server: receive encrypted messages, ACKs, key exchanges, and discovery echoes
    {
        let config = messaging::ListenerConfig {
            socket: shared_socket.clone(),
            our_username: username.clone(),
            history: chat_history.clone(),
            ack_registry: ack_registry.clone(),
            peer_keys: peer_keys.clone(),
            local_keypair: local_keypair.clone(),
            local_identity: local_identity.clone(),
            peer_registry: peers.clone(),
            trust_db: trust_db.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = messaging::listen_for_messages(config).await {
                eprintln!("[hopchat] Messaging listen error: {}", e);
            }
        });
    }

    // Peer registry cleanup: drop peers inactive for > 60s
    {
        let p = peers.clone();
        tokio::spawn(async move {
            peer_registry::cleanup_task(p).await;
        });
    }

    // --- Step 5: Set up the TUI ---
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // --- Step 6: Main event loop ---
    let result = run_event_loop(&mut terminal, &mut state).await;

    // --- Step 7: Cleanup ---
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Error: {}", e);
    }

    Ok(())
}

/// Spawns an async task that scans the local subnet by sending signed
/// discovery and key exchange packets to all 254 host IPs.
fn spawn_subnet_scan(state: &AppState) {
    // A held-down Tab key used to start one full sweep per key event, all
    // racing on separate sockets. One scan at a time is enough.
    if state.scan_running.swap(true, Ordering::Relaxed) {
        return;
    }

    // Every active interface, not just the default route. Falls back to the
    // address shown on screen when interface enumeration comes back empty.
    let mut prefixes = wifi::local_subnets();
    if prefixes.is_empty() {
        if let Some(prefix) = wifi::subnet_prefix(&state.scanner.local_ip) {
            prefixes.push(prefix);
        }
    }
    if prefixes.is_empty() {
        state.scan_running.store(false, Ordering::Relaxed);
        return;
    }
    let socket = state.outbound_socket.clone();
    let scan_running = state.scan_running.clone();

    // Signed discovery packet
    let discovery_payload = messaging::create_signed_discovery(
        &state.username,
        &state.scanner.local_ip,
        state.chat_port,
        &state.identity,
    );

    // Key exchange payload — signed over username + key, so it cannot be
    // replayed under a different name.
    let key_payload = messaging::build_key_packet(
        &state.username,
        &state.keypair.public_key_hex(),
        &state.identity,
    );

    let disc_port = discovery::DISCOVERY_PORT;

    // Sweep the default chat port as well as our own. A peer that stayed on
    // the default is invisible to a sweep that only targets a non-standard
    // port, and vice versa when we are the one on a non-standard port.
    let mut chat_ports = vec![crate::PREFERRED_CHAT_PORT];
    if state.chat_port != crate::PREFERRED_CHAT_PORT {
        chat_ports.push(state.chat_port);
    }

    tokio::spawn(async move {
        for prefix in prefixes {
            for host in 1..=254u8 {
                let target_ip = format!("{}.{}", prefix, host);
                let target_disc = format!("{}:{}", target_ip, disc_port);

                let _ = socket
                    .send_to(discovery_payload.as_bytes(), &target_disc)
                    .await;
                let _ = socket.send_to(key_payload.as_bytes(), &target_disc).await;

                for port in &chat_ports {
                    let target_chat = format!("{}:{}", target_ip, port);
                    let _ = socket
                        .send_to(discovery_payload.as_bytes(), &target_chat)
                        .await;
                    let _ = socket.send_to(key_payload.as_bytes(), &target_chat).await;
                }

                // Pace the burst so receivers can drain their socket buffers.
                if host % 8 == 0 {
                    tokio::time::sleep(Duration::from_millis(4)).await;
                }
            }
        }
        scan_running.store(false, Ordering::Relaxed);
    });
}

/// Returns the device's LAN IPv4 address.
///
/// The routing-table probe needs a default route, which an isolated hotspot or
/// an ad-hoc network does not have. When it fails, fall back to enumerating
/// interfaces and preferring a private address over a link-local one — a
/// 169.254/16 address means DHCP never completed, not that we have a LAN.
pub fn get_local_ip() -> String {
    use std::net::IpAddr;

    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        // connect() on UDP only selects a route and source address. Nothing is
        // transmitted, so this works with no internet access.
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                if let IpAddr::V4(v4) = addr.ip() {
                    if !v4.is_loopback() && !v4.is_unspecified() {
                        return v4.to_string();
                    }
                }
            }
        }
    }

    let candidates: Vec<std::net::Ipv4Addr> = local_ip_address::list_afinet_netifas()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(_, ip)| match ip {
            IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(v4),
            _ => None,
        })
        .collect();

    candidates
        .iter()
        .find(|v4| v4.is_private())
        .or_else(|| candidates.iter().find(|v4| !v4.is_link_local()))
        .map(|v4| v4.to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

/// The main event loop that handles UI rendering, input, and outgoing messages.
async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut AppState,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut event_stream = EventStream::new();
    // Re-check the local address periodically so the address shown on screen,
    // and the subnet we sweep, follow us onto a new network.
    let mut frames_until_ip_refresh: u32 = 0;

    loop {
        // Check the shared quit flag
        if state.quit_requested.load(Ordering::Relaxed) {
            break;
        }

        if frames_until_ip_refresh == 0 {
            state.scanner.local_ip = get_local_ip();
            frames_until_ip_refresh = 200; // roughly ten seconds at 50ms/frame
        }
        frames_until_ip_refresh -= 1;

        // --- Get current peer list snapshot ---
        // Sorted, because HashMap iteration order changes between frames and
        // the highlighted row would move on its own.
        let mut peers_snapshot: Vec<Peer> = {
            let peers_lock = state.peers.lock().await;
            peers_lock.values().cloned().collect()
        };
        peers_snapshot.sort_by(|a, b| a.username.cmp(&b.username));

        // Clamp selected_peer to valid range
        if !peers_snapshot.is_empty() && state.selected_peer >= peers_snapshot.len() {
            state.selected_peer = peers_snapshot.len() - 1;
        }

        // --- Get chat history snapshot for selected peer ---
        // With no peer selected, fall back to the GLOBAL thread. System output
        // such as /help and /peers is written there, and it used to be
        // unreachable because this returned an empty key.
        let selected_username = if !peers_snapshot.is_empty() {
            peers_snapshot[state.selected_peer].username.clone()
        } else {
            "GLOBAL".to_string()
        };

        // Convert VecDeque to Vec at the render boundary
        let active_messages: Vec<ChatMessage> = {
            let history_lock = state.chat_history.lock().await;
            history_lock
                .get(&selected_username)
                .map(|d| d.iter().cloned().collect())
                .unwrap_or_default()
        };

        // --- Render the UI ---
        let ble_status = state.ble.status().await;
        let lan_on = state.lan_enabled.load(Ordering::Relaxed);
        terminal.draw(|frame| {
            let app_layout = layout::compute_layout(frame.size());
            renderer::render_ui(
                frame,
                renderer::RenderArgs {
                    layout: &app_layout,
                    username: &state.username,
                    peers: &peers_snapshot,
                    local_ip: &state.scanner.local_ip,
                    selected_peer: state.selected_peer,
                    messages: &active_messages,
                    input: &state.input_buffer,
                    cursor_pos: state.cursor_pos,
                    scanner_visible: state.scanner.is_visible,
                    scanner_index: state.scanner.selected_index,
                    ble: &ble_status,
                    lan_enabled: lan_on,
                },
            );
            state.last_quit_button_rect = app_layout.quit_button;
        })?;

        // --- Asynchronously poll for keyboard input (50ms timeout) ---
        let action = input::next_input_event(&mut event_stream, Duration::from_millis(50)).await;

        match action {
            input::InputAction::Quit => break,

            input::InputAction::Escape => {
                if state.scanner.is_visible {
                    state.scanner.is_visible = false;
                } else {
                    break;
                }
            }

            input::InputAction::CursorLeft => {
                if !state.scanner.is_visible && state.cursor_pos > 0 {
                    state.cursor_pos -= 1;
                }
            }

            input::InputAction::CursorRight => {
                if !state.scanner.is_visible {
                    let len = state.input_buffer.chars().count();
                    if state.cursor_pos < len {
                        state.cursor_pos += 1;
                    }
                }
            }

            input::InputAction::CursorHome => {
                if !state.scanner.is_visible {
                    state.cursor_pos = 0;
                }
            }

            input::InputAction::CursorEnd => {
                if !state.scanner.is_visible {
                    state.cursor_pos = state.input_buffer.chars().count();
                }
            }

            input::InputAction::Delete => {
                if !state.scanner.is_visible {
                    let len = state.input_buffer.chars().count();
                    if state.cursor_pos < len {
                        let byte_pos = state
                            .input_buffer
                            .char_indices()
                            .nth(state.cursor_pos)
                            .map(|(i, _)| i)
                            .unwrap_or_else(|| state.input_buffer.len());
                        state.input_buffer.remove(byte_pos);
                    }
                }
            }

            input::InputAction::Click(x, y) => {
                if let Some(quit_rect) = state.last_quit_button_rect {
                    if x >= quit_rect.x
                        && x < quit_rect.x + quit_rect.width
                        && y >= quit_rect.y
                        && y < quit_rect.y + quit_rect.height
                    {
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
                    let byte_pos = state
                        .input_buffer
                        .char_indices()
                        .nth(state.cursor_pos)
                        .map(|(i, _)| i)
                        .unwrap_or_else(|| state.input_buffer.len());
                    state.input_buffer.insert(byte_pos, c);
                    state.cursor_pos += 1;
                }
            }

            input::InputAction::Backspace => {
                if !state.scanner.is_visible && state.cursor_pos > 0 {
                    state.cursor_pos -= 1;
                    let byte_pos = state
                        .input_buffer
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
                } else if state.selected_peer > 0 {
                    state.selected_peer -= 1;
                }
            }

            input::InputAction::SelectDown => {
                if state.scanner.is_visible {
                    if state.scanner.selected_index < peers_snapshot.len().saturating_sub(1) {
                        state.scanner.selected_index += 1;
                    }
                } else if !peers_snapshot.is_empty()
                    && state.selected_peer < peers_snapshot.len() - 1
                {
                    state.selected_peer += 1;
                }
            }

            input::InputAction::Send => {
                if state.scanner.is_visible {
                    if !peers_snapshot.is_empty()
                        && state.scanner.selected_index < peers_snapshot.len()
                    {
                        let picked = state.scanner.selected_index;
                        let target = &peers_snapshot[picked];
                        state.selected_peer = picked;

                        // A Bluetooth-linked peer is already reachable. There
                        // is no IP handshake to run, and its address may not
                        // even be an IP address.
                        if !target.connected
                            && !target.ble_connected
                            && target.socket_addr().is_ok()
                        {
                            // Carry the peer's port across. Formatting only the IP
                            // meant anyone on a non-default port was unreachable
                            // from the list that is supposed to exist to avoid
                            // typing addresses by hand.
                            let cmd_input = format!("/connect {} {}", target.ip, target.port);
                            cli::commands::handle_command(state, &cmd_input).await;
                        }
                    }
                    state.scanner.is_visible = false;
                    continue;
                }

                if !state.input_buffer.is_empty() {
                    let cmd_input = state.input_buffer.clone();

                    // 1. Intercept CLI Commands
                    match cli::commands::handle_command(state, &cmd_input).await {
                        cli::commands::CommandResult::Handled => {
                            state.input_buffer.clear();
                            state.cursor_pos = 0;
                            continue;
                        }
                        cli::commands::CommandResult::TriggerScan => {
                            state.input_buffer.clear();
                            state.cursor_pos = 0;
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

                        // Look up the session key
                        let session_key = {
                            let keys_lock = state.peer_keys.lock().await;
                            keys_lock.get(&peer.username).map(|s| s.key)
                        };

                        if let Some(session_key) = session_key {
                            let message = ChatMessage::new(
                                &state.username,
                                &peer.username,
                                &state.input_buffer,
                            );

                            // Add to our local chat history (VecDeque)
                            {
                                let mut history_lock = state.chat_history.lock().await;
                                let list = history_lock
                                    .entry(peer.username.clone())
                                    .or_insert_with(VecDeque::new);
                                list.push_back(message.clone());
                                if list.len() > 1000 {
                                    list.pop_front();
                                }
                            }

                            // Encrypt once: both transports carry the same
                            // packet, so a BLE fallback does not redo the work.
                            let packet = message.to_packet_string(&session_key);
                            let mut ble_ack = None;

                            // Prefer Bluetooth when an authenticated link exists:
                            // the peer may not share an IP network at all. If the
                            // BLE queue is unavailable, fall through to UDP.
                            let sent_over_ble = match packet.as_ref() {
                                Ok(packet) if peer.ble_connected => {
                                    let (outcome, ack) = state.ble.send_packet_awaiting_ack(
                                        &peer.username,
                                        packet,
                                        message.id,
                                    );
                                    if outcome == SendOutcome::Sent {
                                        ble_ack = ack;
                                        true
                                    } else {
                                        false
                                    }
                                }
                                _ => false,
                            };

                            if sent_over_ble {
                                // Queueing is not delivery: wait for the peer's
                                // BLE acknowledgement before claiming success.
                                if let Some(ack) = ble_ack {
                                    let history_handle = state.chat_history.clone();
                                    let peer_name = peer.username.clone();
                                    tokio::spawn(async move {
                                        let text = match tokio::time::timeout(
                                            Duration::from_secs(8),
                                            ack,
                                        )
                                        .await
                                        {
                                            Ok(Ok(())) => "Delivered over Bluetooth ✓".to_string(),
                                            _ => {
                                                "Not delivered over Bluetooth — no acknowledgement"
                                                    .to_string()
                                            }
                                        };

                                        let mut history_lock = history_handle.lock().await;
                                        let list = history_lock
                                            .entry(peer_name.clone())
                                            .or_insert_with(VecDeque::new);
                                        list.push_back(ChatMessage::new(
                                            "SYSTEM", &peer_name, &text,
                                        ));
                                        if list.len() > 1000 {
                                            list.pop_front();
                                        }
                                    });
                                }
                            } else if let Ok(addr) = peer.socket_addr() {
                                // Send to the peer asynchronously, reporting the
                                // real outcome. Claiming delivery up front was a lie
                                // whenever the retries timed out, and the failure
                                // only ever reached stderr, which the TUI hides.
                                let acks = state.ack_registry.clone();
                                let socket_clone = state.outbound_socket.clone();
                                let history_handle = state.chat_history.clone();
                                let peer_name = peer.username.clone();
                                let message_id = message.id;

                                match packet {
                                    Ok(packet) => {
                                        tokio::spawn(async move {
                                            let outcome = messaging::send_packet_with_retry(
                                                socket_clone,
                                                addr,
                                                &packet,
                                                message_id,
                                                acks,
                                            )
                                            .await;

                                            let text = match outcome {
                                                Ok(_) => "Delivered ✓".to_string(),
                                                Err(_) => format!(
                                                    "Not delivered — {} did not respond",
                                                    peer_name
                                                ),
                                            };

                                            let mut history_lock = history_handle.lock().await;
                                            let list = history_lock
                                                .entry(peer_name.clone())
                                                .or_insert_with(VecDeque::new);
                                            list.push_back(ChatMessage::new(
                                                "SYSTEM", &peer_name, &text,
                                            ));
                                            if list.len() > 1000 {
                                                list.pop_front();
                                            }
                                        });
                                    }
                                    Err(_) => {
                                        let mut history_lock = history_handle.lock().await;
                                        let list = history_lock
                                            .entry(peer_name.clone())
                                            .or_insert_with(VecDeque::new);
                                        list.push_back(ChatMessage::new(
                                            "SYSTEM",
                                            &peer_name,
                                            "Not sent — message encryption failed",
                                        ));
                                        if list.len() > 1000 {
                                            list.pop_front();
                                        }
                                    }
                                }
                            } else {
                                let mut history_lock = state.chat_history.lock().await;
                                let list = history_lock
                                    .entry(peer.username.clone())
                                    .or_insert_with(VecDeque::new);
                                list.push_back(ChatMessage::new(
                                    "SYSTEM",
                                    &peer.username,
                                    "Not sent — no reachable Wi-Fi address and no Bluetooth link",
                                ));
                                if list.len() > 1000 {
                                    list.pop_front();
                                }
                            }

                            state.input_buffer.clear();
                            state.cursor_pos = 0;
                        } else {
                            // No session key — initiate Key Exchange
                            if let Ok(addr) = peer.socket_addr() {
                                let handshake_packet = messaging::build_key_packet(
                                    &state.username,
                                    &state.keypair.public_key_hex(),
                                    &state.identity,
                                );

                                let socket_clone = state.outbound_socket.clone();
                                let history_handle = state.chat_history.clone();
                                let peer_name = peer.username.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = messaging::send_raw_packet(
                                        &socket_clone,
                                        addr,
                                        &handshake_packet,
                                    )
                                    .await
                                    {
                                        // Same reason as the delivery status above:
                                        // stderr is invisible once the TUI owns the
                                        // screen, so a failed handshake looked like
                                        // nothing happening at all.
                                        let mut history_lock = history_handle.lock().await;
                                        let list = history_lock
                                            .entry(peer_name.clone())
                                            .or_insert_with(VecDeque::new);
                                        list.push_back(ChatMessage::new(
                                            "SYSTEM",
                                            &peer_name,
                                            &format!(
                                                "Could not reach {} to start the key exchange: {}",
                                                peer_name, e
                                            ),
                                        ));
                                        if list.len() > 1000 {
                                            list.pop_front();
                                        }
                                    }
                                });
                            }

                            // System message showing TOFU fingerprint
                            let tofu_code = state.identity.tofu_fingerprint();
                            let sys_msg = ChatMessage::new(
                                "SYSTEM",
                                &peer.username,
                                &format!("Key exchange initiated. Your TOFU Security Code is [{}]. Please wait a moment and press Enter again to resend.", tofu_code),
                            );
                            let mut history_lock = state.chat_history.lock().await;
                            let list = history_lock
                                .entry(peer.username.clone())
                                .or_insert_with(VecDeque::new);
                            list.push_back(sys_msg);
                            if list.len() > 1000 {
                                list.pop_front();
                            }
                        }
                    }
                }
            }

            input::InputAction::None => {}
        }
    }

    Ok(())
}
