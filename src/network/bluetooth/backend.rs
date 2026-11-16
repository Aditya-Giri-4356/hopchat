// =============================================================================
// HOPCHAT — Bluetooth backend (macOS CoreBluetooth / Linux BlueZ)
// =============================================================================
//
// Every node runs two roles at once:
//
//   Peripheral  — advertises the HopChat GATT service and accepts writes
//   Central     — scans for the same service and connects to peers
//
// Two peripherals would connect to each other twice, so the advertisement
// carries a short hash of the node's Ed25519 key and only the node with the
// lexicographically smaller hash initiates the outgoing connection.
//
// Data path:
//   central   -> writes to WRITE_CHARACTERISTIC   (write-without-response)
//   peripheral-> notifies NOTIFY_CHARACTERISTIC
//
// Both directions carry the same packet strings UDP uses. A 7-byte framing
// header splits packets that do not fit in one ATT payload.

use super::{
    advert_name, build_hello, fragment_packet, read_packet_timestamp, BleConfig, BleHandle,
    Reassembler,
};
use crate::chat::messages::ChatMessage;
use crate::network::messaging::PeerSession;
use crate::network::peer_registry::{mark_ble_connected, mark_ble_disconnected, upsert_peer};
use ble_peripheral_rust::gatt::characteristic::Characteristic;
use ble_peripheral_rust::gatt::peripheral_event::{
    PeripheralEvent, ReadRequestResponse, RequestResponse, WriteRequestResponse,
};
use ble_peripheral_rust::gatt::properties::{AttributePermission, CharacteristicProperty};
use ble_peripheral_rust::gatt::service::Service as GattService;
use ble_peripheral_rust::{Peripheral, PeripheralImpl};
use btleplug::api::{
    Central, Characteristic as BtCharacteristic, Manager as _, Peripheral as _, ScanFilter,
    WriteType,
};
use btleplug::platform::{Manager, Peripheral as BtPeripheral};
use futures::StreamExt;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

/// Per-frame pacing. Firing a hundred GATT writes at once makes phones drop
/// them silently; a few milliseconds between fragments keeps the queue sane.
const FRAGMENT_PACING: Duration = Duration::from_millis(6);
/// How often the link checks whether the peer is still there.
const LINK_WATCH_INTERVAL: Duration = Duration::from_secs(2);
/// Maximum age of a handshake before it is rejected as a replay.
const HELLO_MAX_AGE_SECS: u64 = 300;
/// Retry delay when the radio, permission or adapter is unavailable.
const BACKEND_RETRY: Duration = Duration::from_secs(5);

pub(super) async fn run(config: Arc<BleConfig>, handle: BleHandle) {
    let peripheral_config = config.clone();
    let peripheral_handle = handle.clone();
    let peripheral_task = tokio::spawn(async move {
        loop {
            match run_peripheral(peripheral_config.clone(), peripheral_handle.clone()).await {
                // Never recreate the peripheral after a successful setup:
                // CoreBluetooth keeps one central manager per process, and a
                // second wrapper would be bound to a channel nobody drains.
                Ok(()) => break,
                Err(reason) => {
                    peripheral_handle
                        .update(|s| {
                            s.advertising = false;
                            s.powered = false;
                            s.detail = format!("Bluetooth peripheral: {}", reason);
                        })
                        .await;
                    tokio::time::sleep(BACKEND_RETRY).await;
                }
            }
        }
    });

    let central_config = config;
    let central_handle = handle;
    let central_task = tokio::spawn(async move {
        loop {
            if let Err(reason) = run_central(central_config.clone(), central_handle.clone()).await {
                central_handle
                    .update(|s| {
                        s.scanning = false;
                        s.detail = format!("Bluetooth scan: {}", reason);
                    })
                    .await;
                tokio::time::sleep(BACKEND_RETRY).await;
            }
        }
    });

    let _ = tokio::join!(peripheral_task, central_task);
}

// =============================================================================
// Peripheral role: advertise, serve GATT, receive writes
// =============================================================================

struct LinkState {
    reassembler: Reassembler,
    username: Option<String>,
    /// Token from BleHandle::register_link, so a late teardown cannot close a
    /// newer link to the same peer.
    token: Option<usize>,
    hello_sent: bool,
    last_hello_sent: Instant,
}

impl Default for LinkState {
    fn default() -> Self {
        Self {
            reassembler: Reassembler::new(),
            username: None,
            token: None,
            hello_sent: false,
            last_hello_sent: Instant::now(),
        }
    }
}

async fn run_peripheral(config: Arc<BleConfig>, handle: BleHandle) -> Result<(), String> {
    // `--no-bluetooth` must not touch the radio at all (on macOS the first
    // CoreBluetooth call triggers a permission prompt). Wait until the user
    // turns it on with `/bluetooth on`.
    while !handle.is_enabled() {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let service_uuid = Uuid::parse_str(super::SERVICE_UUID).map_err(|e| e.to_string())?;
    let write_uuid =
        Uuid::parse_str(super::WRITE_CHARACTERISTIC_UUID).map_err(|e| e.to_string())?;
    let notify_uuid =
        Uuid::parse_str(super::NOTIFY_CHARACTERISTIC_UUID).map_err(|e| e.to_string())?;

    let (event_tx, mut event_rx) = mpsc::channel::<PeripheralEvent>(128);
    let mut peripheral = Peripheral::new(event_tx)
        .await
        .map_err(|e| format!("cannot start GATT server: {}", e))?;

    // The adapter can take a moment to report powered-on after launch, and a
    // user may switch Bluetooth off at any time. Wait for it in place instead
    // of returning: reconstruction after this point is unsafe on macOS.
    while !peripheral.is_powered().await.unwrap_or(false) {
        handle
            .update(|s| {
                s.powered = false;
                s.advertising = false;
                s.detail = "waiting for Bluetooth (turn it on and allow this terminal to use it)"
                    .to_string();
            })
            .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let service = GattService {
        uuid: service_uuid,
        primary: true,
        characteristics: vec![
            Characteristic {
                uuid: write_uuid,
                properties: vec![
                    CharacteristicProperty::Write,
                    CharacteristicProperty::WriteWithoutResponse,
                ],
                permissions: vec![AttributePermission::Writeable],
                value: None,
                descriptors: Vec::new(),
            },
            Characteristic {
                uuid: notify_uuid,
                properties: vec![CharacteristicProperty::Notify, CharacteristicProperty::Read],
                permissions: vec![AttributePermission::Readable],
                // Must stay None. CoreBluetooth throws an Objective-C
                // exception (uncatchable from Rust, aborting the process)
                // when a characteristic with a cached value is added to a
                // service. Notifications carry the value instead.
                value: None,
                descriptors: Vec::new(),
            },
        ],
    };
    if let Err(e) = peripheral.add_service(&service).await {
        // Advertising retries need a live peripheral, so keep the process
        // alive with an honest error instead of looping through a rebuild.
        handle
            .update(|s| {
                s.powered = true;
                s.advertising = false;
                s.detail = format!("Bluetooth service registration failed: {}", e);
            })
            .await;
        // Keep the handle alive. Dropping it closes the manager channel, and
        // ble-peripheral-rust then spins on that closed channel forever.
        std::future::pending::<()>().await;
        return Ok(());
    }

    let adv_name = advert_name(&config.identity.public_key_hex());
    let mut advertising = false;
    let mut adv_error: Option<String> = None;
    if handle.is_enabled() {
        match peripheral
            .start_advertising(&adv_name, &[service_uuid])
            .await
        {
            Ok(()) => advertising = true,
            Err(e) => adv_error = Some(format!("cannot advertise yet: {}", e)),
        }
    }

    handle
        .update(|s| {
            s.powered = true;
            s.advertising = advertising;
            s.detail = match adv_error {
                Some(ref e) => e.clone(),
                None if advertising => format!("advertising as {}", adv_name),
                None => "Bluetooth paused".to_string(),
            };
        })
        .await;

    // The writer owns the Peripheral. Advertising toggles are commands to it,
    // because CoreBluetooth/BlueZ both want the same object for notifications
    // and advertising changes.
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);
    let (control_tx, mut control_rx) = mpsc::channel::<bool>(8);
    let writer_adv_name = adv_name.clone();
    let writer_service_uuid = service_uuid;
    let writer_handle = handle.clone();
    let writer = tokio::spawn(async move {
        // A fresh packet always starts at sequence zero, so the receiver drops
        // any stale partial with a colliding id before accepting the new one.
        let mut message_id: u16 = rand::random();
        loop {
            tokio::select! {
                maybe_packet = out_rx.recv() => {
                    let Some(packet) = maybe_packet else { break };
                    for frame in fragment_packet(&packet, message_id) {
                        if peripheral.update_characteristic(notify_uuid, frame).await.is_err() {
                            // Nobody subscribed yet, or the link vanished. The
                            // next fragment/packet will simply be dropped too.
                            break;
                        }
                        tokio::time::sleep(FRAGMENT_PACING).await;
                    }
                    message_id = message_id.wrapping_add(1);
                }
                control = control_rx.recv() => {
                    match control {
                        Some(true) => {
                            let started = peripheral
                                .start_advertising(&writer_adv_name, &[writer_service_uuid])
                                .await
                                .is_ok();
                            writer_handle
                                .update(|s| {
                                    s.advertising = started;
                                    s.detail = if started {
                                        format!("advertising as {}", writer_adv_name)
                                    } else {
                                        "Bluetooth advertising unavailable".to_string()
                                    };
                                })
                                .await;
                        }
                        Some(false) => {
                            let _ = peripheral.stop_advertising().await;
                            writer_handle
                                .update(|s| {
                                    s.advertising = false;
                                    s.detail = "Bluetooth paused".to_string();
                                })
                                .await;
                        }
                        None => break,
                    }
                }
            }
        }
    });

    let mut links: HashMap<String, LinkState> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let mut last_heartbeat = Instant::now();
    let mut next_adv_attempt = Instant::now();

    loop {
        tokio::select! {
            event = event_rx.recv() => {
                let Some(event) = event else { break };
                match event {
                    PeripheralEvent::ReadRequest { request, responder, .. } => {
                        // The library's CoreBluetooth delegate blocks its
                        // dispatch queue until this is answered, so an
                        // unanswered read would wedge the whole peripheral.
                        let response = if request.characteristic == notify_uuid {
                            RequestResponse::Success
                        } else {
                            RequestResponse::InvalidHandle
                        };
                        let _ = responder.send(ReadRequestResponse {
                            response,
                            value: Vec::new(),
                        });
                    }
                    PeripheralEvent::WriteRequest { request, value, responder, .. } => {
                        // Always acknowledge the ATT request, even if we drop
                        // the frame: leaving it unanswered stalls the central.
                        let _ = responder.send(WriteRequestResponse { response: RequestResponse::Success });

                        if !handle.is_enabled() || request.characteristic != write_uuid {
                            continue;
                        }

                        let link = links.entry(request.client).or_default();
                        if let Some(packet) = link.reassembler.push(&value) {
                            if let Ok(text) = String::from_utf8(packet) {
                                handle_packet(&text, link, &config, &handle, &out_tx, None).await;
                            }
                        }
                    }
                    PeripheralEvent::CharacteristicSubscriptionUpdate { request, subscribed } => {
                        if subscribed && request.characteristic == notify_uuid && handle.is_enabled() {
                            // Send our introduction as soon as somebody
                            // subscribes, so a central that connects and waits
                            // does not time out.
                            let link = links.entry(request.client).or_default();
                            if !link.hello_sent
                                && out_tx.send(build_hello(&config).into_bytes()).await.is_ok()
                            {
                                link.hello_sent = true;
                            }
                        } else if !subscribed && request.characteristic == notify_uuid {
                            // Client went away: drop its link state and clean up
                            // the outbound queue / peer registry entry.
                            if let Some(link) = links.remove(&request.client) {
                                teardown(&config, &handle, link.username.as_deref(), link.token).await;
                            }
                        }
                    }
                    PeripheralEvent::StateUpdate { is_powered } => {
                        handle.update(|s| { s.powered = is_powered; }).await;
                    }
                }
            }
            _ = tick.tick() => {
                let wanted = handle.is_enabled();
                let current = handle.status().await.advertising;
                if wanted != current && Instant::now() >= next_adv_attempt {
                    let _ = control_tx.send(wanted).await;
                    // Give the radio a moment before retrying a failed start;
                    // stop requests always go out immediately.
                    if wanted {
                        next_adv_attempt = Instant::now() + Duration::from_secs(5);
                    }
                    handle
                        .update(|s| {
                            s.detail = if wanted {
                                "starting Bluetooth advertising".to_string()
                            } else {
                                "Bluetooth paused".to_string()
                            };
                        })
                        .await;
                }

                // Keep authenticated peers fresh in the registry even when
                // nobody is typing: chat is event-driven, so without this an
                // idle link would look offline after the UDP timeout.
                if handle.is_enabled()
                    && last_heartbeat.elapsed() >= Duration::from_secs(20)
                    && links.values().any(|l| l.username.is_some())
                    && out_tx
                        .try_send(build_hello(&config).into_bytes())
                        .is_ok()
                {
                    last_heartbeat = Instant::now();
                }
            }
        }
    }

    // Tear down every link this peripheral owned.
    let stale: Vec<(String, usize)> = links
        .values()
        .filter_map(|l| match (&l.username, l.token) {
            (Some(username), Some(token)) => Some((username.clone(), token)),
            _ => None,
        })
        .collect();
    for (username, token) in stale {
        teardown(&config, &handle, Some(&username), Some(token)).await;
    }
    drop(out_tx);
    writer.abort();
    let _ = writer.await;
    handle
        .update(|s| {
            s.advertising = false;
            s.powered = false;
        })
        .await;

    Ok(())
}

// =============================================================================
// Central role: scan, connect, subscribe
// =============================================================================

async fn run_central(config: Arc<BleConfig>, handle: BleHandle) -> Result<(), String> {
    while !handle.is_enabled() {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let service_uuid = Uuid::parse_str(super::SERVICE_UUID).map_err(|e| e.to_string())?;
    let manager = Manager::new()
        .await
        .map_err(|e| format!("cannot open Bluetooth: {}", e))?;

    // Once the manager exists, keep it. btleplug runs one CoreBluetooth
    // thread per manager, so rebuilding on a transient adapter/scan error
    // would leak threads instead of recovering.
    let adapter = loop {
        match manager.adapters().await {
            Ok(adapters) => {
                if let Some(adapter) = adapters.into_iter().next() {
                    break adapter;
                }
                handle
                    .set_detail("no Bluetooth adapter found; waiting")
                    .await;
            }
            Err(e) => {
                handle
                    .set_detail(format!("cannot list Bluetooth adapters: {}", e))
                    .await;
            }
        }
        tokio::time::sleep(BACKEND_RETRY).await;
    };

    let our_name = advert_name(&config.identity.public_key_hex());
    let pending: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let mut scanning = false;

    handle
        .update(|s| {
            s.powered = true;
            s.detail = "Bluetooth ready".to_string();
        })
        .await;

    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;

        if !handle.is_enabled() {
            if scanning {
                let _ = adapter.stop_scan().await;
                scanning = false;
                handle.update(|s| s.scanning = false).await;
            }
            continue;
        }

        if !scanning {
            match adapter
                .start_scan(ScanFilter {
                    services: vec![service_uuid],
                })
                .await
            {
                Ok(()) => {
                    scanning = true;
                    handle.update(|s| s.scanning = true).await;
                }
                Err(e) => {
                    // Bluetooth may still be powering on. Retry from the top
                    // of the loop instead of tearing down the manager.
                    handle
                        .set_detail(format!("Bluetooth scan unavailable: {}", e))
                        .await;
                    continue;
                }
            }
        }

        let peripherals = match adapter.peripherals().await {
            Ok(list) => list,
            Err(e) => {
                handle
                    .set_detail(format!("Bluetooth scan error: {}", e))
                    .await;
                continue;
            }
        };

        for peripheral in peripherals {
            let id = format!("{:?}", peripheral.id());
            {
                let guard = pending.lock().await;
                if guard.contains(&id) {
                    continue;
                }
            }
            if peripheral.is_connected().await.unwrap_or(false) {
                continue;
            }

            let properties = match peripheral.properties().await {
                Ok(Some(props)) => props,
                _ => continue,
            };
            let peer_advert = match properties.local_name {
                Some(name) => name,
                None => continue,
            };

            // Only HopChat nodes, and only one side opens the connection.
            if !is_hopchat_advert(&peer_advert) {
                continue;
            }
            if peer_advert.as_str() >= our_name.as_str() {
                continue;
            }

            pending.lock().await.insert(id.clone());
            let link_config = config.clone();
            let link_handle = handle.clone();
            let link_pending = pending.clone();
            tokio::spawn(async move {
                let result =
                    run_central_link(peripheral, peer_advert, link_config, link_handle).await;
                link_pending.lock().await.remove(&id);
                if let Err(reason) = result {
                    // Not fatal: the other side may have gone away mid-setup.
                    let _ = reason;
                }
            });
        }
    }
}

fn is_hopchat_advert(name: &str) -> bool {
    name.len() == super::ADVERT_NAME_PREFIX.len() + 8
        && name.starts_with(super::ADVERT_NAME_PREFIX)
        && name[super::ADVERT_NAME_PREFIX.len()..]
            .chars()
            .all(|c| c.is_ascii_hexdigit())
}

async fn run_central_link(
    peripheral: BtPeripheral,
    peer_advert: String,
    config: Arc<BleConfig>,
    handle: BleHandle,
) -> Result<(), String> {
    let notify_uuid =
        Uuid::parse_str(super::NOTIFY_CHARACTERISTIC_UUID).map_err(|e| e.to_string())?;
    let write_uuid =
        Uuid::parse_str(super::WRITE_CHARACTERISTIC_UUID).map_err(|e| e.to_string())?;

    tokio::time::timeout(Duration::from_secs(15), peripheral.connect())
        .await
        .map_err(|_| "connection timed out".to_string())?
        .map_err(|e| format!("connect failed: {}", e))?;

    tokio::time::timeout(Duration::from_secs(10), peripheral.discover_services())
        .await
        .map_err(|_| "service discovery timed out".to_string())?
        .map_err(|e| format!("service discovery failed: {}", e))?;

    let characteristics = peripheral.characteristics();
    let write_char = find_characteristic(&characteristics, write_uuid)
        .ok_or_else(|| "peer has no HopChat write characteristic".to_string())?;
    let notify_char = find_characteristic(&characteristics, notify_uuid)
        .ok_or_else(|| "peer has no HopChat notify characteristic".to_string())?;

    peripheral
        .subscribe(&notify_char)
        .await
        .map_err(|e| format!("cannot subscribe: {}", e))?;

    let mut notifications = peripheral
        .notifications()
        .await
        .map_err(|e| format!("cannot read notifications: {}", e))?;

    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);
    let writer_peripheral = peripheral.clone();
    let writer_handle = handle.clone();
    let writer = tokio::spawn(async move {
        // A fresh packet always starts at sequence zero, so the receiver drops
        // any stale partial with a colliding id before accepting the new one.
        let mut message_id: u16 = rand::random();
        while let Some(packet) = out_rx.recv().await {
            if !writer_handle.is_enabled() {
                continue;
            }
            let mut failed = false;
            for frame in fragment_packet(&packet, message_id) {
                // Without-response is much faster; fall back to a confirmed
                // write if the peer only offers the plain Write property.
                let result = writer_peripheral
                    .write(&write_char, &frame, WriteType::WithoutResponse)
                    .await;
                let result = match result {
                    Err(_) => {
                        writer_peripheral
                            .write(&write_char, &frame, WriteType::WithResponse)
                            .await
                    }
                    ok => ok,
                };
                if result.is_err() {
                    failed = true;
                    break;
                }
                tokio::time::sleep(FRAGMENT_PACING).await;
            }
            message_id = message_id.wrapping_add(1);
            if failed {
                break;
            }
        }
        let _ = writer_peripheral.disconnect().await;
    });

    // Introduce ourselves immediately; the peripheral sends its own hello on
    // subscription, so both sides have everything they need to derive the key.
    if out_tx
        .send(build_hello(&config).into_bytes())
        .await
        .is_err()
    {
        let _ = peripheral.disconnect().await;
        writer.abort();
        return Ok(());
    }

    let mut link = LinkState {
        reassembler: Reassembler::new(),
        username: None,
        token: None,
        hello_sent: true,
        last_hello_sent: Instant::now(),
    };
    let mut watch = tokio::time::interval(LINK_WATCH_INTERVAL);

    loop {
        tokio::select! {
            notification = notifications.next() => {
                match notification {
                    Some(value) if value.uuid == notify_uuid => {
                        if let Some(packet) = link.reassembler.push(&value.value) {
                            if let Ok(text) = String::from_utf8(packet) {
                                handle_packet(
                                    &text,
                                    &mut link,
                                    &config,
                                    &handle,
                                    &out_tx,
                                    Some(&peer_advert),
                                )
                                .await;
                            }
                        }
                    }
                    Some(_) => {}
                    None => break,
                }
            }
            _ = watch.tick() => {
                if !peripheral.is_connected().await.unwrap_or(false) {
                    break;
                }
            }
        }

        // Retry the hello every 3 seconds until the peer answers, then use it
        // as a heartbeat so an idle link does not age out of the registry.
        let retry_after = if link.username.is_some() {
            Duration::from_secs(20)
        } else {
            Duration::from_secs(3)
        };
        if link.last_hello_sent.elapsed() >= retry_after
            && out_tx.try_send(build_hello(&config).into_bytes()).is_ok()
        {
            link.last_hello_sent = Instant::now();
        }
    }

    if let Some(username) = link.username.clone() {
        teardown(&config, &handle, Some(&username), link.token).await;
    }
    let _ = peripheral.disconnect().await;
    drop(out_tx);
    writer.abort();
    let _ = writer.await;
    Ok(())
}

fn find_characteristic(
    characteristics: &std::collections::BTreeSet<BtCharacteristic>,
    uuid: Uuid,
) -> Option<BtCharacteristic> {
    characteristics.iter().find(|c| c.uuid == uuid).cloned()
}

// =============================================================================
// Shared link packet handling
// =============================================================================

async fn handle_packet(
    packet: &str,
    link: &mut LinkState,
    config: &BleConfig,
    handle: &BleHandle,
    reply: &mpsc::Sender<Vec<u8>>,
    expected_advert: Option<&str>,
) {
    if packet.starts_with("HOPCHAT_BLE|") {
        if let Some(peer) = link.username.clone() {
            // Heartbeat (or a duplicate hello) on an already-authenticated
            // link: refresh liveness, nothing else to negotiate.
            let mut peers = config.peers.lock().await;
            mark_ble_connected(&mut peers, &peer);
            return;
        }
        match accept_hello(packet, config, expected_advert).await {
            Ok(username) => {
                link.username = Some(username.clone());
                link.token = Some(handle.register_link(&username, reply.clone()).await);

                if !link.hello_sent && reply.send(build_hello(config).into_bytes()).await.is_ok() {
                    link.hello_sent = true;
                }

                notify_system(config, &username, "Bluetooth link established (encrypted).").await;
            }
            Err(reason) => {
                handle
                    .set_detail(format!("Bluetooth handshake rejected: {}", reason))
                    .await;
            }
        }
    } else if let Some(ack_id) = packet.strip_prefix("HOPCHAT_BLE_ACK|") {
        // Delivery acknowledgement for a message we queued on this link.
        if let (Some(peer), Ok(id)) = (link.username.as_deref(), ack_id.parse::<u64>()) {
            handle.acknowledge(peer, id);
        }
    } else if packet.starts_with("HOPCHAT_MSG|") {
        if let Some(peer) = link.username.clone() {
            accept_chat(packet, &peer, config, handle, reply).await;
        }
    }
}

/// Validates a peer's BLE introduction and wires the session into the same
/// registries UDP uses.
async fn accept_hello(
    packet: &str,
    config: &BleConfig,
    expected_advert: Option<&str>,
) -> Result<String, String> {
    let parts: Vec<&str> = packet.split('|').collect();
    if parts.len() != 8 || parts[0] != "HOPCHAT_BLE" {
        return Err("malformed handshake".to_string());
    }

    let username = crate::network::discovery::sanitize_network_username(parts[1])
        .ok_or_else(|| "invalid username".to_string())?;
    if username == config.username {
        return Err("handshake from ourselves".to_string());
    }

    let x25519_hex = parts[2];
    let ed25519_hex = parts[3];
    let signature = parts[4];
    let ip = parts[5];
    let port: u16 = parts[6]
        .parse()
        .map_err(|_| "invalid chat port".to_string())?;
    let packet_ip: IpAddr = ip.parse().map_err(|_| "invalid chat address".to_string())?;
    let timestamp: u64 = parts[7]
        .parse()
        .map_err(|_| "invalid handshake timestamp".to_string())?;

    if read_packet_timestamp().abs_diff(timestamp) > HELLO_MAX_AGE_SECS {
        return Err("stale handshake".to_string());
    }

    // The advertisement carried a hash of the identity key. If the signed key
    // does not match it, the peer is not who it claimed to be while scanning.
    if let Some(advert) = expected_advert {
        if advert != advert_name(ed25519_hex) {
            return Err("identity does not match advertisement".to_string());
        }
    }

    let signed = format!("{}|{}|{}|{}", x25519_hex, ip, port, timestamp);
    if !crate::user::identity::LocalIdentity::verify_signature(
        ed25519_hex,
        signed.as_bytes(),
        signature,
    ) {
        return Err(format!("bad signature from {}", username));
    }

    {
        let mut db = config.trust_db.lock().await;
        if !db.verify_or_pin(&username, ed25519_hex) {
            return Err(format!(
                "identity key changed for {} (possible MITM)",
                username
            ));
        }
    }

    let derived = config
        .keypair
        .derive_session_key(x25519_hex)
        .map_err(|e| format!("key exchange failed: {}", e))?;

    {
        let mut keys = config.peer_keys.lock().await;
        let unchanged = keys.get(&username).is_some_and(|s| s.key == derived);
        if !unchanged {
            keys.insert(
                username.clone(),
                PeerSession {
                    key: derived,
                    replay: crate::network::messaging::ReplayWindow::new(),
                },
            );
        }
    }

    {
        let mut peers = config.peers.lock().await;
        let is_new = !peers.contains_key(&username);
        if is_new {
            upsert_peer(&mut peers, &username, &packet_ip.to_string(), port, true);
        } else if let Some(peer) = peers.get_mut(&username) {
            // A peer already reachable over UDP keeps its live LAN address;
            // the BLE handshake only fills in an address for peers we have
            // never seen on the network.
            if !peer.connected {
                peer.ip = packet_ip.to_string();
                peer.port = port;
            }
            peer.online = true;
            peer.last_seen = tokio::time::Instant::now();
        }
        mark_ble_connected(&mut peers, &username);
    }

    Ok(username)
}

/// Decrypts and stores a chat message arriving over an authenticated link.
async fn accept_chat(
    packet: &str,
    peer: &str,
    config: &BleConfig,
    handle: &BleHandle,
    reply: &mpsc::Sender<Vec<u8>>,
) {
    // Decrypt and update that same session's replay window under one lock, so
    // a key rotation cannot swap the window between the two steps.
    let (message, fresh) = {
        let mut keys = config.peer_keys.lock().await;
        let Some(session) = keys.get_mut(peer) else {
            return;
        };
        let Some(message) = ChatMessage::from_packet_string(packet, &session.key) else {
            return;
        };

        // Same checks as the UDP listener: the ciphertext must be addressed to
        // us and must not be a reflection of something we sent.
        if message.sender != peer
            || message.receiver != config.username
            || message.sender == config.username
        {
            return;
        }

        let fresh = session.replay.check_and_accept(message.id);
        (message, fresh)
    };

    let message_id = message.id;
    if fresh {
        {
            let mut history = config.history.lock().await;
            let list = history
                .entry(peer.to_string())
                .or_insert_with(std::collections::VecDeque::new);
            list.push_back(message);
            if list.len() > 1000 {
                list.pop_front();
            }
        }

        {
            let mut peers = config.peers.lock().await;
            mark_ble_connected(&mut peers, peer);
        }

        handle
            .update(|s| s.detail = format!("Bluetooth traffic with {}", peer))
            .await;
    }

    // Acknowledge after storage, so "delivered" means the message is safely
    // in the receiver's history. A retransmission is still acknowledged even
    // though it is correctly stored only once.
    let _ = reply.try_send(format!("HOPCHAT_BLE_ACK|{}", message_id).into_bytes());
}

async fn teardown(
    config: &BleConfig,
    handle: &BleHandle,
    username: Option<&str>,
    token: Option<usize>,
) {
    let (Some(username), Some(token)) = (username, token) else {
        return;
    };
    // A reconnect may already have replaced this link; only the link that
    // still owns the token may mark the peer disconnected.
    if !handle.unregister_link(username, token).await {
        return;
    }
    {
        let mut peers = config.peers.lock().await;
        mark_ble_disconnected(&mut peers, username);
    }
    notify_system(config, username, "Bluetooth link closed.").await;
}

async fn notify_system(config: &BleConfig, peer: &str, text: &str) {
    let mut history = config.history.lock().await;
    let list = history
        .entry(peer.to_string())
        .or_insert_with(std::collections::VecDeque::new);
    list.push_back(ChatMessage::new("SYSTEM", peer, text));
    if list.len() > 1000 {
        list.pop_front();
    }
}
