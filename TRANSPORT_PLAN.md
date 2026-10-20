# HopChat Transport Plan

What HopChat needs to carry a message when the network it was built for isn't there.

This is a working document, not a spec. It'll change as hardware gets tested. Last
serious pass: October 2026, after finally sitting down and counting how many ways a
packet can actually leave a device.

---

## Why bother

Right now HopChat speaks UDP over whatever IP network it happens to be sitting on. In
practice that means a router, a phone hotspot, or a crossover cable. That covers maybe
80% of the situations this thing was written for, and it does it well.

The remaining 20% is the interesting part. A router with no internet but no open ports.
A building where WiFi is locked down to enterprise auth. A ferry. A field exercise. Two
phones in a basement with no infrastructure at all, and the message just needs to get
through anyway.

So the goal isn't "add Bluetooth". It's: **pick the best available way to move a
packet, and make the app not care which one won.** Bluetooth is one entry on a list
that's longer than most people expect.

---

## The one rule

One envelope. Many pipes.

Everything above the transport layer — encryption, sessions, trust, chat history —
treats a medium as a dumb pipe that moves opaque bytes. A medium is "supported" once it
can carry a frame and tell us how big that frame can be. That's it. Adding the next
medium later is a new file, not a rewrite.

Which brings up the one thing that constrains the whole design:

> **The narrowest pipe sets the envelope size.**

LoRa gives you 233 bytes per packet. BLE gives you 182 on an iPhone. Data-over-sound
gives you 8 to 16 bytes *per second*. If the header is 60 bytes, the sound transport
can't even carry a header. So the v3 envelope has to fit in roughly 40 bytes, with a
compact mode below that. Design for the worst pipe first and everything else is free.

That's also the honest reason the current wire format has to go. Right now a message is
`HOPCHAT_MSG|<hex>`, where the hex is a 24-byte nonce plus ciphertext. Hex doubles every
byte. On a 182-byte BLE frame you'd get about 35 bytes of actual text and no room for
anything else. It works fine on UDP, where 65 KB is a rounding error. It will not work
over a radio.

---

## Everything that can move a packet

Grouped by how much work it needs from us, not by how famous it is.

### A. Carries IP already — basically free

If a medium hands us an IP packet, it's an afternoon of glue code and HopChat's existing
UDP stack does the rest.

| Medium | Range | Throughput | Where it works | Take |
|---|---|---|---|---|
| Wi-Fi via a router or hotspot | 30–100 m | 1–100 Mbps | everything | Already have it |
| Self-hosted SoftAP (phone hotspot) | ~30 m | 10–50 Mbps | everything | Already have it |
| Wi-Fi Direct / P2P | ~100 m | 20–40 MB/s | Android, Linux | Build. iOS never implemented it |
| Wi-Fi Aware / NAN | ~150 m | high | Android 8+; iOS pending | Later. Android-only today |
| Ad-hoc / IBSS / 802.11s | 100 m per hop | Mbps | Linux only | Build. Real multi-hop WiFi, no AP |
| Apple P2P Wi-Fi (AWDL) | ~50 m | 100+ Mbps measured | iOS, macOS | Use, but via Network.framework |
| Ethernet, USB tethering, RNDIS | wired | Gbps | everything | Free. Same code path as row 1 |

Two notes worth writing down now, because they'll bite later.

**Don't use MultipeerConnectivity.** It's tempting — it does discovery and transfer and
it's one framework. But it has no backpressure, its throughput falls off a cliff past a
few hundred KB/s in practice, and Apple's own guidance is to move to `Network.framework`
with `includePeerToPeer = true`. Use that instead. It's more work up front and much less
work at month six.

**Cellular is not a transport.** It gets you a relay, not a peer, and it quietly breaks
the offline promise. If it ever shows up here it'll be as an optional gateway, clearly
labelled, off by default.

### B. Bluetooth — needs its own framing

| Medium | Range | Throughput | Where it works | Take |
|---|---|---|---|---|
| BLE GATT (write-no-response + notify) | 10–30 m | 20–80 KB/s | everything | **Phase 4.** The universal baseline |
| BLE L2CAP CoC | 10–30 m | 100s KB/s | everything | Phase 4.5. Fast path, kernel-side flow control |
| BLE advertising, never connecting | 10–30 m | ~28 B, zero in background | everything | Discovery hint only, never data |
| Classic RFCOMM / SPP | 10–30 m | 150–250 KB/s | Linux, Android — **not iOS** | Phase 7. Optional fast pipe |
| Bluetooth SIG Mesh | 10 m per hop | ~11 B payload | embedded | No |

Things people get wrong here, in order of how much time they cost:

- **iOS caps ATT MTU at 185**, so 182 bytes of payload. You can't change it. Android will
  happily negotiate 517 and then the iPhone drops you back down. Design for 182 and treat
  anything above it as a bonus.
- **Unicast GATT is a conga line.** Fire fifty write-without-responses at once and the
  phones will silently discard them. Two to four in flight, wait for the callback, 5 ms
  between fragments.
- **Advertising carries nothing useful.** In the background iOS moves your service UUIDs
  to a hashed overflow area and drops the local name entirely. Advertise the service UUID
  and put the real introduction in a GATT read.
- **Classic RFCOMM is not available on iOS.** It needs an MFi accessory with Apple's
  auth chip. Android and Linux only. Great as a bonus pipe, useless as a primary one.

SIG Mesh gets a hard no. It's designed for lightbulbs. Payloads are about eleven bytes
after the bearer layers, and you have to provision nodes before they'll talk. Wrong tool.

### C. Other radio

| Medium | Range | Throughput | Take |
|---|---|---|---|
| LoRa via a Meshtastic radio | **2–15 km** | ~1 kbps, 233 B payload | **Build. Highest value on this list** |
| Raw LoRa, RNode, Reticulum | km | 0.3–37 kbps | Interop target, second pass |
| Sub-GHz FSK (CC1101 class) | 100s of m | low | Skip. Meshtastic already owns this |
| AX.25 / APRS packet radio | 10s of km | 1200 baud | Skip. Needs an amateur licence |
| NFC | under 4 cm | ~100 kbps burst | **Build — as a pairing ceremony, not a chat pipe** |
| UWB (802.15.4z) | 10 m | — | No. Ranging only, no payload API |
| Zigbee / Thread / 802.15.4 | 30 m | 250 kbps | No. Needs a border router, no phone radio |

The LoRa row deserves a paragraph. A $25 Meshtastic board exposes a documented client API
over BLE and serial. We open a connection, hand it a frame, it puts that frame on a radio
that reaches two to fifteen kilometres without a licence, and somebody else's node hands
it back. That's roughly four hundred lines of code to take HopChat from a thirty-metre app
to a kilometre-range one. Nothing else on this list has that ratio. The 233-byte payload
is also exactly why the envelope has to be small, so it forces the right decision early.

NFC earns its slot for a different reason. The README already admits the TOFU
first-contact window: if you've never met a peer, nothing stops an impostor being the
first one to answer. A tap or a QR scan closes that window for a few hundred lines. It's
not a transport, it's a trust ceremony, but it belongs in this document because it's the
same class of problem.

### D. Optical and acoustic

| Medium | Range | Throughput | Take |
|---|---|---|---|
| Data over sound (ggwave, 15–19.5 kHz) | 1–5 m | **8–16 B/s** | Build. Air-gap and no-RF mode |
| QR to camera, fountain-coded | line of sight | 100s B/s to KB/s | Build. Bootstrapping and key exchange |
| Li-Fi (802.11bb) | 10 m | high | No consumer hardware exists |
| IrDA | 1 m | — | Dead for twenty years |

Sound is slow enough that it's funny, and then you realise what it's for: two devices
with every radio turned off, in a room, still exchanging a key. Sixteen bytes a second is
plenty for a session key. It also gives us a mode with literally no RF signature, which
for some of the people who'd use this app is the entire point.

### E. No radio at all

| Medium | Take |
|---|---|
| Signed packet file on a USB stick | Build. Nearly free, works across any gap |
| Human courier carrying a device between mesh islands | Falls out of the outbox design for free |

The second one isn't a technology, it's a consequence. Once messages queue for absent
peers, walking a laptop from one side of a valley to the other is a working delivery
mechanism. Worth saying out loud so nobody "optimises" it away.

---

## The interface

Small on purpose. If this grows, the abstraction is wrong.

```rust
pub trait Transport: Send + Sync {
    fn caps(&self) -> Caps;
    async fn up(&mut self, ctx: Ctx) -> Result<()>;
    fn inbound(&self) -> mpsc::Receiver<Frame>;
    async fn send(&self, route: &Route, frame: Frame) -> Result<()>;
    fn cost(&self) -> Cost;
}

pub struct Caps {
    pub max_pdu: usize,     // 182 BLE, 233 LoRa, 8 sound, 65507 UDP
    pub reliable: bool,     // stream-like, or fire and forget
    pub broadcast: bool,    // can it address "everyone nearby"
    pub ordered: bool,
    pub range_class: Range, // Near / Room / Block / Kilometre
}

pub enum Route {
    Udp(SocketAddr),
    Rfcomm { addr: BdAddr, channel: u8 },
    Ble { link: LinkId, addr: BleAddr },
    Lora { node: MeshtasticNodeId },
    Sound,
    Qr,
    File(PathBuf),
    Any(Identity),          // send on every live medium, dedupe on arrival
}
```

`Route::Any` is the whole trick. Hand it a peer identity, it goes out on whatever's live,
and duplicate arrivals are dropped by message ID. That's how a message survives you
walking out of BLE range halfway through sending it.

Note that `Peer` currently holds an IP and a port. That has to become an identity plus a
list of routes. BLE has no `SocketAddr`, and iPhones rotate MAC addresses, so the only
stable handle on a peer is the username and their Ed25519 key. This is a real refactor of
`peer_registry`, not a rename.

---

## Picking a medium

Highest available wins, then fall back.

```
LAN/UDP -> Wi-Fi Direct/Aware -> RFCOMM -> BLE CoC -> BLE GATT -> LoRa -> Sound/QR -> USB file
  fast          fast               fast      medium     slow        km        airgap      days
```

Two things override the ordering:

**Range override.** If the peer isn't on the LAN but is five kilometres away, LoRa jumps
the queue no matter how slow it is. Distance beats bandwidth when it's the only option.

**Silence override.** Deny-to-discover mode disables advertising and beacons and uses only
QR or sound. No RF signature at all, regardless of what's faster.

---

## Bridging

Every node is a potential gateway. A laptop that can see both WiFi and a BLE peer relays
between them. A phone sitting next to a Meshtastic radio puts LoRa traffic onto WiFi.

This costs almost nothing extra, because the mesh layer never knew what a medium was in
the first place. Same envelope, TTL decremented, dedupe by message ID, held in the outbox
if the next hop is asleep. Six pipes, one network.

---

## Phases

Ordered by dependency, not by excitement. Each one has a gate: if the gate doesn't pass,
the next phase doesn't start.

| Phase | Work | Gate |
|---|---|---|
| **P0** | Two Linux boxes, `bluer`, GATT server and client simultaneously. Also get a Meshtastic radio and poke its API | Real MTU and throughput numbers. **No protocol code before this** |
| **P1** | Split `hopchat-core` out of the binary | UDP byte-identical, still talks to a v2.3.0 node |
| **P2** | v3 binary envelope, fragmentation, reassembly, v2 compat shim | A clean hour under cargo-fuzz |
| **P3** | UDP behind the trait | iSH still works. This is the regression gate for everything after |
| **P4** | BLE GATT on Linux, dual role, per-link send queue with credits | Two laptops chat with WiFi physically off |
| **P5** | Mesh: TTL, dedupe, relay jitter, outbox, bitmap SACK | A to B to C, where A and C never see each other |
| **P6** | LoRa bridge, HopChat as a Meshtastic client | A message crosses 2 km on a $25 radio |
| **P7** | iOS and Android shells, both roles | Phone to laptop, no infrastructure at all |
| **P8** | Bandwidth tier: RFCOMM, Wi-Fi Direct, Aware, AWDL | 10 MB file between two phones, no router |
| **P9** | Air gap tier: sound and QR with fountain codes | Two air-gapped devices exchange a key and a message |
| **P10** | NFC tap-to-trust | The TOFU first-contact window is closed at pairing |
| **P11** | Hardening: per-link rate limits, radio DoS bounds, mesh fuzzing | 24-hour soak test |

A few honest notes on ordering.

**P2 is not optional and it's easy to postpone.** Build a `LoopbackTransport` with
`max_pdu = 20` and thirty percent packet loss. With that plus the fuzz harness you can
develop the entire multi-medium stack — fragmentation, mesh, outbox, fallback — on one
laptop with no radios attached. Chasing a seven-hop bug through real hardware takes a
week. In the harness it takes a minute. Write it first, thank yourself later.

**P7 is bigger than the rest of the list combined.** Mobile BLE lifecycle, background
execution limits, permissions dialogs, app review. The protocol work is the easy part.
Budget accordingly.

**P3 matters more than it looks.** iSH is the reason the i586 target exists and the reason
`once_cell` and `AtomicUsize` are in the codebase. BLE support cannot follow it there, so
P3 is the moment we prove the trait didn't quietly break the one platform that has to keep
working. Keep BLE behind a Cargo feature and leave it off for i586.

---

## What we're not doing

Written down so nobody proposes it again in six months and we all have to rediscover why.

- **Bluetooth SIG Mesh.** Eleven-byte payloads, mandatory provisioning, built for lighting.
- **UWB.** No application payload API. Ranging is not messaging.
- **Zigbee, Thread, 802.15.4.** Needs a border router, and no phone ships the radio.
- **Li-Fi.** No hardware to buy.
- **IrDA.** No.
- **AX.25 / APRS.** Amateur licence required. Fun, but not for a general-purpose app.
- **Cellular as a transport.** It's a relay. It breaks the offline claim. If it appears at
  all it's an optional gateway, off by default, clearly labelled.
- **MultipeerConnectivity.** See section A. Tempting, bad throughput, no backpressure,
  Apple points elsewhere.

---

## Open questions

- Does BlueZ let one adapter run a GATT server and a GATT client at the same time without
  falling over? P0 answers this and P4 depends on the answer.
- How does a BLE link behave when the user locks the phone? Probably fine on Android with
  a foreground service, probably not fine on iOS.
- Is the Meshtastic client API stable enough to build on, or should we talk to the radio
  directly over serial?
- What's the actual energy cost of keeping BLE scanning alive for hours? If it's
  unacceptable we need a duty cycle that doesn't miss peers.
- Wi-Fi Aware on iOS is now the interesting one, since the DMA ruling pushes Apple toward
  the open standard. If that lands, section A6 gets simpler and A4 gets much more useful.

---

## Reading list

Nothing here is novel. Most of the design decisions above are copied from people who
shipped first and documented what broke.

- bitchat whitepaper — fragmentation sizes, TTL defaults, the outbox model
- Meshtastic client API docs — the 233-byte payload and the BLE framing quirks
- `bluez/bluer` examples — GATT server, L2CAP sockets, LE advertisement
- Memfault's BLE throughput primer — where the real numbers come from
- ggwave — FSK over sound, and how little you can get away with
