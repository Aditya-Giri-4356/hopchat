// =============================================================================
// HOPCHAT — Network Module: Wi-Fi / LAN transport status
// =============================================================================
//
// HopChat's original transport is UDP over whatever local IP network the
// device is attached to. This module makes that transport visible and
// controllable:
//
//   * lists every active IPv4 interface, so a laptop with Wi-Fi and Ethernet
//     (or a phone hotspot plus a VPN) can see what it will be discovered on
//   * derives the /24 subnet for each interface so discovery sweeps all of
//     them instead of only the default route
//   * reports whether LAN broadcasting is enabled
//
// There is no portable terminal API for Wi-Fi Direct / AWDL, so this module
// deliberately does not pretend to join IBSS networks. It manages the Wi-Fi
// path HopChat already has: UDP over the connected LAN.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

/// One IPv4 interface currently up on the device.
#[derive(Clone, Debug)]
pub struct InterfaceInfo {
    pub name: String,
    pub ip: String,
    /// True for 10/8, 172.16/12 and 192.168/16 addresses.
    pub private: bool,
}

/// Snapshot shown by the `/wifi` command and the status bar.
#[derive(Clone, Debug, Default)]
pub struct WifiStatus {
    pub enabled: bool,
    /// Primary address used in announcements.
    pub ip: String,
    pub interfaces: Vec<InterfaceInfo>,
    /// /24 prefixes discovery sweeps.
    pub subnets: Vec<String>,
}

impl WifiStatus {
    /// Short label for the TUI: `on` / `off`, plus the interface when known.
    pub fn summary(&self) -> &'static str {
        if !self.enabled {
            "off"
        } else if self.interfaces.is_empty() {
            "no link"
        } else {
            "on"
        }
    }

    /// The Wi-Fi interface when it can be identified by name. Ethernet-only
    /// hosts return None rather than mislabelling their uplink.
    pub fn wifi_interface(&self) -> Option<&InterfaceInfo> {
        self.interfaces
            .iter()
            .find(|iface| is_wifi_interface(&iface.name))
    }
}

/// Enumerates non-loopback IPv4 interfaces.
///
/// This is best-effort and must never panic: a device with no network is a
/// supported state, not an error.
pub fn interfaces() -> Vec<InterfaceInfo> {
    let mut found: Vec<InterfaceInfo> = local_ip_address::list_afinet_netifas()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(name, ip)| match ip {
            IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(InterfaceInfo {
                name,
                ip: v4.to_string(),
                private: v4.is_private(),
            }),
            _ => None,
        })
        .collect();
    found.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.ip.cmp(&b.ip)));
    found
}

/// /24 prefixes that discovery should sweep, without duplicates.
///
/// The sweep has always assumed a /24. That matches home routers, phone
/// hotspots and most field networks; on a wider network it still covers the
/// local /24, which is where peers are.
pub fn local_subnets() -> Vec<String> {
    let mut subnets: Vec<String> = Vec::new();
    for iface in interfaces() {
        if let Some(prefix) = subnet_prefix(&iface.ip) {
            if !subnets.contains(&prefix) {
                subnets.push(prefix);
            }
        }
        // A laptop with five VPN adapters should not fire five sweeps every
        // thirty seconds. Four distinct networks is already generous.
        if subnets.len() >= 4 {
            break;
        }
    }
    subnets
}

/// First three octets of an IPv4 address, or None.
pub fn subnet_prefix(ip: &str) -> Option<String> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
    } else {
        None
    }
}

pub fn status(primary_ip: &str, enabled: &AtomicBool) -> WifiStatus {
    let interfaces = interfaces();
    let subnets = local_subnets();
    WifiStatus {
        enabled: enabled.load(Ordering::Relaxed),
        ip: primary_ip.to_string(),
        interfaces,
        subnets,
    }
}

/// Interface names used by Wi-Fi on macOS (`en0`), Linux (`wlan0`, `wlp*`)
/// and Android/Termux (`wlan0`). Ethernet on macOS is also `en*`, so this is a
/// display hint only — never used for routing decisions.
fn is_wifi_interface(name: &str) -> bool {
    name.starts_with("wl")
        || name == "en0"
        || name == "en1"
        || name.starts_with("wlan")
        || name.starts_with("ath")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_prefix_rejects_non_ipv4() {
        assert_eq!(subnet_prefix("192.168.1.42"), Some("192.168.1".to_string()));
        assert_eq!(subnet_prefix("fe80::1"), None);
        assert_eq!(subnet_prefix("192.168.1"), None);
        assert_eq!(subnet_prefix("192.168.1.999"), None);
    }
}
