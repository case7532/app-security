/// ARP monitoring logic.
///
/// This module provides the core ARP table monitoring and spoof detection
/// algorithms. The actual pcap-based packet capture will be implemented
/// when the system integration layer is added.
///
/// Detection strategies:
/// 1. Periodic ARP table scanning for duplicate IP-to-MAC mappings
/// 2. pcap-based passive ARP reply monitoring for unsolicited replies
/// 3. Detection of MAC address changes for known gateway IPs

use std::collections::HashMap;

/// Represents a single ARP table entry.
#[derive(Debug, Clone, PartialEq)]
pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
    pub interface: String,
}

/// Tracks known ARP mappings and detects anomalies.
pub struct ArpMonitor {
    /// Known IP-to-MAC mappings (IP -> MAC).
    known_mappings: HashMap<String, String>,
    /// Detected anomalies.
    anomalies: Vec<ArpAnomaly>,
}

/// Represents a detected ARP anomaly.
#[derive(Debug, Clone)]
pub struct ArpAnomaly {
    pub ip: String,
    pub previous_mac: String,
    pub new_mac: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ArpMonitor {
    pub fn new() -> Self {
        Self {
            known_mappings: HashMap::new(),
            anomalies: Vec::new(),
        }
    }

    /// Record a known mapping (e.g., gateway IP to MAC).
    pub fn add_known_mapping(&mut self, ip: &str, mac: &str) {
        self.known_mappings
            .insert(ip.to_string(), mac.to_string());
    }

    /// Check an ARP entry against known mappings. Returns an anomaly if
    /// the MAC for a known IP has changed.
    pub fn check_entry(&mut self, entry: &ArpEntry) -> Option<ArpAnomaly> {
        if let Some(expected_mac) = self.known_mappings.get(&entry.ip) {
            if expected_mac != &entry.mac {
                let anomaly = ArpAnomaly {
                    ip: entry.ip.clone(),
                    previous_mac: expected_mac.clone(),
                    new_mac: entry.mac.clone(),
                    timestamp: chrono::Utc::now(),
                };
                self.anomalies.push(anomaly.clone());
                return Some(anomaly);
            }
        }
        None
    }

    /// Get all detected anomalies.
    pub fn anomalies(&self) -> &[ArpAnomaly] {
        &self.anomalies
    }

    /// Clear all state.
    pub fn reset(&mut self) {
        self.known_mappings.clear();
        self.anomalies.clear();
    }
}

impl Default for ArpMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_monitor_no_anomaly_for_unknown_ip() {
        let mut monitor = ArpMonitor::new();
        let entry = ArpEntry {
            ip: "192.168.1.100".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            interface: "eth0".to_string(),
        };
        assert!(monitor.check_entry(&entry).is_none());
    }

    #[test]
    fn test_arp_monitor_detects_mac_change() {
        let mut monitor = ArpMonitor::new();
        monitor.add_known_mapping("192.168.1.1", "11:22:33:44:55:66");

        let entry = ArpEntry {
            ip: "192.168.1.1".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            interface: "eth0".to_string(),
        };

        let anomaly = monitor.check_entry(&entry);
        assert!(anomaly.is_some());
        let a = anomaly.unwrap();
        assert_eq!(a.ip, "192.168.1.1");
        assert_eq!(a.previous_mac, "11:22:33:44:55:66");
        assert_eq!(a.new_mac, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_arp_monitor_no_anomaly_for_matching_mac() {
        let mut monitor = ArpMonitor::new();
        monitor.add_known_mapping("192.168.1.1", "11:22:33:44:55:66");

        let entry = ArpEntry {
            ip: "192.168.1.1".to_string(),
            mac: "11:22:33:44:55:66".to_string(),
            interface: "eth0".to_string(),
        };

        assert!(monitor.check_entry(&entry).is_none());
    }

    #[test]
    fn test_arp_monitor_tracks_anomalies() {
        let mut monitor = ArpMonitor::new();
        monitor.add_known_mapping("192.168.1.1", "11:22:33:44:55:66");

        let entry = ArpEntry {
            ip: "192.168.1.1".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            interface: "eth0".to_string(),
        };

        monitor.check_entry(&entry);
        assert_eq!(monitor.anomalies().len(), 1);
    }

    #[test]
    fn test_arp_monitor_reset() {
        let mut monitor = ArpMonitor::new();
        monitor.add_known_mapping("192.168.1.1", "11:22:33:44:55:66");

        let entry = ArpEntry {
            ip: "192.168.1.1".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            interface: "eth0".to_string(),
        };

        monitor.check_entry(&entry);
        assert_eq!(monitor.anomalies().len(), 1);

        monitor.reset();
        assert!(monitor.anomalies().is_empty());
        // After reset, the mapping is gone so the same entry shouldn't trigger
        let entry2 = ArpEntry {
            ip: "192.168.1.1".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            interface: "eth0".to_string(),
        };
        assert!(monitor.check_entry(&entry2).is_none());
    }
}
