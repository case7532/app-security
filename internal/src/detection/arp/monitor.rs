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

use serde::{Deserialize, Serialize};

/// Configuration for the ARP detection module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpConfig {
    /// Whether ARP detection is enabled.
    pub enabled: bool,
    /// Scan interval in seconds.
    pub scan_interval_secs: u64,
    /// Known gateway IP-to-MAC mappings to monitor.
    pub known_gateways: Vec<GatewayConfig>,
    /// Maximum number of anomalies to retain in memory.
    pub max_anomalies: usize,
    /// Whether to log all ARP table changes (not just anomalies).
    pub log_all_changes: bool,
}

/// Configuration for a known gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// IP address of the gateway.
    pub ip: String,
    /// Expected MAC address.
    pub mac: String,
    /// Optional description.
    pub description: Option<String>,
}

impl Default for ArpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval_secs: 5,
            known_gateways: Vec::new(),
            max_anomalies: 1000,
            log_all_changes: false,
        }
    }
}

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
    /// Maximum anomalies to retain.
    max_anomalies: usize,
}

/// Represents a detected ARP anomaly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpAnomaly {
    pub ip: String,
    pub previous_mac: String,
    pub new_mac: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Optional description of the anomaly.
    pub description: Option<String>,
}

impl ArpMonitor {
    pub fn new() -> Self {
        Self {
            known_mappings: HashMap::new(),
            anomalies: Vec::new(),
            max_anomalies: 1000,
        }
    }

    /// Create a new ArpMonitor with custom max anomalies.
    pub fn with_max_anomalies(max_anomalies: usize) -> Self {
        Self {
            known_mappings: HashMap::new(),
            anomalies: Vec::new(),
            max_anomalies,
        }
    }

    /// Create a monitor pre-loaded with gateway configurations.
    pub fn from_config(config: &ArpConfig) -> Self {
        let mut monitor = Self::with_max_anomalies(config.max_anomalies);
        for gw in &config.known_gateways {
            monitor.add_known_mapping(&gw.ip, &gw.mac);
        }
        monitor
    }

    /// Record a known mapping (e.g., gateway IP to MAC).
    pub fn add_known_mapping(&mut self, ip: &str, mac: &str) {
        self.known_mappings
            .insert(ip.to_string(), mac.to_string());
    }

    /// Remove a known mapping.
    pub fn remove_known_mapping(&mut self, ip: &str) -> Option<String> {
        self.known_mappings.remove(ip)
    }

    /// Check if a known mapping exists.
    pub fn has_known_mapping(&self, ip: &str) -> bool {
        self.known_mappings.contains_key(ip)
    }

    /// Get the expected MAC for an IP, if known.
    pub fn get_expected_mac(&self, ip: &str) -> Option<&str> {
        self.known_mappings.get(ip).map(|s| s.as_str())
    }

    /// Get the count of known mappings.
    pub fn known_mapping_count(&self) -> usize {
        self.known_mappings.len()
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
                    description: Some(format!(
                        "MAC changed from {} to {} on {}",
                        expected_mac, entry.mac, entry.interface
                    )),
                };
                self.anomalies.push(anomaly.clone());
                // Enforce max anomalies limit
                if self.anomalies.len() > self.max_anomalies {
                    self.anomalies.remove(0);
                }
                return Some(anomaly);
            }
        }
        None
    }

    /// Check a batch of ARP entries. Returns all anomalies found.
    pub fn check_entries(&mut self, entries: &[ArpEntry]) -> Vec<ArpAnomaly> {
        entries
            .iter()
            .filter_map(|entry| self.check_entry(entry))
            .collect()
    }

    /// Get all detected anomalies.
    pub fn anomalies(&self) -> &[ArpAnomaly] {
        &self.anomalies
    }

    /// Get the count of anomalies.
    pub fn anomaly_count(&self) -> usize {
        self.anomalies.len()
    }

    /// Clear all state.
    pub fn reset(&mut self) {
        self.known_mappings.clear();
        self.anomalies.clear();
    }

    /// Clear anomalies only, keep known mappings.
    pub fn clear_anomalies(&mut self) {
        self.anomalies.clear();
    }

    /// Get all known mappings as a slice of (ip, mac) pairs.
    pub fn known_mappings(&self) -> Vec<(&str, &str)> {
        self.known_mappings
            .iter()
            .map(|(ip, mac)| (ip.as_str(), mac.as_str()))
            .collect()
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
    fn test_arp_config_default() {
        let config = ArpConfig::default();
        assert!(config.enabled);
        assert_eq!(config.scan_interval_secs, 5);
        assert!(config.known_gateways.is_empty());
        assert_eq!(config.max_anomalies, 1000);
        assert!(!config.log_all_changes);
    }

    #[test]
    fn test_arp_config_serialization() {
        let config = ArpConfig {
            enabled: true,
            scan_interval_secs: 10,
            known_gateways: vec![GatewayConfig {
                ip: "192.168.1.1".to_string(),
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
                description: Some("Main gateway".to_string()),
            }],
            max_anomalies: 500,
            log_all_changes: true,
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ArpConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.enabled, deserialized.enabled);
        assert_eq!(config.scan_interval_secs, deserialized.scan_interval_secs);
        assert_eq!(config.known_gateways.len(), deserialized.known_gateways.len());
        assert_eq!(config.max_anomalies, deserialized.max_anomalies);
    }

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
        assert!(a.description.is_some());
        assert!(a.description.unwrap().contains("eth0"));
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
        assert_eq!(monitor.anomaly_count(), 1);
    }

    #[test]
    fn test_arp_monitor_max_anomalies() {
        let mut monitor = ArpMonitor::with_max_anomalies(3);
        monitor.add_known_mapping("192.168.1.1", "11:22:33:44:55:66");

        for i in 0..5 {
            let entry = ArpEntry {
                ip: "192.168.1.1".to_string(),
                mac: format!("aa:bb:cc:dd:ee:{:02x}", i),
                interface: "eth0".to_string(),
            };
            monitor.check_entry(&entry);
        }

        // Should cap at max_anomalies + 1 (one extra before trimming)
        assert!(monitor.anomaly_count() <= 4);
    }

    #[test]
    fn test_arp_monitor_from_config() {
        let config = ArpConfig {
            enabled: true,
            scan_interval_secs: 5,
            known_gateways: vec![
                GatewayConfig {
                    ip: "192.168.1.1".to_string(),
                    mac: "11:22:33:44:55:66".to_string(),
                    description: None,
                },
                GatewayConfig {
                    ip: "10.0.0.1".to_string(),
                    mac: "aa:bb:cc:dd:ee:ff".to_string(),
                    description: Some("Secondary".to_string()),
                },
            ],
            max_anomalies: 500,
            log_all_changes: false,
        };

        let monitor = ArpMonitor::from_config(&config);
        assert_eq!(monitor.known_mapping_count(), 2);
        assert_eq!(monitor.get_expected_mac("192.168.1.1"), Some("11:22:33:44:55:66"));
        assert_eq!(monitor.get_expected_mac("10.0.0.1"), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn test_arp_monitor_remove_mapping() {
        let mut monitor = ArpMonitor::new();
        monitor.add_known_mapping("192.168.1.1", "11:22:33:44:55:66");
        assert!(monitor.has_known_mapping("192.168.1.1"));

        monitor.remove_known_mapping("192.168.1.1");
        assert!(!monitor.has_known_mapping("192.168.1.1"));
    }

    #[test]
    fn test_arp_monitor_check_entries_batch() {
        let mut monitor = ArpMonitor::new();
        monitor.add_known_mapping("192.168.1.1", "11:22:33:44:55:66");
        monitor.add_known_mapping("192.168.1.2", "aa:bb:cc:dd:ee:ff");

        let entries = vec![
            ArpEntry {
                ip: "192.168.1.1".to_string(),
                mac: "aa:bb:cc:dd:ee:01".to_string(), // anomaly
                interface: "eth0".to_string(),
            },
            ArpEntry {
                ip: "192.168.1.2".to_string(),
                mac: "aa:bb:cc:dd:ee:ff".to_string(), // ok
                interface: "eth0".to_string(),
            },
            ArpEntry {
                ip: "192.168.1.3".to_string(),
                mac: "ff:ff:ff:ff:ff:ff".to_string(), // unknown, no anomaly
                interface: "eth0".to_string(),
            },
        ];

        let anomalies = monitor.check_entries(&entries);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].ip, "192.168.1.1");
    }

    #[test]
    fn test_arp_monitor_clear_anomalies() {
        let mut monitor = ArpMonitor::new();
        monitor.add_known_mapping("192.168.1.1", "11:22:33:44:55:66");

        let entry = ArpEntry {
            ip: "192.168.1.1".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            interface: "eth0".to_string(),
        };
        monitor.check_entry(&entry);
        assert_eq!(monitor.anomaly_count(), 1);

        monitor.clear_anomalies();
        assert_eq!(monitor.anomaly_count(), 0);
        // Mapping should still exist
        assert!(monitor.has_known_mapping("192.168.1.1"));
    }

    #[test]
    fn test_arp_monitor_known_mappings() {
        let mut monitor = ArpMonitor::new();
        monitor.add_known_mapping("192.168.1.1", "11:22:33:44:55:66");
        monitor.add_known_mapping("10.0.0.1", "aa:bb:cc:dd:ee:ff");

        let mappings = monitor.known_mappings();
        assert_eq!(mappings.len(), 2);
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
        assert_eq!(monitor.anomaly_count(), 1);

        monitor.reset();
        assert!(monitor.anomalies().is_empty());
        assert_eq!(monitor.known_mapping_count(), 0);
        // After reset, the mapping is gone so the same entry shouldn't trigger
        let entry2 = ArpEntry {
            ip: "192.168.1.1".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            interface: "eth0".to_string(),
        };
        assert!(monitor.check_entry(&entry2).is_none());
    }

    #[test]
    fn test_arp_anomaly_serialization() {
        let anomaly = ArpAnomaly {
            ip: "192.168.1.1".to_string(),
            previous_mac: "11:22:33:44:55:66".to_string(),
            new_mac: "aa:bb:cc:dd:ee:ff".to_string(),
            timestamp: chrono::Utc::now(),
            description: Some("MAC changed".to_string()),
        };

        let json = serde_json::to_string(&anomaly).unwrap();
        let deserialized: ArpAnomaly = serde_json::from_str(&json).unwrap();

        assert_eq!(anomaly.ip, deserialized.ip);
        assert_eq!(anomaly.previous_mac, deserialized.previous_mac);
        assert_eq!(anomaly.new_mac, deserialized.new_mac);
        assert_eq!(anomaly.description, deserialized.description);
    }
}
