pub mod monitor;

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::core::event_bus::EventBus;
use crate::core::mod_trait::{ModuleConfig, ModuleEvent, ModuleStatus, SecurityModule};
use monitor::{ArpAnomaly, ArpConfig, ArpEntry, ArpMonitor};

pub struct ArpDetectorModule {
    event_bus: EventBus,
    status: ModuleStatus,
    /// Controls the ARP monitoring loop. Set to `true` in `start()`, `false` in `stop()`.
    running: Arc<AtomicBool>,
    /// The ARP spoof detection engine.
    arp_monitor: ArpMonitor,
    /// Module configuration.
    config: ArpConfig,
}

impl ArpDetectorModule {
    pub fn new(event_bus: EventBus) -> Self {
        Self {
            event_bus,
            status: ModuleStatus::Created,
            running: Arc::new(AtomicBool::new(false)),
            arp_monitor: ArpMonitor::new(),
            config: ArpConfig::default(),
        }
    }

    /// Create a new ArpDetectorModule with custom configuration.
    pub fn with_config(event_bus: EventBus, config: ArpConfig) -> Self {
        let arp_monitor = ArpMonitor::from_config(&config);
        Self {
            event_bus,
            status: ModuleStatus::Created,
            running: Arc::new(AtomicBool::new(false)),
            arp_monitor,
            config,
        }
    }

    /// Get the current configuration.
    pub fn config(&self) -> &ArpConfig {
        &self.config
    }

    /// Publish an ARP spoof event. Used by the monitoring loop and for testing.
    pub async fn publish_arp_spoof(&self, attacker_mac: &str, victim_ip: &str) {
        let _ = self.event_bus.publish(ModuleEvent::ArpSpoofDetected {
            attacker_mac: attacker_mac.to_string(),
            victim_ip: victim_ip.to_string(),
        });
    }

    /// Backward-compatible alias used by existing tests.
    pub async fn simulate_arp_spoof(&self, attacker_mac: &str, victim_ip: &str) {
        self.publish_arp_spoof(attacker_mac, victim_ip).await;
    }

    /// Add a known IP-to-MAC mapping to the detection engine.
    pub fn add_known_mapping(&mut self, ip: &str, mac: &str) {
        self.arp_monitor.add_known_mapping(ip, mac);
    }

    /// Remove a known IP-to-MAC mapping.
    pub fn remove_known_mapping(&mut self, ip: &str) -> Option<String> {
        self.arp_monitor.remove_known_mapping(ip)
    }

    /// Check if a known mapping exists.
    pub fn has_known_mapping(&self, ip: &str) -> bool {
        self.arp_monitor.has_known_mapping(ip)
    }

    /// Get the count of known mappings.
    pub fn known_mapping_count(&self) -> usize {
        self.arp_monitor.known_mapping_count()
    }

    /// Check an ARP entry against known mappings. Returns an anomaly if the MAC
    /// for a known IP has changed, and publishes an `ArpSpoofDetected` event.
    pub fn check_arp_entry(&mut self, entry: &ArpEntry) -> Option<ArpAnomaly> {
        let anomaly = self.arp_monitor.check_entry(entry);
        if let Some(ref a) = anomaly {
            let _ = self.event_bus.publish(ModuleEvent::ArpSpoofDetected {
                attacker_mac: a.new_mac.clone(),
                victim_ip: a.ip.clone(),
            });
        }
        anomaly
    }

    /// Check a batch of ARP entries.
    pub fn check_entries(&mut self, entries: &[ArpEntry]) -> Vec<ArpAnomaly> {
        let anomalies = self.arp_monitor.check_entries(entries);
        for a in &anomalies {
            let _ = self.event_bus.publish(ModuleEvent::ArpSpoofDetected {
                attacker_mac: a.new_mac.clone(),
                victim_ip: a.ip.clone(),
            });
        }
        anomalies
    }

    /// Get all detected anomalies from the underlying monitor.
    pub fn anomalies(&self) -> &[ArpAnomaly] {
        self.arp_monitor.anomalies()
    }

    /// Get the count of anomalies.
    pub fn anomaly_count(&self) -> usize {
        self.arp_monitor.anomaly_count()
    }

    /// Clear all anomalies.
    pub fn clear_anomalies(&mut self) {
        self.arp_monitor.clear_anomalies();
    }

    /// The ARP monitoring loop. Checks the `running` flag each iteration so
    /// that `stop()` can terminate it gracefully.
    async fn monitor_arp(running: Arc<AtomicBool>, event_bus: EventBus, scan_interval: u64) {
        while running.load(Ordering::Relaxed) {
            // Periodic ARP table scanning for anomalies.
            // The actual pcap-based packet capture or ARP table parsing will be
            // implemented when the system integration layer is added. For now,
            // this loop provides the correct control-flow skeleton with a
            // working shutdown mechanism.
            tokio::time::sleep(tokio::time::Duration::from_secs(scan_interval)).await;
        }
        // Graceful exit: the loop stopped because `running` was set to false.
        let _ = event_bus.publish(ModuleEvent::ModuleStopped {
            module_id: "arp_detector".to_string(),
        });
    }
}

#[async_trait]
impl SecurityModule for ArpDetectorModule {
    fn id(&self) -> &str {
        "arp_detector"
    }

    fn name(&self) -> &str {
        "ARP Spoof Detector"
    }

    fn priority(&self) -> u32 {
        3
    }

    fn dependencies(&self) -> Vec<&str> {
        vec![]
    }

    async fn initialize(
        &mut self,
        _config: &ModuleConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Initialized;
        Ok(())
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.running.store(true, Ordering::Relaxed);
        let running = Arc::clone(&self.running);
        let event_bus = self.event_bus.clone();
        let scan_interval = self.config.scan_interval_secs;
        // Spawn the monitoring loop as a background task so start() returns
        // immediately.
        tokio::spawn(Self::monitor_arp(running, event_bus, scan_interval));
        self.status = ModuleStatus::Running;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.running.store(false, Ordering::Relaxed);
        self.status = ModuleStatus::Stopped;
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    async fn on_event(&mut self, _event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[test]
    fn test_add_known_mapping_and_check() {
        let event_bus = EventBus::new(100);
        let mut detector = ArpDetectorModule::new(event_bus);

        detector.add_known_mapping("192.168.1.1", "11:22:33:44:55:66");

        // Matching MAC -- no anomaly
        let entry_ok = ArpEntry {
            ip: "192.168.1.1".to_string(),
            mac: "11:22:33:44:55:66".to_string(),
            interface: "eth0".to_string(),
        };
        assert!(detector.check_arp_entry(&entry_ok).is_none());

        // Different MAC -- anomaly detected
        let entry_bad = ArpEntry {
            ip: "192.168.1.1".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            interface: "eth0".to_string(),
        };
        let anomaly = detector.check_arp_entry(&entry_bad);
        assert!(anomaly.is_some());
        assert_eq!(anomaly.unwrap().previous_mac, "11:22:33:44:55:66");
    }

    #[test]
    fn test_anomalies_tracked() {
        let event_bus = EventBus::new(100);
        let mut detector = ArpDetectorModule::new(event_bus);

        detector.add_known_mapping("10.0.0.1", "aa:bb:cc:dd:ee:00");

        let entry = ArpEntry {
            ip: "10.0.0.1".to_string(),
            mac: "ff:ff:ff:ff:ff:ff".to_string(),
            interface: "eth0".to_string(),
        };
        detector.check_arp_entry(&entry);
        assert_eq!(detector.anomaly_count(), 1);
    }

    #[tokio::test]
    async fn test_monitor_shuts_down_on_stop() {
        let event_bus = EventBus::new(100);
        let mut detector = ArpDetectorModule::new(event_bus);

        detector
            .initialize(&ModuleConfig::default())
            .await
            .unwrap();
        detector.start().await.unwrap();
        assert_eq!(detector.status(), ModuleStatus::Running);

        // Let the monitoring loop tick at least once
        sleep(Duration::from_millis(100)).await;

        // stop() flips the flag -- the loop should exit on its next iteration
        detector.stop().await.unwrap();
        assert_eq!(detector.status(), ModuleStatus::Stopped);
        assert!(!detector.running.load(Ordering::Relaxed));

        // Give the spawned task time to observe the flag and exit
        sleep(Duration::from_millis(200)).await;
    }

    #[test]
    fn test_with_config_creates_detector() {
        let event_bus = EventBus::new(100);
        let config = ArpConfig {
            enabled: true,
            scan_interval_secs: 10,
            known_gateways: vec![monitor::GatewayConfig {
                ip: "192.168.1.1".to_string(),
                mac: "11:22:33:44:55:66".to_string(),
                description: Some("Gateway".to_string()),
            }],
            max_anomalies: 500,
            log_all_changes: true,
        };

        let detector = ArpDetectorModule::with_config(event_bus, config);
        assert_eq!(detector.config().scan_interval_secs, 10);
        assert!(detector.config().log_all_changes);
        assert_eq!(detector.known_mapping_count(), 1);
        assert!(detector.has_known_mapping("192.168.1.1"));
    }

    #[test]
    fn test_remove_known_mapping() {
        let event_bus = EventBus::new(100);
        let mut detector = ArpDetectorModule::new(event_bus);

        detector.add_known_mapping("192.168.1.1", "11:22:33:44:55:66");
        assert!(detector.has_known_mapping("192.168.1.1"));

        detector.remove_known_mapping("192.168.1.1");
        assert!(!detector.has_known_mapping("192.168.1.1"));
    }

    #[test]
    fn test_check_entries_batch() {
        let event_bus = EventBus::new(100);
        let mut detector = ArpDetectorModule::new(event_bus);

        detector.add_known_mapping("192.168.1.1", "11:22:33:44:55:66");
        detector.add_known_mapping("192.168.1.2", "aa:bb:cc:dd:ee:ff");

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
                mac: "ff:ff:ff:ff:ff:ff".to_string(), // unknown
                interface: "eth0".to_string(),
            },
        ];

        let anomalies = detector.check_entries(&entries);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].ip, "192.168.1.1");
    }

    #[test]
    fn test_clear_anomalies() {
        let event_bus = EventBus::new(100);
        let mut detector = ArpDetectorModule::new(event_bus);

        detector.add_known_mapping("192.168.1.1", "11:22:33:44:55:66");
        let entry = ArpEntry {
            ip: "192.168.1.1".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            interface: "eth0".to_string(),
        };
        detector.check_arp_entry(&entry);
        assert_eq!(detector.anomaly_count(), 1);

        detector.clear_anomalies();
        assert_eq!(detector.anomaly_count(), 0);
        assert!(detector.has_known_mapping("192.168.1.1"));
    }

    #[test]
    fn test_on_event_is_noop() {
        let event_bus = EventBus::new(100);
        let mut detector = ArpDetectorModule::new(event_bus);

        let event = ModuleEvent::VpnConnected {
            server: "test".to_string(),
            ip: "1.2.3.4".to_string(),
        };
        assert!(detector.on_event(&event).await.is_ok());
    }
}
