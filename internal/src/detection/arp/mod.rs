pub mod monitor;

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::core::event_bus::EventBus;
use crate::core::mod_trait::{ModuleConfig, ModuleEvent, ModuleStatus, SecurityModule};
use monitor::{ArpAnomaly, ArpEntry, ArpMonitor};

pub struct ArpDetectorModule {
    event_bus: EventBus,
    status: ModuleStatus,
    /// Controls the ARP monitoring loop. Set to `true` in `start()`, `false` in `stop()`.
    running: Arc<AtomicBool>,
    /// The ARP spoof detection engine.
    arp_monitor: ArpMonitor,
}

impl ArpDetectorModule {
    pub fn new(event_bus: EventBus) -> Self {
        Self {
            event_bus,
            status: ModuleStatus::Created,
            running: Arc::new(AtomicBool::new(false)),
            arp_monitor: ArpMonitor::new(),
        }
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

    /// Get all detected anomalies from the underlying monitor.
    pub fn anomalies(&self) -> &[ArpAnomaly] {
        self.arp_monitor.anomalies()
    }

    /// The ARP monitoring loop. Checks the `running` flag each iteration so
    /// that `stop()` can terminate it gracefully.
    async fn monitor_arp(running: Arc<AtomicBool>, event_bus: EventBus) {
        while running.load(Ordering::Relaxed) {
            // Periodic ARP table scanning for anomalies.
            // The actual pcap-based packet capture or ARP table parsing will be
            // implemented when the system integration layer is added. For now,
            // this loop provides the correct control-flow skeleton with a
            // working shutdown mechanism.
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
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
        // Spawn the monitoring loop as a background task so start() returns
        // immediately.
        tokio::spawn(Self::monitor_arp(running, event_bus));
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
        assert_eq!(detector.anomalies().len(), 1);
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
}
