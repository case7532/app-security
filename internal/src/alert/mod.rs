pub mod log;
pub mod types;

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::core::event_bus::EventBus;
use crate::core::mod_trait::{ModuleConfig, ModuleEvent, ModuleStatus, SecurityModule};

use types::{Alert, AlertConfig, AlertSeverity};

/// Alert module that listens to events and creates security alerts.
pub struct AlertManager {
    #[allow(dead_code)]
    event_bus: EventBus,
    status: ModuleStatus,
    /// In-memory alert storage.
    alerts: Arc<RwLock<Vec<Alert>>>,
    /// Alert configuration.
    config: AlertConfig,
}

impl AlertManager {
    pub fn new(event_bus: EventBus) -> Self {
        Self {
            event_bus,
            status: ModuleStatus::Created,
            alerts: Arc::new(RwLock::new(Vec::new())),
            config: AlertConfig::default(),
        }
    }

    /// Create with custom configuration.
    pub fn with_config(event_bus: EventBus, config: AlertConfig) -> Self {
        Self {
            event_bus,
            status: ModuleStatus::Created,
            alerts: Arc::new(RwLock::new(Vec::new())),
            config,
        }
    }

    /// Get current configuration.
    pub fn config(&self) -> &AlertConfig {
        &self.config
    }

    /// Add an alert to storage.
    pub async fn add_alert(&self, alert: Alert) {
        let mut alerts = self.alerts.write().await;

        // Enforce max alerts limit
        if alerts.len() >= self.config.max_alerts {
            alerts.remove(0);
        }

        alerts.push(alert);
    }

    /// Get all alerts.
    pub async fn get_alerts(&self) -> Vec<Alert> {
        self.alerts.read().await.clone()
    }

    /// Get alerts filtered by severity.
    pub async fn get_alerts_by_severity(&self, severity: AlertSeverity) -> Vec<Alert> {
        self.alerts
            .read()
            .await
            .iter()
            .filter(|a| a.severity == severity)
            .cloned()
            .collect()
    }

    /// Get the count of alerts.
    pub async fn alert_count(&self) -> usize {
        self.alerts.read().await.len()
    }

    /// Get the count of alerts by severity.
    pub async fn count_by_severity(&self, severity: AlertSeverity) -> usize {
        self.alerts
            .read()
            .await
            .iter()
            .filter(|a| a.severity == severity)
            .count()
    }

    /// Clear all alerts.
    pub async fn clear_alerts(&self) {
        self.alerts.write().await.clear();
    }

    /// Clear alerts older than a given duration.
    pub async fn clear_old_alerts(&self, max_age: std::time::Duration) {
        let cutoff = chrono::Utc::now() - chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::hours(24));
        self.alerts
            .write()
            .await
            .retain(|a| a.timestamp > cutoff);
    }

    /// Get the most recent N alerts.
    pub async fn recent_alerts(&self, limit: usize) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        alerts.iter().rev().take(limit).cloned().collect()
    }

    /// Get unacknowledged alerts.
    pub async fn unacknowledged_alerts(&self) -> Vec<Alert> {
        self.alerts
            .read()
            .await
            .iter()
            .filter(|a| !a.acknowledged)
            .cloned()
            .collect()
    }

    /// Acknowledge an alert by ID.
    pub async fn acknowledge_alert(&self, alert_id: &str) -> bool {
        let mut alerts = self.alerts.write().await;
        if let Some(alert) = alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.acknowledged = true;
            true
        } else {
            false
        }
    }

    /// Convert a ModuleEvent to an Alert, if applicable.
    fn event_to_alert(event: &ModuleEvent) -> Option<Alert> {
        match event {
            ModuleEvent::ArpSpoofDetected {
                attacker_mac,
                victim_ip,
            } => Some(Alert::new(
                AlertSeverity::Critical,
                "ARP Spoof Detected".to_string(),
                format!(
                    "ARP spoofing detected: MAC {} is impersonating IP {}",
                    attacker_mac, victim_ip
                ),
            )),
            ModuleEvent::VpnDisconnected { reason } => Some(Alert::new(
                AlertSeverity::High,
                "VPN Disconnected".to_string(),
                format!("VPN connection lost: {}", reason),
            )),
            ModuleEvent::VpnConnectionFailed { error } => Some(Alert::new(
                AlertSeverity::High,
                "VPN Connection Failed".to_string(),
                format!("Failed to connect to VPN: {}", error),
            )),
            ModuleEvent::DnsLeakDetected {
                dns_server,
                interface,
            } => Some(Alert::new(
                AlertSeverity::High,
                "DNS Leak Detected".to_string(),
                format!(
                    "DNS leak detected: {} responded on interface {}",
                    dns_server, interface
                ),
            )),
            ModuleEvent::FirewallRuleBlocked { src_ip, dst_port } => Some(Alert::new(
                AlertSeverity::Medium,
                "Traffic Blocked".to_string(),
                format!("Firewall blocked traffic from {} to port {}", src_ip, dst_port),
            )),
            ModuleEvent::ModuleFailed {
                module_id,
                error,
            } => Some(Alert::new(
                AlertSeverity::High,
                "Module Failed".to_string(),
                format!("Module '{}' failed: {}", module_id, error),
            )),
            ModuleEvent::VpnConnected { server, ip } => Some(Alert::new(
                AlertSeverity::Info,
                "VPN Connected".to_string(),
                format!("Connected to VPN server {} (IP: {})", server, ip),
            )),
            ModuleEvent::FirewallRuleAdded {
                rule_id,
                description,
            } => Some(Alert::new(
                AlertSeverity::Info,
                "Firewall Rule Added".to_string(),
                format!("Rule '{}' added: {}", rule_id, description),
            )),
            _ => None,
        }
    }
}

#[async_trait]
impl SecurityModule for AlertManager {
    fn id(&self) -> &str {
        "alert_manager"
    }

    fn name(&self) -> &str {
        "Alert Manager"
    }

    fn priority(&self) -> u32 {
        6
    }

    fn dependencies(&self) -> Vec<&str> {
        vec![]
    }

    async fn initialize(&mut self, _config: &ModuleConfig) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Initialized;
        Ok(())
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Running;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Stopped;
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    async fn on_event(&mut self, event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(alert) = Self::event_to_alert(event) {
            self.add_alert(alert).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (EventBus, AlertManager) {
        let event_bus = EventBus::new(32);
        let manager = AlertManager::new(event_bus.clone());
        (event_bus, manager)
    }

    #[tokio::test]
    async fn test_alert_manager_creation() {
        let (_, manager) = setup();
        assert_eq!(manager.id(), "alert_manager");
        assert_eq!(manager.name(), "Alert Manager");
        assert_eq!(manager.priority(), 6);
        assert!(manager.dependencies().is_empty());
    }

    #[tokio::test]
    async fn test_alert_manager_lifecycle() {
        let (_, mut manager) = setup();
        assert_eq!(manager.status(), ModuleStatus::Created);

        manager.initialize(&ModuleConfig::default()).await.unwrap();
        assert_eq!(manager.status(), ModuleStatus::Initialized);

        manager.start().await.unwrap();
        assert_eq!(manager.status(), ModuleStatus::Running);

        manager.stop().await.unwrap();
        assert_eq!(manager.status(), ModuleStatus::Stopped);
    }

    #[tokio::test]
    async fn test_add_and_get_alerts() {
        let (_, manager) = setup();

        let alert = Alert::new(
            AlertSeverity::Critical,
            "Test Alert".to_string(),
            "Test message".to_string(),
        );
        manager.add_alert(alert).await;

        assert_eq!(manager.alert_count().await, 1);
        let alerts = manager.get_alerts().await;
        assert_eq!(alerts[0].title, "Test Alert");
    }

    #[tokio::test]
    async fn test_filter_by_severity() {
        let (_, manager) = setup();

        manager
            .add_alert(Alert::new(
                AlertSeverity::Critical,
                "Critical".to_string(),
                "msg".to_string(),
            ))
            .await;
        manager
            .add_alert(Alert::new(
                AlertSeverity::Info,
                "Info".to_string(),
                "msg".to_string(),
            ))
            .await;
        manager
            .add_alert(Alert::new(
                AlertSeverity::Critical,
                "Critical 2".to_string(),
                "msg".to_string(),
            ))
            .await;

        let critical = manager
            .get_alerts_by_severity(AlertSeverity::Critical)
            .await;
        assert_eq!(critical.len(), 2);

        let info = manager.get_alerts_by_severity(AlertSeverity::Info).await;
        assert_eq!(info.len(), 1);
    }

    #[tokio::test]
    async fn test_clear_alerts() {
        let (_, manager) = setup();

        manager
            .add_alert(Alert::new(
                AlertSeverity::Info,
                "Test".to_string(),
                "msg".to_string(),
            ))
            .await;
        assert_eq!(manager.alert_count().await, 1);

        manager.clear_alerts().await;
        assert_eq!(manager.alert_count().await, 0);
    }

    #[tokio::test]
    async fn test_recent_alerts() {
        let (_, manager) = setup();

        for i in 0..5 {
            manager
                .add_alert(Alert::new(
                    AlertSeverity::Info,
                    format!("Alert {}", i),
                    "msg".to_string(),
                ))
                .await;
        }

        let recent = manager.recent_alerts(3).await;
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].title, "Alert 4"); // most recent first
    }

    #[tokio::test]
    async fn test_acknowledge_alert() {
        let (_, manager) = setup();

        let mut alert = Alert::new(
            AlertSeverity::High,
            "Test".to_string(),
            "msg".to_string(),
        );
        let id = alert.id.clone();
        manager.add_alert(alert).await;

        assert!(!manager.unacknowledged_alerts().await.is_empty());

        manager.acknowledge_alert(&id).await;
        assert!(manager.unacknowledged_alerts().await.is_empty());
    }

    #[tokio::test]
    async fn test_event_to_alert_arp_spoof() {
        let event = ModuleEvent::ArpSpoofDetected {
            attacker_mac: "aa:bb:cc:dd:ee:ff".to_string(),
            victim_ip: "192.168.1.1".to_string(),
        };
        let alert = AlertManager::event_to_alert(&event).unwrap();
        assert_eq!(alert.severity, AlertSeverity::Critical);
        assert!(alert.message.contains("aa:bb:cc:dd:ee:ff"));
    }

    #[tokio::test]
    async fn test_event_to_alert_vpn_disconnect() {
        let event = ModuleEvent::VpnDisconnected {
            reason: "Connection lost".to_string(),
        };
        let alert = AlertManager::event_to_alert(&event).unwrap();
        assert_eq!(alert.severity, AlertSeverity::High);
        assert!(alert.message.contains("Connection lost"));
    }

    #[tokio::test]
    async fn test_event_to_alert_dns_leak() {
        let event = ModuleEvent::DnsLeakDetected {
            dns_server: "8.8.8.8".to_string(),
            interface: "en0".to_string(),
        };
        let alert = AlertManager::event_to_alert(&event).unwrap();
        assert_eq!(alert.severity, AlertSeverity::High);
        assert!(alert.message.contains("8.8.8.8"));
    }

    #[tokio::test]
    async fn test_event_to_alert_no_alert_for_module_started() {
        let event = ModuleEvent::ModuleStarted {
            module_id: "test".to_string(),
        };
        assert!(AlertManager::event_to_alert(&event).is_none());
    }

    #[tokio::test]
    async fn test_on_event_creates_alert() {
        let (_, mut manager) = setup();
        manager.start().await.unwrap();

        let event = ModuleEvent::ArpSpoofDetected {
            attacker_mac: "aa:bb:cc:dd:ee:ff".to_string(),
            victim_ip: "192.168.1.1".to_string(),
        };
        manager.on_event(&event).await.unwrap();

        assert_eq!(manager.alert_count().await, 1);
    }

    #[tokio::test]
    async fn test_max_alerts_limit() {
        let event_bus = EventBus::new(32);
        let config = AlertConfig {
            max_alerts: 3,
            ..Default::default()
        };
        let manager = AlertManager::with_config(event_bus, config);

        for i in 0..5 {
            manager
                .add_alert(Alert::new(
                    AlertSeverity::Info,
                    format!("Alert {}", i),
                    "msg".to_string(),
                ))
                .await;
        }

        // Should cap at max_alerts
        assert_eq!(manager.alert_count().await, 3);
    }
}
