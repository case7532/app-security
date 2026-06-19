use app_security::alert::types::{Alert, AlertCategory, AlertConfig, AlertSeverity};
use app_security::alert::AlertManager;
use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::{ModuleConfig, ModuleEvent, ModuleStatus, SecurityModule};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn setup() -> (EventBus, AlertManager) {
    let event_bus = EventBus::new(32);
    let manager = AlertManager::new(event_bus.clone());
    (event_bus, manager)
}

// ---------------------------------------------------------------------------
// Module identity and lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_alert_manager_id_and_metadata() {
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
async fn test_alert_manager_start_stop_idempotent() {
    let (_, mut manager) = setup();
    manager.initialize(&ModuleConfig::default()).await.unwrap();

    manager.start().await.unwrap();
    manager.start().await.unwrap();
    assert_eq!(manager.status(), ModuleStatus::Running);

    manager.stop().await.unwrap();
    manager.stop().await.unwrap();
    assert_eq!(manager.status(), ModuleStatus::Stopped);
}

// ---------------------------------------------------------------------------
// Alert types
// ---------------------------------------------------------------------------

#[test]
fn test_alert_severity_display() {
    assert_eq!(format!("{}", AlertSeverity::Info), "INFO");
    assert_eq!(format!("{}", AlertSeverity::Medium), "MEDIUM");
    assert_eq!(format!("{}", AlertSeverity::High), "HIGH");
    assert_eq!(format!("{}", AlertSeverity::Critical), "CRITICAL");
}

#[test]
fn test_alert_severity_ordering() {
    assert!(AlertSeverity::Info < AlertSeverity::Medium);
    assert!(AlertSeverity::Medium < AlertSeverity::High);
    assert!(AlertSeverity::High < AlertSeverity::Critical);
}

#[test]
fn test_alert_creation() {
    let alert = Alert::new(
        AlertSeverity::High,
        "Test".to_string(),
        "Message".to_string(),
    );

    assert!(!alert.id.is_empty());
    assert_eq!(alert.severity, AlertSeverity::High);
    assert_eq!(alert.title, "Test");
    assert_eq!(alert.message, "Message");
    assert!(!alert.acknowledged);
}

#[test]
fn test_alert_with_category() {
    let alert = Alert::with_category(
        AlertSeverity::High,
        AlertCategory::Vpn,
        "VPN Alert".to_string(),
        "Disconnected".to_string(),
    );

    assert_eq!(alert.category, AlertCategory::Vpn);
}

#[test]
fn test_alert_display() {
    let alert = Alert::new(
        AlertSeverity::Critical,
        "ARP Spoof".to_string(),
        "Detected attack".to_string(),
    );

    let display = format!("{}", alert);
    assert!(display.contains("CRITICAL"));
    assert!(display.contains("ARP Spoof"));
    assert!(display.contains("Detected attack"));
}

#[test]
fn test_alert_serialization_roundtrip() {
    let alert = Alert::new(
        AlertSeverity::High,
        "Test".to_string(),
        "Message".to_string(),
    );

    let json = serde_json::to_string(&alert).unwrap();
    let deserialized: Alert = serde_json::from_str(&json).unwrap();

    assert_eq!(alert.id, deserialized.id);
    assert_eq!(alert.severity, deserialized.severity);
    assert_eq!(alert.title, deserialized.title);
    assert_eq!(alert.message, deserialized.message);
}

// ---------------------------------------------------------------------------
// AlertConfig
// ---------------------------------------------------------------------------

#[test]
fn test_alert_config_default() {
    let config = AlertConfig::default();
    assert!(config.enabled);
    assert_eq!(config.max_alerts, 1000);
    assert_eq!(config.min_severity, AlertSeverity::Info);
    assert!(config.log_to_file);
    assert!(config.log_file_path.is_none());
    assert_eq!(config.max_age_secs, 86400);
}

#[test]
fn test_alert_config_serialization() {
    let config = AlertConfig {
        enabled: true,
        max_alerts: 500,
        min_severity: AlertSeverity::High,
        log_to_file: false,
        log_file_path: Some("/tmp/alerts.log".to_string()),
        max_age_secs: 3600,
    };

    let json = serde_json::to_string(&config).unwrap();
    let deserialized: AlertConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(config.max_alerts, deserialized.max_alerts);
    assert_eq!(config.min_severity, deserialized.min_severity);
    assert_eq!(config.log_file_path, deserialized.log_file_path);
    assert_eq!(config.max_age_secs, deserialized.max_age_secs);
}

#[test]
fn test_alert_config_toml_roundtrip() {
    let config = AlertConfig {
        enabled: true,
        max_alerts: 200,
        min_severity: AlertSeverity::Medium,
        log_to_file: true,
        log_file_path: Some("/var/log/alerts.json".to_string()),
        max_age_secs: 7200,
    };

    let toml_str = toml::to_string_pretty(&config).unwrap();
    let deserialized: AlertConfig = toml::from_str(&toml_str).unwrap();

    assert_eq!(config.max_alerts, deserialized.max_alerts);
    assert_eq!(config.min_severity, deserialized.min_severity);
}

// ---------------------------------------------------------------------------
// Alert management
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_add_and_get_alerts() {
    let (_, manager) = setup();

    manager
        .add_alert(Alert::new(
            AlertSeverity::Critical,
            "Critical Alert".to_string(),
            "Something bad".to_string(),
        ))
        .await;

    assert_eq!(manager.alert_count().await, 1);
    let alerts = manager.get_alerts().await;
    assert_eq!(alerts[0].title, "Critical Alert");
}

#[tokio::test]
async fn test_add_multiple_alerts() {
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

    assert_eq!(manager.alert_count().await, 5);
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

    let high = manager.get_alerts_by_severity(AlertSeverity::High).await;
    assert_eq!(high.len(), 0);
}

#[tokio::test]
async fn test_count_by_severity() {
    let (_, manager) = setup();

    manager
        .add_alert(Alert::new(
            AlertSeverity::High,
            "H1".to_string(),
            "msg".to_string(),
        ))
        .await;
    manager
        .add_alert(Alert::new(
            AlertSeverity::High,
            "H2".to_string(),
            "msg".to_string(),
        ))
        .await;
    manager
        .add_alert(Alert::new(
            AlertSeverity::Critical,
            "C1".to_string(),
            "msg".to_string(),
        ))
        .await;

    assert_eq!(
        manager.count_by_severity(AlertSeverity::High).await,
        2
    );
    assert_eq!(
        manager.count_by_severity(AlertSeverity::Critical).await,
        1
    );
    assert_eq!(manager.count_by_severity(AlertSeverity::Info).await, 0);
}

#[tokio::test]
async fn test_clear_alerts() {
    let (_, manager) = setup();

    for i in 0..3 {
        manager
            .add_alert(Alert::new(
                AlertSeverity::Info,
                format!("Alert {}", i),
                "msg".to_string(),
            ))
            .await;
    }
    assert_eq!(manager.alert_count().await, 3);

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
    assert_eq!(recent[0].title, "Alert 4");
    assert_eq!(recent[1].title, "Alert 3");
    assert_eq!(recent[2].title, "Alert 2");
}

#[tokio::test]
async fn test_recent_alerts_limit() {
    let (_, manager) = setup();

    for i in 0..3 {
        manager
            .add_alert(Alert::new(
                AlertSeverity::Info,
                format!("Alert {}", i),
                "msg".to_string(),
            ))
            .await;
    }

    let recent = manager.recent_alerts(10).await;
    assert_eq!(recent.len(), 3);
}

// ---------------------------------------------------------------------------
// Acknowledgment
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_acknowledge_alert() {
    let (_, manager) = setup();

    let alert = Alert::new(
        AlertSeverity::High,
        "Test".to_string(),
        "msg".to_string(),
    );
    let id = alert.id.clone();
    manager.add_alert(alert).await;

    assert_eq!(manager.unacknowledged_alerts().await.len(), 1);

    let result = manager.acknowledge_alert(&id).await;
    assert!(result);
    assert_eq!(manager.unacknowledged_alerts().await.len(), 0);
}

#[tokio::test]
async fn test_acknowledge_nonexistent_alert() {
    let (_, manager) = setup();

    let result = manager.acknowledge_alert("nonexistent-id").await;
    assert!(!result);
}

#[tokio::test]
async fn test_unacknowledged_alerts() {
    let (_, manager) = setup();

    let alert1 = Alert::new(
        AlertSeverity::High,
        "Alert 1".to_string(),
        "msg".to_string(),
    );
    let id1 = alert1.id.clone();
    manager.add_alert(alert1).await;

    manager
        .add_alert(Alert::new(
            AlertSeverity::High,
            "Alert 2".to_string(),
            "msg".to_string(),
        ))
        .await;

    assert_eq!(manager.unacknowledged_alerts().await.len(), 2);

    manager.acknowledge_alert(&id1).await;
    let unacked = manager.unacknowledged_alerts().await;
    assert_eq!(unacked.len(), 1);
    assert_eq!(unacked[0].title, "Alert 2");
}

// ---------------------------------------------------------------------------
// Max alerts limit
// ---------------------------------------------------------------------------

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

    assert_eq!(manager.alert_count().await, 3);
    let alerts = manager.get_alerts().await;
    assert_eq!(alerts[0].title, "Alert 2");
}

// ---------------------------------------------------------------------------
// Event-driven alert creation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_on_event_creates_arp_alert() {
    let (_, mut manager) = setup();
    manager.start().await.unwrap();

    let event = ModuleEvent::ArpSpoofDetected {
        attacker_mac: "aa:bb:cc:dd:ee:ff".to_string(),
        victim_ip: "192.168.1.1".to_string(),
    };
    manager.on_event(&event).await.unwrap();

    assert_eq!(manager.alert_count().await, 1);
    let alerts = manager.get_alerts().await;
    assert_eq!(alerts[0].severity, AlertSeverity::Critical);
    assert!(alerts[0].message.contains("aa:bb:cc:dd:ee:ff"));
}

#[tokio::test]
async fn test_on_event_creates_vpn_disconnect_alert() {
    let (_, mut manager) = setup();
    manager.start().await.unwrap();

    let event = ModuleEvent::VpnDisconnected {
        reason: "Connection lost".to_string(),
    };
    manager.on_event(&event).await.unwrap();

    assert_eq!(manager.alert_count().await, 1);
    let alerts = manager.get_alerts().await;
    assert_eq!(alerts[0].severity, AlertSeverity::High);
    assert!(alerts[0].message.contains("Connection lost"));
}

#[tokio::test]
async fn test_on_event_creates_vpn_failed_alert() {
    let (_, mut manager) = setup();
    manager.start().await.unwrap();

    let event = ModuleEvent::VpnConnectionFailed {
        error: "Timeout".to_string(),
    };
    manager.on_event(&event).await.unwrap();

    assert_eq!(manager.alert_count().await, 1);
    let alerts = manager.get_alerts().await;
    assert_eq!(alerts[0].severity, AlertSeverity::High);
}

#[tokio::test]
async fn test_on_event_creates_dns_leak_alert() {
    let (_, mut manager) = setup();
    manager.start().await.unwrap();

    let event = ModuleEvent::DnsLeakDetected {
        dns_server: "8.8.8.8".to_string(),
        interface: "en0".to_string(),
    };
    manager.on_event(&event).await.unwrap();

    assert_eq!(manager.alert_count().await, 1);
    let alerts = manager.get_alerts().await;
    assert_eq!(alerts[0].severity, AlertSeverity::High);
    assert!(alerts[0].message.contains("8.8.8.8"));
}

#[tokio::test]
async fn test_on_event_creates_firewall_blocked_alert() {
    let (_, mut manager) = setup();
    manager.start().await.unwrap();

    let event = ModuleEvent::FirewallRuleBlocked {
        src_ip: "10.0.0.5".to_string(),
        dst_port: 443,
    };
    manager.on_event(&event).await.unwrap();

    assert_eq!(manager.alert_count().await, 1);
    let alerts = manager.get_alerts().await;
    assert_eq!(alerts[0].severity, AlertSeverity::Medium);
    assert!(alerts[0].message.contains("10.0.0.5"));
}

#[tokio::test]
async fn test_on_event_creates_module_failed_alert() {
    let (_, mut manager) = setup();
    manager.start().await.unwrap();

    let event = ModuleEvent::ModuleFailed {
        module_id: "dns".to_string(),
        error: "Connection refused".to_string(),
    };
    manager.on_event(&event).await.unwrap();

    assert_eq!(manager.alert_count().await, 1);
    let alerts = manager.get_alerts().await;
    assert_eq!(alerts[0].severity, AlertSeverity::High);
}

#[tokio::test]
async fn test_on_event_creates_vpn_connected_alert() {
    let (_, mut manager) = setup();
    manager.start().await.unwrap();

    let event = ModuleEvent::VpnConnected {
        server: "us-east".to_string(),
        ip: "1.2.3.4".to_string(),
    };
    manager.on_event(&event).await.unwrap();

    assert_eq!(manager.alert_count().await, 1);
    let alerts = manager.get_alerts().await;
    assert_eq!(alerts[0].severity, AlertSeverity::Info);
}

#[tokio::test]
async fn test_on_event_no_alert_for_module_started() {
    let (_, mut manager) = setup();
    manager.start().await.unwrap();

    let event = ModuleEvent::ModuleStarted {
        module_id: "dns".to_string(),
    };
    manager.on_event(&event).await.unwrap();

    assert_eq!(manager.alert_count().await, 0);
}

#[tokio::test]
async fn test_on_event_no_alert_for_module_stopped() {
    let (_, mut manager) = setup();
    manager.start().await.unwrap();

    let event = ModuleEvent::ModuleStopped {
        module_id: "dns".to_string(),
    };
    manager.on_event(&event).await.unwrap();

    assert_eq!(manager.alert_count().await, 0);
}

// ---------------------------------------------------------------------------
// Multiple events create multiple alerts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_multiple_events_create_alerts() {
    let (_, mut manager) = setup();
    manager.start().await.unwrap();

    let events = vec![
        ModuleEvent::ArpSpoofDetected {
            attacker_mac: "aa:bb:cc:dd:ee:ff".to_string(),
            victim_ip: "192.168.1.1".to_string(),
        },
        ModuleEvent::VpnDisconnected {
            reason: "test".to_string(),
        },
        ModuleEvent::DnsLeakDetected {
            dns_server: "8.8.8.8".to_string(),
            interface: "en0".to_string(),
        },
        ModuleEvent::FirewallRuleBlocked {
            src_ip: "10.0.0.1".to_string(),
            dst_port: 22,
        },
    ];

    for event in &events {
        manager.on_event(event).await.unwrap();
    }

    assert_eq!(manager.alert_count().await, 4);
    assert_eq!(
        manager.count_by_severity(AlertSeverity::Critical).await,
        1
    );
    assert_eq!(manager.count_by_severity(AlertSeverity::High).await, 2);
    assert_eq!(
        manager.count_by_severity(AlertSeverity::Medium).await,
        1
    );
}

// ---------------------------------------------------------------------------
// with_config constructor
// ---------------------------------------------------------------------------

#[test]
fn test_with_config() {
    let event_bus = EventBus::new(32);
    let config = AlertConfig {
        enabled: true,
        max_alerts: 100,
        min_severity: AlertSeverity::High,
        log_to_file: false,
        log_file_path: None,
        max_age_secs: 3600,
    };

    let manager = AlertManager::with_config(event_bus, config);
    assert_eq!(manager.config().max_alerts, 100);
    assert_eq!(manager.config().min_severity, AlertSeverity::High);
    assert!(!manager.config().log_to_file);
}
