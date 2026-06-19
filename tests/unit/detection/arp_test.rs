use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::{ModuleConfig, ModuleEvent, ModuleStatus, SecurityModule};
use app_security::detection::arp::monitor::{ArpConfig, ArpEntry, GatewayConfig};
use app_security::detection::arp::ArpDetectorModule;

// ---------------------------------------------------------------------------
// Module identity and lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_arp_detector_initialization() {
    let event_bus = EventBus::new(100);
    let mut detector = ArpDetectorModule::new(event_bus);

    assert_eq!(detector.status(), ModuleStatus::Created);

    detector
        .initialize(&ModuleConfig::default())
        .await
        .unwrap();
    assert_eq!(detector.status(), ModuleStatus::Initialized);
}

#[tokio::test]
async fn test_arp_detector_start_stop() {
    let event_bus = EventBus::new(100);
    let mut detector = ArpDetectorModule::new(event_bus);

    detector
        .initialize(&ModuleConfig::default())
        .await
        .unwrap();
    detector.start().await.unwrap();
    assert_eq!(detector.status(), ModuleStatus::Running);

    detector.stop().await.unwrap();
    assert_eq!(detector.status(), ModuleStatus::Stopped);
}

#[tokio::test]
async fn test_arp_detector_id_and_metadata() {
    let event_bus = EventBus::new(100);
    let detector = ArpDetectorModule::new(event_bus);

    assert_eq!(detector.id(), "arp_detector");
    assert_eq!(detector.name(), "ARP Spoof Detector");
    assert_eq!(detector.priority(), 3);
    assert!(detector.dependencies().is_empty());
}

#[tokio::test]
async fn test_arp_detector_unrelated_events_ignored() {
    let event_bus = EventBus::new(100);
    let mut detector = ArpDetectorModule::new(event_bus);

    detector
        .initialize(&ModuleConfig::default())
        .await
        .unwrap();
    detector.start().await.unwrap();

    let event = ModuleEvent::VpnConnected {
        server: "10.0.0.1".to_string(),
        ip: "10.0.0.2".to_string(),
    };
    detector.on_event(&event).await.unwrap();
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

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
    assert_eq!(config.known_gateways[0].ip, deserialized.known_gateways[0].ip);
}

#[test]
fn test_arp_config_toml_roundtrip() {
    let config = ArpConfig {
        enabled: true,
        scan_interval_secs: 15,
        known_gateways: vec![
            GatewayConfig {
                ip: "192.168.1.1".to_string(),
                mac: "11:22:33:44:55:66".to_string(),
                description: Some("Primary".to_string()),
            },
            GatewayConfig {
                ip: "10.0.0.1".to_string(),
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
                description: None,
            },
        ],
        max_anomalies: 200,
        log_all_changes: false,
    };

    let toml_str = toml::to_string_pretty(&config).unwrap();
    let deserialized: ArpConfig = toml::from_str(&toml_str).unwrap();

    assert_eq!(config.enabled, deserialized.enabled);
    assert_eq!(config.scan_interval_secs, deserialized.scan_interval_secs);
    assert_eq!(config.known_gateways.len(), deserialized.known_gateways.len());
}

// ---------------------------------------------------------------------------
// with_config constructor
// ---------------------------------------------------------------------------

#[test]
fn test_with_config_creates_detector() {
    let event_bus = EventBus::new(100);
    let config = ArpConfig {
        enabled: true,
        scan_interval_secs: 10,
        known_gateways: vec![GatewayConfig {
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
fn test_with_config_multiple_gateways() {
    let event_bus = EventBus::new(100);
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
                description: None,
            },
            GatewayConfig {
                ip: "172.16.0.1".to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                description: None,
            },
        ],
        max_anomalies: 1000,
        log_all_changes: false,
    };

    let detector = ArpDetectorModule::with_config(event_bus, config);
    assert_eq!(detector.known_mapping_count(), 3);
}

// ---------------------------------------------------------------------------
// Known mapping management
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_add_and_check_known_mapping() {
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
fn test_remove_known_mapping() {
    let event_bus = EventBus::new(100);
    let mut detector = ArpDetectorModule::new(event_bus);

    detector.add_known_mapping("192.168.1.1", "11:22:33:44:55:66");
    assert!(detector.has_known_mapping("192.168.1.1"));
    assert_eq!(detector.known_mapping_count(), 1);

    detector.remove_known_mapping("192.168.1.1");
    assert!(!detector.has_known_mapping("192.168.1.1"));
    assert_eq!(detector.known_mapping_count(), 0);
}

#[test]
fn test_has_known_mapping() {
    let event_bus = EventBus::new(100);
    let detector = ArpDetectorModule::new(event_bus);

    assert!(!detector.has_known_mapping("192.168.1.1"));
}

// ---------------------------------------------------------------------------
// Anomaly detection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_anomalies_tracked() {
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
    assert_eq!(detector.anomalies().len(), 1);
}

#[tokio::test]
async fn test_check_arp_entry_emits_event() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();
    let mut detector = ArpDetectorModule::new(event_bus);

    detector.add_known_mapping("192.168.1.1", "11:22:33:44:55:66");

    let entry = ArpEntry {
        ip: "192.168.1.1".to_string(),
        mac: "aa:bb:cc:dd:ee:ff".to_string(),
        interface: "eth0".to_string(),
    };
    detector.check_arp_entry(&entry);

    let event = receiver.recv().await.unwrap();
    match event {
        ModuleEvent::ArpSpoofDetected {
            attacker_mac,
            victim_ip,
        } => {
            assert_eq!(attacker_mac, "aa:bb:cc:dd:ee:ff");
            assert_eq!(victim_ip, "192.168.1.1");
        }
        _ => panic!("Expected ArpSpoofDetected event"),
    }
}

#[tokio::test]
async fn test_simulate_arp_spoof_emits_event() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();
    let detector = ArpDetectorModule::new(event_bus);

    detector
        .simulate_arp_spoof("aa:bb:cc:dd:ee:ff", "192.168.1.1")
        .await;

    let event = receiver.recv().await.unwrap();
    match event {
        ModuleEvent::ArpSpoofDetected {
            attacker_mac,
            victim_ip,
        } => {
            assert_eq!(attacker_mac, "aa:bb:cc:dd:ee:ff");
            assert_eq!(victim_ip, "192.168.1.1");
        }
        _ => panic!("Expected ArpSpoofDetected event"),
    }
}

// ---------------------------------------------------------------------------
// Batch operations
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_check_entries_batch() {
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

#[tokio::test]
async fn test_check_entries_emits_events() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();
    let mut detector = ArpDetectorModule::new(event_bus);

    detector.add_known_mapping("192.168.1.1", "11:22:33:44:55:66");
    detector.add_known_mapping("192.168.1.2", "aa:bb:cc:dd:ee:ff");

    let entries = vec![
        ArpEntry {
            ip: "192.168.1.1".to_string(),
            mac: "aa:bb:cc:dd:ee:01".to_string(),
            interface: "eth0".to_string(),
        },
        ArpEntry {
            ip: "192.168.1.2".to_string(),
            mac: "aa:bb:cc:dd:ee:01".to_string(),
            interface: "eth0".to_string(),
        },
    ];

    let anomalies = detector.check_entries(&entries);
    assert_eq!(anomalies.len(), 2);

    // Both anomalies should have emitted events
    let event1 = receiver.recv().await.unwrap();
    let event2 = receiver.recv().await.unwrap();
    assert!(matches!(event1, ModuleEvent::ArpSpoofDetected { .. }));
    assert!(matches!(event2, ModuleEvent::ArpSpoofDetected { .. }));
}

// ---------------------------------------------------------------------------
// Clear anomalies
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_clear_anomalies() {
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
    // Mapping should still exist
    assert!(detector.has_known_mapping("192.168.1.1"));
}

// ---------------------------------------------------------------------------
// ArpAnomaly serialization
// ---------------------------------------------------------------------------

#[test]
fn test_anomaly_serialization() {
    use app_security::detection::arp::monitor::ArpAnomaly;
    use chrono::Utc;

    let anomaly = ArpAnomaly {
        ip: "192.168.1.1".to_string(),
        previous_mac: "11:22:33:44:55:66".to_string(),
        new_mac: "aa:bb:cc:dd:ee:ff".to_string(),
        timestamp: Utc::now(),
        description: Some("MAC changed".to_string()),
    };

    let json = serde_json::to_string(&anomaly).unwrap();
    let deserialized: ArpAnomaly = serde_json::from_str(&json).unwrap();

    assert_eq!(anomaly.ip, deserialized.ip);
    assert_eq!(anomaly.previous_mac, deserialized.previous_mac);
    assert_eq!(anomaly.new_mac, deserialized.new_mac);
    assert_eq!(anomaly.description, deserialized.description);
}
