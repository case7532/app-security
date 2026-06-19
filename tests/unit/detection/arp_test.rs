use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::{ModuleConfig, ModuleEvent, ModuleStatus, SecurityModule};
use app_security::detection::arp::ArpDetectorModule;

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
async fn test_arp_detector_detects_spoof() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();
    let mut detector = ArpDetectorModule::new(event_bus);

    detector
        .initialize(&ModuleConfig::default())
        .await
        .unwrap();
    detector.start().await.unwrap();

    // Simulate ARP spoof detection
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

    // An unrelated event should be silently ignored
    let event = ModuleEvent::VpnConnected {
        server: "10.0.0.1".to_string(),
        ip: "10.0.0.2".to_string(),
    };
    detector.on_event(&event).await.unwrap();
}
