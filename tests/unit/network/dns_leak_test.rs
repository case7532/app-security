use app_security::network::dns::leak::DnsLeakDetector;
use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::ModuleEvent;
use std::collections::HashSet;

#[tokio::test]
async fn test_leak_detector_identifies_known_server() {
    let event_bus = EventBus::new(100);
    let mut known = HashSet::new();
    known.insert("8.8.8.8".parse().unwrap());
    known.insert("1.1.1.1".parse().unwrap());

    let detector = DnsLeakDetector::new(event_bus, known);

    assert!(detector.is_known_server(&"8.8.8.8".parse().unwrap()));
    assert!(detector.is_known_server(&"1.1.1.1".parse().unwrap()));
    assert!(!detector.is_known_server(&"192.168.1.1".parse().unwrap()));
}

#[tokio::test]
async fn test_leak_detector_publishes_event() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();
    let mut known = HashSet::new();
    known.insert("8.8.8.8".parse().unwrap());

    let detector = DnsLeakDetector::new(event_bus, known);

    detector.detect_leak("8.8.8.8".parse().unwrap(), "eth0").await;

    let event = receiver.recv().await.unwrap();
    assert!(matches!(event, ModuleEvent::DnsLeakDetected { .. }));
}

#[tokio::test]
async fn test_leak_detector_no_event_for_unknown_server() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();
    let mut known = HashSet::new();
    known.insert("8.8.8.8".parse().unwrap());

    let detector = DnsLeakDetector::new(event_bus, known);

    // 192.168.1.1 is NOT in known set, so no event should be published
    detector.detect_leak("192.168.1.1".parse().unwrap(), "eth0").await;

    // The receiver should have no events available
    assert!(receiver.try_recv().is_err());
}

#[tokio::test]
async fn test_leak_detector_event_details() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();
    let mut known = HashSet::new();
    known.insert("8.8.8.8".parse().unwrap());

    let detector = DnsLeakDetector::new(event_bus, known);

    detector.detect_leak("8.8.8.8".parse().unwrap(), "wlan0").await;

    let event = receiver.recv().await.unwrap();
    match event {
        ModuleEvent::DnsLeakDetected { dns_server, interface } => {
            assert_eq!(dns_server, "8.8.8.8");
            assert_eq!(interface, "wlan0");
        }
        _ => panic!("Expected DnsLeakDetected event"),
    }
}
