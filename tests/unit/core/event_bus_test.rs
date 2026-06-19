use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::ModuleEvent;

#[tokio::test]
async fn test_event_publish_subscribe() {
    let bus = EventBus::new(10);
    let mut receiver = bus.subscribe();

    let event = ModuleEvent::ModuleStarted {
        module_id: "test".to_string(),
    };

    bus.publish(event.clone()).unwrap();

    let received = receiver.recv().await.unwrap();
    assert_eq!(format!("{:?}", received), format!("{:?}", event));
}

#[tokio::test]
async fn test_multiple_subscribers() {
    let bus = EventBus::new(10);
    let mut receiver1 = bus.subscribe();
    let mut receiver2 = bus.subscribe();

    let event = ModuleEvent::VpnConnected {
        server: "test".to_string(),
        ip: "10.0.0.1".to_string(),
    };

    bus.publish(event).unwrap();

    let received1 = receiver1.recv().await.unwrap();
    let received2 = receiver2.recv().await.unwrap();

    assert_eq!(format!("{:?}", received1), format!("{:?}", received2));
}
