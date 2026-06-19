mod common;

use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::{ModuleConfig, SecurityModule, ModuleEvent};
use app_security::network::vpn::VpnModule;
use app_security::network::killswitch::KillSwitchModule;
use common::mock_platform::MockPlatform;

/// Helper: drain all pending events from the receiver and return them.
async fn drain_events(receiver: &mut tokio::sync::broadcast::Receiver<ModuleEvent>) -> Vec<ModuleEvent> {
    let mut events = Vec::new();
    loop {
        match receiver.try_recv() {
            Ok(event) => events.push(event),
            Err(_) => break,
        }
    }
    events
}

/// Test that a VPN disconnect event causes the KillSwitchModule to activate.
///
/// In the current architecture, the ModuleManager publishes events via the
/// EventBus but does not auto-dispatch them to other modules. This test
/// simulates the full event-driven flow by:
/// 1. Starting both modules
/// 2. Connecting the VPN (which publishes VpnConnected)
/// 3. Disconnecting the VPN (which publishes VpnDisconnected)
/// 4. Draining the event bus and forwarding the VpnDisconnected event
///    to the KillSwitchModule (as an event dispatcher would)
/// 5. Verifying the killswitch activated
#[tokio::test]
async fn test_vpn_disconnect_triggers_killswitch() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();

    // Create modules
    let mut vpn = VpnModule::new(event_bus.clone(), Box::new(MockPlatform::new()));
    let mut killswitch = KillSwitchModule::new(event_bus.clone(), Box::new(MockPlatform::new()));

    // Initialize and start
    vpn.initialize(&ModuleConfig::default()).await.unwrap();
    killswitch.initialize(&ModuleConfig::default()).await.unwrap();

    vpn.start().await.unwrap();
    killswitch.start().await.unwrap();

    // Connect VPN -- publishes VpnConnected event
    vpn.connect("10.0.0.1", "test-key").await.unwrap();
    assert!(vpn.is_connected().await);

    // Drain the VpnConnected event so it doesn't interfere
    drain_events(&mut receiver).await;

    // Disconnect VPN -- publishes VpnDisconnected event
    vpn.disconnect().await.unwrap();
    assert!(!vpn.is_connected().await);

    // Receive the VpnDisconnected event from the bus
    let events = drain_events(&mut receiver).await;
    assert!(!events.is_empty(), "Expected at least one event after disconnect");

    let disconnect_event = events.into_iter().find(|e| matches!(e, ModuleEvent::VpnDisconnected { .. }))
        .expect("Expected a VpnDisconnected event");

    // Forward the event to the killswitch module (simulating an event dispatcher)
    killswitch.on_event(&disconnect_event).await.unwrap();

    // Verify killswitch activated
    assert!(killswitch.is_active().await, "KillSwitch should be active after VPN disconnect");

    // Verify the event variant
    if let ModuleEvent::VpnDisconnected { ref reason } = disconnect_event {
        assert_eq!(reason, "User disconnect");
    } else {
        panic!("Expected VpnDisconnected event variant");
    }
}

/// Test that reconnecting VPN deactivates the killswitch.
#[tokio::test]
async fn test_vpn_reconnect_deactivates_killswitch() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();

    let mut vpn = VpnModule::new(event_bus.clone(), Box::new(MockPlatform::new()));
    let mut killswitch = KillSwitchModule::new(event_bus.clone(), Box::new(MockPlatform::new()));

    vpn.initialize(&ModuleConfig::default()).await.unwrap();
    killswitch.initialize(&ModuleConfig::default()).await.unwrap();
    vpn.start().await.unwrap();
    killswitch.start().await.unwrap();

    // Connect VPN -- drain the VpnConnected event
    vpn.connect("10.0.0.1", "test-key").await.unwrap();
    drain_events(&mut receiver).await;

    // Disconnect -- triggers killswitch
    vpn.disconnect().await.unwrap();
    let events = drain_events(&mut receiver).await;
    let disconnect_event = events.into_iter().find(|e| matches!(e, ModuleEvent::VpnDisconnected { .. }))
        .expect("Expected a VpnDisconnected event");
    killswitch.on_event(&disconnect_event).await.unwrap();
    assert!(killswitch.is_active().await);

    // Reconnect VPN -- publishes VpnConnected event
    vpn.connect("10.0.0.2", "test-key-2").await.unwrap();

    // Receive the VpnConnected event and forward it
    let events = drain_events(&mut receiver).await;
    let connect_event = events.into_iter().find(|e| matches!(e, ModuleEvent::VpnConnected { .. }))
        .expect("Expected a VpnConnected event");
    killswitch.on_event(&connect_event).await.unwrap();

    // Verify killswitch deactivated
    assert!(!killswitch.is_active().await, "KillSwitch should deactivate after VPN reconnect");
}

/// Test that the killswitch does not activate on unrelated events.
#[tokio::test]
async fn test_killswitch_ignores_unrelated_events() {
    let event_bus = EventBus::new(100);
    let mut killswitch = KillSwitchModule::new(event_bus.clone(), Box::new(MockPlatform::new()));

    killswitch.initialize(&ModuleConfig::default()).await.unwrap();
    killswitch.start().await.unwrap();

    // Send an unrelated event
    let event = ModuleEvent::ArpSpoofDetected {
        attacker_mac: "aa:bb:cc:dd:ee:ff".to_string(),
        victim_ip: "192.168.1.1".to_string(),
    };
    killswitch.on_event(&event).await.unwrap();

    // Killswitch should not be active
    assert!(!killswitch.is_active().await, "KillSwitch should not activate on unrelated events");
}

/// Test the full round-trip: VPN connects -> disconnects -> killswitch activates,
/// verifying firewall rules are applied on the mock platform.
#[tokio::test]
async fn test_killswitch_applies_firewall_rules_on_disconnect() {
    let event_bus = EventBus::new(100);

    let mock_platform = Box::new(MockPlatform::new());
    let mut vpn = VpnModule::new(event_bus.clone(), mock_platform);

    let killswitch_platform = Box::new(MockPlatform::new());
    let mut killswitch = KillSwitchModule::new(event_bus.clone(), killswitch_platform);

    vpn.initialize(&ModuleConfig::default()).await.unwrap();
    killswitch.initialize(&ModuleConfig::default()).await.unwrap();
    vpn.start().await.unwrap();
    killswitch.start().await.unwrap();

    // Connect and disconnect VPN
    vpn.connect("10.0.0.1", "test-key").await.unwrap();
    vpn.disconnect().await.unwrap();

    // Forward the disconnect event to killswitch (constructed directly)
    let disconnect_event = ModuleEvent::VpnDisconnected {
        reason: "Test disconnect".to_string(),
    };
    killswitch.on_event(&disconnect_event).await.unwrap();

    // Verify killswitch is active and has firewall rules
    assert!(killswitch.is_active().await);
    let rules = killswitch.get_firewall_rules().await;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, "killswitch-block");
    assert_eq!(rules[0].action, app_security::platform::FirewallAction::Block);
}
