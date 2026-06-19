use app_security::core::manager::ModuleManager;
use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::{ModuleConfig, ModuleStatus, SecurityModule, ModuleEvent};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

struct MockModule {
    id: String,
    events_received: Arc<RwLock<Vec<ModuleEvent>>>,
}

impl MockModule {
    fn new(id: &str) -> (Self, Arc<RwLock<Vec<ModuleEvent>>>) {
        let events = Arc::new(RwLock::new(Vec::new()));
        (Self {
            id: id.to_string(),
            events_received: events.clone(),
        }, events)
    }
}

#[async_trait]
impl SecurityModule for MockModule {
    fn id(&self) -> &str { &self.id }
    fn name(&self) -> &str { "Mock" }
    fn priority(&self) -> u32 { 10 }
    fn dependencies(&self) -> Vec<&str> { vec![] }
    async fn initialize(&mut self, _config: &ModuleConfig) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
    fn status(&self) -> ModuleStatus { ModuleStatus::Running }
    async fn on_event(&mut self, event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> {
        self.events_received.write().await.push(event.clone());
        Ok(())
    }
}

#[tokio::test]
async fn test_event_dispatch_forwards_to_modules() {
    let event_bus = EventBus::new(100);
    let mut manager = ModuleManager::new(event_bus.clone());

    let (module1, events1) = MockModule::new("mod1");
    let (module2, events2) = MockModule::new("mod2");

    manager.register_module(Box::new(module1)).await.unwrap();
    manager.register_module(Box::new(module2)).await.unwrap();

    manager.start_all().await.unwrap();
    manager.start_event_dispatch().await;

    // Publish event
    let event = ModuleEvent::ModuleStarted { module_id: "test".to_string() };
    event_bus.publish(event.clone()).unwrap();

    // Wait for dispatch
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Verify both modules received the event
    let received1 = events1.read().await;
    let received2 = events2.read().await;

    assert_eq!(received1.len(), 1);
    assert_eq!(received2.len(), 1);
    assert!(matches!(&received1[0], ModuleEvent::ModuleStarted { .. }));
    assert!(matches!(&received2[0], ModuleEvent::ModuleStarted { .. }));
}
