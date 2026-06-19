use app_security::core::manager::ModuleManager;
use app_security::core::mod_trait::{ModuleConfig, ModuleStatus, SecurityModule, ModuleEvent};
use app_security::core::event_bus::EventBus;
use async_trait::async_trait;

struct TestModule {
    id: String,
    status: ModuleStatus,
    started: bool,
}

impl TestModule {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            status: ModuleStatus::Created,
            started: false,
        }
    }
}

#[async_trait]
impl SecurityModule for TestModule {
    fn id(&self) -> &str { &self.id }
    fn name(&self) -> &str { "Test Module" }
    fn priority(&self) -> u32 { 10 }
    fn dependencies(&self) -> Vec<&str> { vec![] }

    async fn initialize(&mut self, _config: &ModuleConfig) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Initialized;
        Ok(())
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Running;
        self.started = true;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Stopped;
        self.started = false;
        Ok(())
    }

    fn status(&self) -> ModuleStatus { self.status.clone() }

    async fn on_event(&mut self, _event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
}

#[tokio::test]
async fn test_manager_register_module() {
    let event_bus = EventBus::new(100);
    let mut manager = ModuleManager::new(event_bus);

    let module = Box::new(TestModule::new("test1"));
    manager.register_module(module).await.unwrap();

    let modules = manager.get_module_ids().await;
    assert!(modules.contains(&"test1".to_string()));
}

#[tokio::test]
async fn test_manager_start_module() {
    let event_bus = EventBus::new(100);
    let mut manager = ModuleManager::new(event_bus);

    let module = Box::new(TestModule::new("test1"));
    manager.register_module(module).await.unwrap();

    manager.start_module("test1").await.unwrap();

    let status = manager.get_module_status("test1").await.unwrap();
    assert_eq!(status, ModuleStatus::Running);
}

#[tokio::test]
async fn test_manager_start_all() {
    let event_bus = EventBus::new(100);
    let mut manager = ModuleManager::new(event_bus);

    manager.register_module(Box::new(TestModule::new("mod1"))).await.unwrap();
    manager.register_module(Box::new(TestModule::new("mod2"))).await.unwrap();

    manager.start_all().await.unwrap();

    assert_eq!(manager.get_module_status("mod1").await.unwrap(), ModuleStatus::Running);
    assert_eq!(manager.get_module_status("mod2").await.unwrap(), ModuleStatus::Running);
}
