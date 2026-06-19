use app_security::core::mod_trait::{ModuleConfig, ModuleStatus, ModuleEvent, SecurityModule};
use async_trait::async_trait;

struct MockModule {
    status: ModuleStatus,
}

impl MockModule {
    fn new() -> Self {
        Self {
            status: ModuleStatus::Created,
        }
    }
}

#[async_trait]
impl SecurityModule for MockModule {
    fn id(&self) -> &str { "mock" }
    fn name(&self) -> &str { "Mock Module" }
    fn priority(&self) -> u32 { 100 }
    fn dependencies(&self) -> Vec<&str> { vec![] }

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

    async fn on_event(&mut self, _event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

#[tokio::test]
async fn test_mock_module_lifecycle() {
    let mut module = MockModule::new();

    assert_eq!(module.status(), ModuleStatus::Created);
    assert_eq!(module.id(), "mock");

    module.initialize(&ModuleConfig::default()).await.unwrap();
    assert_eq!(module.status(), ModuleStatus::Initialized);

    module.start().await.unwrap();
    assert_eq!(module.status(), ModuleStatus::Running);

    module.stop().await.unwrap();
    assert_eq!(module.status(), ModuleStatus::Stopped);
}

#[tokio::test]
async fn test_module_event_handling() {
    let mut module = MockModule::new();
    module.initialize(&ModuleConfig::default()).await.unwrap();

    let event = ModuleEvent::VpnConnected {
        server: "test-server".to_string(),
        ip: "10.0.0.1".to_string(),
    };

    assert!(module.on_event(&event).await.is_ok());
}
