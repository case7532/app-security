use app_security::core::toposort::topological_sort;
use app_security::core::manager::ModuleManager;
use app_security::core::mod_trait::{ModuleConfig, ModuleStatus, SecurityModule, ModuleEvent};
use app_security::core::event_bus::EventBus;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[test]
fn test_topological_sort_no_dependencies() {
    let mut deps: HashMap<String, Vec<String>> = HashMap::new();
    deps.insert("a".to_string(), vec![]);
    deps.insert("b".to_string(), vec![]);
    deps.insert("c".to_string(), vec![]);

    let order = topological_sort(&deps).unwrap();
    assert_eq!(order.len(), 3);
    assert!(order.contains(&"a".to_string()));
    assert!(order.contains(&"b".to_string()));
    assert!(order.contains(&"c".to_string()));
}

#[test]
fn test_topological_sort_with_dependencies() {
    let mut deps: HashMap<String, Vec<String>> = HashMap::new();
    deps.insert("vpn".to_string(), vec![]);
    deps.insert("killswitch".to_string(), vec!["vpn".to_string()]);
    deps.insert("arp".to_string(), vec![]);

    let order = topological_sort(&deps).unwrap();

    let vpn_pos = order.iter().position(|x| x == "vpn").unwrap();
    let ks_pos = order.iter().position(|x| x == "killswitch").unwrap();
    assert!(vpn_pos < ks_pos);
}

#[test]
fn test_topological_sort_circular_dependency() {
    let mut deps: HashMap<String, Vec<String>> = HashMap::new();
    deps.insert("a".to_string(), vec!["b".to_string()]);
    deps.insert("b".to_string(), vec!["a".to_string()]);

    let result = topological_sort(&deps);
    assert!(result.is_err());
}

// -- Integration test: ModuleManager::start_all() respects dependencies --

struct OrderedModule {
    id: String,
    deps: Vec<String>,
    status: ModuleStatus,
    start_order: Arc<RwLock<Vec<String>>>,
}

#[async_trait]
impl SecurityModule for OrderedModule {
    fn id(&self) -> &str { &self.id }
    fn name(&self) -> &str { &self.id }
    fn priority(&self) -> u32 { 10 }
    fn dependencies(&self) -> Vec<&str> {
        self.deps.iter().map(|s| s.as_str()).collect()
    }
    async fn initialize(&mut self, _config: &ModuleConfig) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Initialized;
        Ok(())
    }
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.start_order.write().await.push(self.id.clone());
        self.status = ModuleStatus::Running;
        Ok(())
    }
    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Stopped;
        Ok(())
    }
    fn status(&self) -> ModuleStatus { self.status.clone() }
    async fn on_event(&mut self, _event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
}

#[tokio::test]
async fn test_start_all_respects_dependency_order() {
    let event_bus = EventBus::new(100);
    let mut manager = ModuleManager::new(event_bus);
    let start_order: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(Vec::new()));

    // killswitch depends on vpn, so vpn must start first.
    manager.register_module(Box::new(OrderedModule {
        id: "killswitch".to_string(),
        deps: vec!["vpn".to_string()],
        status: ModuleStatus::Created,
        start_order: start_order.clone(),
    })).await.unwrap();

    manager.register_module(Box::new(OrderedModule {
        id: "vpn".to_string(),
        deps: vec![],
        status: ModuleStatus::Created,
        start_order: start_order.clone(),
    })).await.unwrap();

    manager.register_module(Box::new(OrderedModule {
        id: "arp".to_string(),
        deps: vec![],
        status: ModuleStatus::Created,
        start_order: start_order.clone(),
    })).await.unwrap();

    manager.start_all().await.unwrap();

    let order = start_order.read().await;
    let vpn_pos = order.iter().position(|x| x == "vpn").unwrap();
    let ks_pos = order.iter().position(|x| x == "killswitch").unwrap();
    assert!(vpn_pos < ks_pos, "vpn (pos {}) must start before killswitch (pos {})", vpn_pos, ks_pos);
}
