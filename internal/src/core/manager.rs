use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use super::mod_trait::{SecurityModule, ModuleConfig, ModuleStatus};
use super::event_bus::EventBus;

pub struct ModuleManager {
    modules: HashMap<String, Arc<RwLock<Box<dyn SecurityModule>>>>,
    event_bus: EventBus,
}

impl ModuleManager {
    pub fn new(event_bus: EventBus) -> Self {
        Self {
            modules: HashMap::new(),
            event_bus,
        }
    }

    pub async fn register_module(&mut self, module: Box<dyn SecurityModule>) -> Result<(), String> {
        let id = module.id().to_string();
        self.modules.insert(id, Arc::new(RwLock::new(module)));
        Ok(())
    }

    pub async fn start_module(&self, id: &str) -> Result<(), String> {
        let module = self.modules.get(id)
            .ok_or_else(|| format!("Module not found: {}", id))?;

        let mut module = module.write().await;

        if module.status() == ModuleStatus::Running {
            return Ok(());
        }

        module.initialize(&ModuleConfig::default()).await
            .map_err(|e| e.to_string())?;

        module.start().await
            .map_err(|e| e.to_string())?;

        self.event_bus.publish(super::mod_trait::ModuleEvent::ModuleStarted {
            module_id: id.to_string(),
        }).map_err(|e| e.to_string())?;

        Ok(())
    }

    pub async fn stop_module(&self, id: &str) -> Result<(), String> {
        let module = self.modules.get(id)
            .ok_or_else(|| format!("Module not found: {}", id))?;

        let mut module = module.write().await;

        if module.status() != ModuleStatus::Running {
            return Ok(());
        }

        module.stop().await
            .map_err(|e| e.to_string())?;

        self.event_bus.publish(super::mod_trait::ModuleEvent::ModuleStopped {
            module_id: id.to_string(),
        }).map_err(|e| e.to_string())?;

        Ok(())
    }

    pub async fn start_all(&self) -> Result<(), String> {
        let mut ids: Vec<String> = self.modules.keys().cloned().collect();
        ids.sort();

        for id in ids {
            self.start_module(&id).await?;
        }
        Ok(())
    }

    pub async fn stop_all(&self) -> Result<(), String> {
        for id in self.modules.keys() {
            self.stop_module(id).await?;
        }
        Ok(())
    }

    pub async fn get_module_status(&self, id: &str) -> Result<ModuleStatus, String> {
        let module = self.modules.get(id)
            .ok_or_else(|| format!("Module not found: {}", id))?;

        Ok(module.read().await.status())
    }

    pub async fn get_module_ids(&self) -> Vec<String> {
        self.modules.keys().cloned().collect()
    }

    /// Start event dispatch loop - forwards events to all modules
    pub async fn start_event_dispatch(&self) {
        let mut receiver = self.event_bus.subscribe();
        let modules = self.modules.clone();

        tokio::spawn(async move {
            while let Ok(event) = receiver.recv().await {
                for module in modules.values() {
                    let mut module = module.write().await;
                    let _ = module.on_event(&event).await;
                }
            }
        });
    }
}
