pub mod platform;

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::core::event_bus::EventBus;
use crate::core::mod_trait::{ModuleConfig, ModuleEvent, ModuleStatus, SecurityModule};
use crate::platform::{FirewallAction, FirewallRule, Platform};

pub struct KillSwitchModule {
    event_bus: EventBus,
    platform: Arc<RwLock<Box<dyn Platform>>>,
    status: ModuleStatus,
    active: bool,
    saved_rules: Vec<FirewallRule>,
}

impl KillSwitchModule {
    pub fn new(event_bus: EventBus, platform: Box<dyn Platform>) -> Self {
        Self {
            event_bus,
            platform: Arc::new(RwLock::new(platform)),
            status: ModuleStatus::Created,
            active: false,
            saved_rules: Vec::new(),
        }
    }

    pub async fn is_active(&self) -> bool {
        self.active
    }

    pub async fn get_firewall_rules(&self) -> Vec<FirewallRule> {
        self.saved_rules.clone()
    }

    async fn activate(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.active {
            return Ok(());
        }

        let block_rule = FirewallRule {
            id: "killswitch-block".to_string(),
            action: FirewallAction::Block,
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            protocol: None,
            description: "Kill switch - block all traffic".to_string(),
        };

        {
            let mut platform = self.platform.write().await;
            platform.add_firewall_rule(block_rule.clone()).await
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        }

        self.saved_rules.push(block_rule);
        self.active = true;

        Ok(())
    }

    async fn deactivate(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.active {
            return Ok(());
        }

        {
            let mut platform = self.platform.write().await;
            platform.remove_firewall_rule("killswitch-block").await
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        }

        self.saved_rules.clear();
        self.active = false;

        Ok(())
    }
}

#[async_trait]
impl SecurityModule for KillSwitchModule {
    fn id(&self) -> &str {
        "killswitch"
    }

    fn name(&self) -> &str {
        "Kill Switch"
    }

    fn priority(&self) -> u32 {
        2
    }

    fn dependencies(&self) -> Vec<&str> {
        vec!["vpn"]
    }

    async fn initialize(
        &mut self,
        _config: &ModuleConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Initialized;
        Ok(())
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Running;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Ensure firewall rules are cleaned up on stop
        self.deactivate().await?;
        self.status = ModuleStatus::Stopped;
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    async fn on_event(&mut self, event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> {
        match event {
            ModuleEvent::VpnDisconnected { .. } => {
                self.activate().await?;
                let _ = self.event_bus.publish(ModuleEvent::ModuleStarted {
                    module_id: "killswitch".to_string(),
                });
            }
            ModuleEvent::VpnConnected { .. } => {
                self.deactivate().await?;
            }
            _ => {}
        }
        Ok(())
    }
}
