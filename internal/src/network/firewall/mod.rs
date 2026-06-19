pub mod config;
pub mod platform;
pub mod rules;

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::core::event_bus::EventBus;
use crate::core::mod_trait::{ModuleConfig, ModuleEvent, ModuleStatus, SecurityModule};

use config::FirewallConfig;
use platform::FirewallPlatform;
use rules::{FirewallAction, FirewallDirection, FirewallError, FirewallRule};

/// Events specific to the firewall module.
#[derive(Debug, Clone)]
pub enum FirewallEvent {
    /// A rule was added to the firewall.
    RuleAdded { rule_id: String, description: String },
    /// A rule was removed from the firewall.
    RuleRemoved { rule_id: String },
    /// Traffic was blocked by a rule.
    RuleBlocked { src_ip: String, dst_port: u16 },
}

impl From<FirewallEvent> for ModuleEvent {
    fn from(event: FirewallEvent) -> Self {
        match event {
            FirewallEvent::RuleAdded { rule_id, description } => {
                ModuleEvent::FirewallRuleAdded { rule_id, description }
            }
            FirewallEvent::RuleRemoved { rule_id } => {
                ModuleEvent::FirewallRuleRemoved { rule_id }
            }
            FirewallEvent::RuleBlocked { src_ip, dst_port } => {
                ModuleEvent::FirewallRuleBlocked { src_ip, dst_port }
            }
        }
    }
}

/// Firewall module for managing system firewall rules.
pub struct FirewallModule {
    event_bus: EventBus,
    platform: Arc<dyn FirewallPlatform>,
    status: ModuleStatus,
    active_rules: Arc<RwLock<Vec<FirewallRule>>>,
    config: Option<FirewallConfig>,
}

impl FirewallModule {
    /// Create a new FirewallModule with the given platform implementation.
    pub fn new(event_bus: EventBus, platform: Arc<dyn FirewallPlatform>) -> Self {
        Self {
            event_bus,
            platform,
            status: ModuleStatus::Created,
            active_rules: Arc::new(RwLock::new(Vec::new())),
            config: None,
        }
    }

    /// Add a firewall rule.
    pub async fn add_rule(&self, rule: FirewallRule) -> Result<(), FirewallError> {
        // Check if rule already exists
        if self.platform.check_rule_exists(&rule.id).await? {
            return Err(FirewallError::RuleAlreadyExists(rule.id.clone()));
        }

        // Add rule to platform
        self.platform.add_rule(&rule).await?;

        // Track in active rules
        {
            let mut rules = self.active_rules.write().await;
            rules.push(rule.clone());
        }

        // Emit event
        let event = FirewallEvent::RuleAdded {
            rule_id: rule.id.clone(),
            description: rule.description.clone(),
        };
        let _ = self.event_bus.publish(event.into());

        Ok(())
    }

    /// Remove a firewall rule by ID.
    pub async fn remove_rule(&self, rule_id: &str) -> Result<(), FirewallError> {
        // Remove from platform
        self.platform.remove_rule(rule_id).await?;

        // Remove from active rules
        {
            let mut rules = self.active_rules.write().await;
            rules.retain(|r| r.id != rule_id);
        }

        // Emit event
        let event = FirewallEvent::RuleRemoved {
            rule_id: rule_id.to_string(),
        };
        let _ = self.event_bus.publish(event.into());

        Ok(())
    }

    /// List all active firewall rules.
    pub async fn list_rules(&self) -> Result<Vec<FirewallRule>, FirewallError> {
        self.platform.list_rules().await
    }

    /// Flush all firewall rules.
    pub async fn flush_rules(&self) -> Result<(), FirewallError> {
        self.platform.flush_rules().await?;

        // Clear active rules
        {
            let mut rules = self.active_rules.write().await;
            rules.clear();
        }

        Ok(())
    }

    /// Get the count of active rules.
    pub async fn rule_count(&self) -> usize {
        self.active_rules.read().await.len()
    }

    /// Load and apply configuration rules.
    pub async fn load_config(&mut self, config: FirewallConfig) -> Result<(), Box<dyn std::error::Error>> {
        self.config = Some(config.clone());

        // Apply configured rules
        for rule_config in &config.rules {
            let action = match rule_config.action.as_str() {
                "allow" => FirewallAction::Allow,
                "block" => FirewallAction::Block,
                "reject" => FirewallAction::Reject,
                _ => continue,
            };

            let direction = match rule_config.direction.as_str() {
                "inbound" => FirewallDirection::Inbound,
                "outbound" => FirewallDirection::Outbound,
                "both" => FirewallDirection::Both,
                _ => continue,
            };

            let rule = FirewallRule {
                id: rule_config.id.clone(),
                action,
                direction,
                src_ip: rule_config.src_ip.clone(),
                dst_ip: rule_config.dst_ip.clone(),
                dst_port: rule_config.dst_port,
                protocol: rule_config.protocol.clone(),
                description: rule_config.description.clone(),
            };

            if let Err(e) = self.add_rule(rule).await {
                eprintln!("Failed to add rule {}: {}", rule_config.id, e);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl SecurityModule for FirewallModule {
    fn id(&self) -> &str {
        "firewall"
    }

    fn name(&self) -> &str {
        "Firewall Module"
    }

    fn priority(&self) -> u32 {
        5
    }

    fn dependencies(&self) -> Vec<&str> {
        vec![]
    }

    async fn initialize(&mut self, _config: &ModuleConfig) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Initialized;
        Ok(())
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Running;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Flush all rules on stop
        self.flush_rules().await?;
        self.status = ModuleStatus::Stopped;
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    async fn on_event(&mut self, _event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> {
        // Firewall module doesn't react to other module events
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform::MockFirewallPlatform;

    fn setup() -> (EventBus, Arc<MockFirewallPlatform>) {
        let event_bus = EventBus::new(32);
        let platform = Arc::new(MockFirewallPlatform::new());
        (event_bus, platform)
    }

    #[tokio::test]
    async fn test_firewall_module_creation() {
        let (event_bus, platform) = setup();
        let module = FirewallModule::new(event_bus, platform);

        assert_eq!(module.id(), "firewall");
        assert_eq!(module.name(), "Firewall Module");
        assert_eq!(module.priority(), 5);
        assert!(module.dependencies().is_empty());
        assert_eq!(module.rule_count().await, 0);
    }

    #[tokio::test]
    async fn test_firewall_module_lifecycle() {
        let (event_bus, platform) = setup();
        let mut module = FirewallModule::new(event_bus, platform);

        assert_eq!(module.status(), ModuleStatus::Created);

        module.initialize(&ModuleConfig::default()).await.unwrap();
        assert_eq!(module.status(), ModuleStatus::Initialized);

        module.start().await.unwrap();
        assert_eq!(module.status(), ModuleStatus::Running);

        module.stop().await.unwrap();
        assert_eq!(module.status(), ModuleStatus::Stopped);
    }

    #[tokio::test]
    async fn test_add_rule() {
        let (event_bus, platform) = setup();
        let module = FirewallModule::new(event_bus, platform);

        let rule = FirewallRule {
            id: "test-rule".to_string(),
            action: FirewallAction::Allow,
            direction: FirewallDirection::Inbound,
            src_ip: None,
            dst_ip: None,
            dst_port: Some(443),
            protocol: Some("tcp".to_string()),
            description: "Allow HTTPS".to_string(),
        };

        assert!(module.add_rule(rule).await.is_ok());
        assert_eq!(module.rule_count().await, 1);
    }

    #[tokio::test]
    async fn test_add_duplicate_rule() {
        let (event_bus, platform) = setup();
        let module = FirewallModule::new(event_bus, platform);

        let rule = FirewallRule {
            id: "dup".to_string(),
            action: FirewallAction::Allow,
            direction: FirewallDirection::Inbound,
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            protocol: None,
            description: "Duplicate".to_string(),
        };

        assert!(module.add_rule(rule.clone()).await.is_ok());
        let err = module.add_rule(rule).await.unwrap_err();
        assert!(matches!(err, FirewallError::RuleAlreadyExists(_)));
    }

    #[tokio::test]
    async fn test_remove_rule() {
        let (event_bus, platform) = setup();
        let module = FirewallModule::new(event_bus, platform);

        let rule = FirewallRule {
            id: "removable".to_string(),
            action: FirewallAction::Block,
            direction: FirewallDirection::Outbound,
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            protocol: None,
            description: "Remove me".to_string(),
        };

        module.add_rule(rule).await.unwrap();
        assert_eq!(module.rule_count().await, 1);

        module.remove_rule("removable").await.unwrap();
        assert_eq!(module.rule_count().await, 0);
    }

    #[tokio::test]
    async fn test_remove_nonexistent_rule() {
        let (event_bus, platform) = setup();
        let module = FirewallModule::new(event_bus, platform);

        let err = module.remove_rule("ghost").await.unwrap_err();
        assert!(matches!(err, FirewallError::RuleNotFound(_)));
    }

    #[tokio::test]
    async fn test_flush_rules() {
        let (event_bus, platform) = setup();
        let module = FirewallModule::new(event_bus, platform);

        for i in 0..3 {
            let rule = FirewallRule {
                id: format!("rule-{}", i),
                action: FirewallAction::Allow,
                direction: FirewallDirection::Inbound,
                src_ip: None,
                dst_ip: None,
                dst_port: None,
                protocol: None,
                description: format!("Rule {}", i),
            };
            module.add_rule(rule).await.unwrap();
        }
        assert_eq!(module.rule_count().await, 3);

        module.flush_rules().await.unwrap();
        assert_eq!(module.rule_count().await, 0);
    }

    #[tokio::test]
    async fn test_list_rules() {
        let (event_bus, platform) = setup();
        let module = FirewallModule::new(event_bus, platform);

        let rule = FirewallRule {
            id: "listed".to_string(),
            action: FirewallAction::Reject,
            direction: FirewallDirection::Both,
            src_ip: Some("10.0.0.0/8".to_string()),
            dst_ip: None,
            dst_port: None,
            protocol: None,
            description: "Listed rule".to_string(),
        };

        module.add_rule(rule).await.unwrap();
        let rules = module.list_rules().await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "listed");
    }

    #[tokio::test]
    async fn test_stop_flushes_rules() {
        let (event_bus, platform) = setup();
        let mut module = FirewallModule::new(event_bus, platform);

        let rule = FirewallRule {
            id: "cleanup".to_string(),
            action: FirewallAction::Block,
            direction: FirewallDirection::Inbound,
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            protocol: None,
            description: "Cleanup test".to_string(),
        };

        module.add_rule(rule).await.unwrap();
        module.start().await.unwrap();
        assert_eq!(module.rule_count().await, 1);

        module.stop().await.unwrap();
        assert_eq!(module.rule_count().await, 0);
    }

    #[tokio::test]
    async fn test_on_event_is_noop() {
        let (event_bus, platform) = setup();
        let mut module = FirewallModule::new(event_bus, platform);

        let event = ModuleEvent::VpnConnected {
            server: "test".to_string(),
            ip: "1.2.3.4".to_string(),
        };
        assert!(module.on_event(&event).await.is_ok());
    }
}
