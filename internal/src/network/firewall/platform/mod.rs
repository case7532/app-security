pub mod macos;
pub mod linux;
pub mod windows;

use async_trait::async_trait;

use super::rules::{FirewallError, FirewallRule};

/// Platform-specific firewall operations.
#[async_trait]
pub trait FirewallPlatform: Send + Sync {
    /// Add a firewall rule.
    async fn add_rule(&self, rule: &FirewallRule) -> Result<(), FirewallError>;

    /// Remove a firewall rule by ID.
    async fn remove_rule(&self, rule_id: &str) -> Result<(), FirewallError>;

    /// List all active firewall rules.
    async fn list_rules(&self) -> Result<Vec<FirewallRule>, FirewallError>;

    /// Flush all firewall rules.
    async fn flush_rules(&self) -> Result<(), FirewallError>;

    /// Check if a rule with the given ID exists.
    async fn check_rule_exists(&self, rule_id: &str) -> Result<bool, FirewallError>;
}

/// Mock firewall platform for testing.
pub struct MockFirewallPlatform {
    rules: std::sync::Arc<tokio::sync::RwLock<Vec<FirewallRule>>>,
}

impl MockFirewallPlatform {
    pub fn new() -> Self {
        Self {
            rules: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }

    pub async fn get_rules(&self) -> Vec<FirewallRule> {
        self.rules.read().await.clone()
    }
}

impl Default for MockFirewallPlatform {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FirewallPlatform for MockFirewallPlatform {
    async fn add_rule(&self, rule: &FirewallRule) -> Result<(), FirewallError> {
        let mut rules = self.rules.write().await;
        if rules.iter().any(|r| r.id == rule.id) {
            return Err(FirewallError::RuleAlreadyExists(rule.id.clone()));
        }
        rules.push(rule.clone());
        Ok(())
    }

    async fn remove_rule(&self, rule_id: &str) -> Result<(), FirewallError> {
        let mut rules = self.rules.write().await;
        let len_before = rules.len();
        rules.retain(|r| r.id != rule_id);
        if rules.len() == len_before {
            return Err(FirewallError::RuleNotFound(rule_id.to_string()));
        }
        Ok(())
    }

    async fn list_rules(&self) -> Result<Vec<FirewallRule>, FirewallError> {
        Ok(self.rules.read().await.clone())
    }

    async fn flush_rules(&self) -> Result<(), FirewallError> {
        self.rules.write().await.clear();
        Ok(())
    }

    async fn check_rule_exists(&self, rule_id: &str) -> Result<bool, FirewallError> {
        Ok(self.rules.read().await.iter().any(|r| r.id == rule_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::rules::{FirewallAction, FirewallDirection};

    #[tokio::test]
    async fn test_mock_add_rule() {
        let mock = MockFirewallPlatform::new();
        let rule = FirewallRule {
            id: "test-1".to_string(),
            action: FirewallAction::Allow,
            direction: FirewallDirection::Inbound,
            src_ip: None,
            dst_ip: None,
            dst_port: Some(443),
            protocol: Some("tcp".to_string()),
            description: "Allow HTTPS".to_string(),
        };

        assert!(mock.add_rule(&rule).await.is_ok());
        let rules = mock.list_rules().await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "test-1");
    }

    #[tokio::test]
    async fn test_mock_duplicate_rule() {
        let mock = MockFirewallPlatform::new();
        let rule = FirewallRule {
            id: "dup".to_string(),
            action: FirewallAction::Block,
            direction: FirewallDirection::Both,
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            protocol: None,
            description: "Block all".to_string(),
        };

        assert!(mock.add_rule(&rule).await.is_ok());
        let err = mock.add_rule(&rule).await.unwrap_err();
        assert!(matches!(err, FirewallError::RuleAlreadyExists(_)));
    }

    #[tokio::test]
    async fn test_mock_remove_rule() {
        let mock = MockFirewallPlatform::new();
        let rule = FirewallRule {
            id: "removable".to_string(),
            action: FirewallAction::Block,
            direction: FirewallDirection::Inbound,
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            protocol: None,
            description: "Remove me".to_string(),
        };

        mock.add_rule(&rule).await.unwrap();
        assert!(mock.remove_rule("removable").await.is_ok());
        assert_eq!(mock.list_rules().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_mock_remove_nonexistent() {
        let mock = MockFirewallPlatform::new();
        let err = mock.remove_rule("ghost").await.unwrap_err();
        assert!(matches!(err, FirewallError::RuleNotFound(_)));
    }

    #[tokio::test]
    async fn test_mock_flush_rules() {
        let mock = MockFirewallPlatform::new();
        for i in 0..5 {
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
            mock.add_rule(&rule).await.unwrap();
        }
        assert_eq!(mock.list_rules().await.unwrap().len(), 5);

        mock.flush_rules().await.unwrap();
        assert_eq!(mock.list_rules().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_mock_check_rule_exists() {
        let mock = MockFirewallPlatform::new();
        assert!(!mock.check_rule_exists("nope").await.unwrap());

        let rule = FirewallRule {
            id: "exists".to_string(),
            action: FirewallAction::Allow,
            direction: FirewallDirection::Outbound,
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            protocol: None,
            description: "Exists".to_string(),
        };
        mock.add_rule(&rule).await.unwrap();
        assert!(mock.check_rule_exists("exists").await.unwrap());
    }
}
