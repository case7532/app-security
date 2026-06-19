use serde::{Deserialize, Serialize};

/// Configuration for the firewall module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    /// Whether the firewall module is enabled.
    pub enabled: bool,
    /// Default action for unmatched traffic.
    pub default_action: FirewallAction,
    /// Whether to log blocked traffic.
    pub log_blocked: bool,
    /// Rules to apply on startup.
    pub rules: Vec<FirewallRuleConfig>,
}

/// A firewall rule configuration entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleConfig {
    /// Unique identifier for this rule.
    pub id: String,
    /// Action to take (allow, block, reject).
    pub action: String,
    /// Direction (inbound, outbound, both).
    pub direction: String,
    /// Source IP or CIDR range.
    pub src_ip: Option<String>,
    /// Destination IP or CIDR range.
    pub dst_ip: Option<String>,
    /// Destination port.
    pub dst_port: Option<u16>,
    /// Protocol (tcp, udp, icmp).
    pub protocol: Option<String>,
    /// Human-readable description.
    pub description: String,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_action: FirewallAction::Block,
            log_blocked: true,
            rules: Vec::new(),
        }
    }
}

/// Action to take for unmatched traffic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FirewallAction {
    Allow,
    Block,
}

impl FirewallConfig {
    /// Load configuration from a TOML file.
    pub fn load(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        toml::from_str(&content).map_err(|e| e.to_string())
    }

    /// Save configuration to a TOML file.
    pub fn save(&self, path: &str) -> Result<(), String> {
        let content = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, content).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = FirewallConfig::default();
        assert!(config.enabled);
        assert_eq!(config.default_action, FirewallAction::Block);
        assert!(config.log_blocked);
        assert!(config.rules.is_empty());
    }

    #[test]
    fn test_config_serialization() {
        let config = FirewallConfig {
            enabled: true,
            default_action: FirewallAction::Block,
            log_blocked: false,
            rules: vec![FirewallRuleConfig {
                id: "test-rule".to_string(),
                action: "allow".to_string(),
                direction: "inbound".to_string(),
                src_ip: Some("192.168.1.0/24".to_string()),
                dst_ip: None,
                dst_port: Some(443),
                protocol: Some("tcp".to_string()),
                description: "Allow HTTPS".to_string(),
            }],
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: FirewallConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.enabled, deserialized.enabled);
        assert_eq!(config.default_action, deserialized.default_action);
        assert_eq!(config.rules.len(), deserialized.rules.len());
        assert_eq!(config.rules[0].id, deserialized.rules[0].id);
    }
}
