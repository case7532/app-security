use serde::{Deserialize, Serialize};

/// Direction of network traffic for firewall rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FirewallDirection {
    Inbound,
    Outbound,
    Both,
}

/// A firewall rule that can be applied across platforms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Unique identifier for this rule.
    pub id: String,
    /// Action to take when traffic matches this rule.
    pub action: FirewallAction,
    /// Direction this rule applies to.
    pub direction: FirewallDirection,
    /// Source IP address or CIDR range (None = any).
    pub src_ip: Option<String>,
    /// Destination IP address or CIDR range (None = any).
    pub dst_ip: Option<String>,
    /// Destination port (None = any).
    pub dst_port: Option<u16>,
    /// Protocol (tcp, udp, icmp, or None for any).
    pub protocol: Option<String>,
    /// Human-readable description.
    pub description: String,
}

/// Action to take when traffic matches a rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FirewallAction {
    Allow,
    Block,
    Reject,
}

/// Errors that can occur during firewall operations.
#[derive(Debug, Clone)]
pub enum FirewallError {
    /// Platform command execution failed.
    PlatformError(String),
    /// Rule with this ID already exists.
    RuleAlreadyExists(String),
    /// Rule with this ID was not found.
    RuleNotFound(String),
    /// Invalid rule configuration.
    InvalidRule(String),
    /// Firewall service is not available.
    ServiceUnavailable(String),
}

impl std::fmt::Display for FirewallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallError::PlatformError(msg) => write!(f, "Platform error: {}", msg),
            FirewallError::RuleAlreadyExists(id) => write!(f, "Rule already exists: {}", id),
            FirewallError::RuleNotFound(id) => write!(f, "Rule not found: {}", id),
            FirewallError::InvalidRule(msg) => write!(f, "Invalid rule: {}", msg),
            FirewallError::ServiceUnavailable(msg) => write!(f, "Service unavailable: {}", msg),
        }
    }
}

impl std::error::Error for FirewallError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firewall_rule_creation() {
        let rule = FirewallRule {
            id: "test-1".to_string(),
            action: FirewallAction::Allow,
            direction: FirewallDirection::Inbound,
            src_ip: Some("192.168.1.0/24".to_string()),
            dst_ip: None,
            dst_port: Some(443),
            protocol: Some("tcp".to_string()),
            description: "Allow HTTPS from LAN".to_string(),
        };

        assert_eq!(rule.id, "test-1");
        assert_eq!(rule.action, FirewallAction::Allow);
        assert_eq!(rule.direction, FirewallDirection::Inbound);
        assert!(rule.src_ip.is_some());
        assert!(rule.dst_ip.is_none());
        assert_eq!(rule.dst_port, Some(443));
    }

    #[test]
    fn test_firewall_action_equality() {
        assert_eq!(FirewallAction::Allow, FirewallAction::Allow);
        assert_ne!(FirewallAction::Allow, FirewallAction::Block);
        assert_ne!(FirewallAction::Block, FirewallAction::Reject);
    }

    #[test]
    fn test_firewall_direction_equality() {
        assert_eq!(FirewallDirection::Inbound, FirewallDirection::Inbound);
        assert_ne!(FirewallDirection::Inbound, FirewallDirection::Outbound);
        assert_ne!(FirewallDirection::Outbound, FirewallDirection::Both);
    }

    #[test]
    fn test_firewall_error_display() {
        let err = FirewallError::RuleNotFound("test-rule".to_string());
        assert_eq!(format!("{}", err), "Rule not found: test-rule");

        let err = FirewallError::PlatformError("pfctl failed".to_string());
        assert!(format!("{}", err).contains("pfctl failed"));
    }

    #[test]
    fn test_rule_serialization() {
        let rule = FirewallRule {
            id: "serialize-test".to_string(),
            action: FirewallAction::Block,
            direction: FirewallDirection::Outbound,
            src_ip: None,
            dst_ip: Some("10.0.0.0/8".to_string()),
            dst_port: Some(80),
            protocol: Some("tcp".to_string()),
            description: "Block outbound HTTP to internal".to_string(),
        };

        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: FirewallRule = serde_json::from_str(&json).unwrap();

        assert_eq!(rule.id, deserialized.id);
        assert_eq!(rule.action, deserialized.action);
        assert_eq!(rule.direction, deserialized.direction);
        assert_eq!(rule.dst_port, deserialized.dst_port);
    }
}
