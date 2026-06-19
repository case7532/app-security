// macOS pf (Packet Filter) firewall implementation.

use async_trait::async_trait;

use super::super::rules::{FirewallAction, FirewallDirection, FirewallError, FirewallRule};
use super::FirewallPlatform;

pub struct MacOSFirewall;

impl MacOSFirewall {
    pub fn new() -> Self {
        Self
    }

    /// Convert a FirewallRule to a pf rule string.
    fn rule_to_pf(&self, rule: &FirewallRule) -> Result<String, FirewallError> {
        let action = match rule.action {
            FirewallAction::Allow => "pass",
            FirewallAction::Block => "block",
            FirewallAction::Reject => "block return-rst",
        };

        let direction = match rule.direction {
            FirewallDirection::Inbound => "in",
            FirewallDirection::Outbound => "out",
            FirewallDirection::Both => "in out",
        };

        let mut parts = vec![action.to_string(), direction.to_string()];

        if let Some(ref proto) = rule.protocol {
            parts.push(format!("proto {}", proto));
        }

        if let Some(ref src) = rule.src_ip {
            parts.push(format!("from {}", src));
        } else {
            parts.push("from any".to_string());
        }

        if let Some(ref dst) = rule.dst_ip {
            parts.push(format!("to {}", dst));
        } else {
            parts.push("to any".to_string());
        }

        if let Some(port) = rule.dst_port {
            parts.push(format!("port {}", port));
        }

        // Add a comment with the rule ID for tracking
        parts.push(format!("tag {}", rule.id));

        Ok(parts.join(" "))
    }
}

impl Default for MacOSFirewall {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FirewallPlatform for MacOSFirewall {
    async fn add_rule(&self, rule: &FirewallRule) -> Result<(), FirewallError> {
        let pf_rule = self.rule_to_pf(rule)?;

        // Use std::process::Command for synchronous stdin write
        let output = std::process::Command::new("pfctl")
            .args(["-a", "com.apple/blockall", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(ref mut stdin) = child.stdin {
                    use std::io::Write;
                    stdin.write_all(pf_rule.as_bytes())?;
                }
                child.wait_with_output()
            })
            .map_err(|e| FirewallError::PlatformError(format!("Failed to execute pfctl: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::PlatformError(format!(
                "pfctl failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    async fn remove_rule(&self, rule_id: &str) -> Result<(), FirewallError> {
        // List current rules, find the one with matching tag, rebuild without it
        let rules = self.list_rules().await?;
        let filtered: Vec<&FirewallRule> = rules.iter().filter(|r| r.id != rule_id).collect();

        if filtered.len() == rules.len() {
            return Err(FirewallError::RuleNotFound(rule_id.to_string()));
        }

        // Flush and re-add remaining rules
        self.flush_rules().await?;
        for rule in &filtered {
            self.add_rule(rule).await?;
        }

        Ok(())
    }

    async fn list_rules(&self) -> Result<Vec<FirewallRule>, FirewallError> {
        // Parse pfctl output to get current rules
        let output = std::process::Command::new("pfctl")
            .args(["-sr", "-a", "com.apple/blockall"])
            .output()
            .map_err(|e| FirewallError::PlatformError(format!("Failed to execute pfctl: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::PlatformError(format!(
                "pfctl failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut rules = Vec::new();

        for line in stdout.lines() {
            if line.is_empty() {
                continue;
            }

            // Parse rule from pfctl output format
            // This is a simplified parser - production code would be more robust
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let action = match parts[0] {
                "pass" => FirewallAction::Allow,
                "block" => {
                    if line.contains("return-rst") {
                        FirewallAction::Reject
                    } else {
                        FirewallAction::Block
                    }
                }
                _ => continue,
            };

            let direction = if parts.contains(&"in") && parts.contains(&"out") {
                FirewallDirection::Both
            } else if parts.contains(&"in") {
                FirewallDirection::Inbound
            } else if parts.contains(&"out") {
                FirewallDirection::Outbound
            } else {
                FirewallDirection::Both
            };

            // Extract rule ID from tag
            let rule_id = parts
                .windows(2)
                .find(|w| w[0] == "tag")
                .map(|w| w[1].to_string())
                .unwrap_or_else(|| format!("rule-{}", rules.len()));

            rules.push(FirewallRule {
                id: rule_id,
                action,
                direction,
                src_ip: None,
                dst_ip: None,
                dst_port: None,
                protocol: None,
                description: line.to_string(),
            });
        }

        Ok(rules)
    }

    async fn flush_rules(&self) -> Result<(), FirewallError> {
        let output = std::process::Command::new("pfctl")
            .args(["-a", "com.apple/blockall", "-F", "all"])
            .output()
            .map_err(|e| FirewallError::PlatformError(format!("Failed to execute pfctl: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::PlatformError(format!(
                "pfctl failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    async fn check_rule_exists(&self, rule_id: &str) -> Result<bool, FirewallError> {
        let rules = self.list_rules().await?;
        Ok(rules.iter().any(|r| r.id == rule_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_to_pf_block_inbound() {
        let fw = MacOSFirewall::new();
        let rule = FirewallRule {
            id: "block-in".to_string(),
            action: FirewallAction::Block,
            direction: FirewallDirection::Inbound,
            src_ip: Some("10.0.0.0/8".to_string()),
            dst_ip: None,
            dst_port: Some(80),
            protocol: Some("tcp".to_string()),
            description: "Block inbound HTTP".to_string(),
        };

        let pf_rule = fw.rule_to_pf(&rule).unwrap();
        assert!(pf_rule.contains("block"));
        assert!(pf_rule.contains("in"));
        assert!(pf_rule.contains("proto tcp"));
        assert!(pf_rule.contains("from 10.0.0.0/8"));
        assert!(pf_rule.contains("port 80"));
        assert!(pf_rule.contains("tag block-in"));
    }

    #[test]
    fn test_rule_to_pf_allow_outbound() {
        let fw = MacOSFirewall::new();
        let rule = FirewallRule {
            id: "allow-out".to_string(),
            action: FirewallAction::Allow,
            direction: FirewallDirection::Outbound,
            src_ip: None,
            dst_ip: Some("192.168.1.0/24".to_string()),
            dst_port: Some(443),
            protocol: Some("tcp".to_string()),
            description: "Allow HTTPS to LAN".to_string(),
        };

        let pf_rule = fw.rule_to_pf(&rule).unwrap();
        assert!(pf_rule.contains("pass"));
        assert!(pf_rule.contains("out"));
        assert!(pf_rule.contains("from any"));
        assert!(pf_rule.contains("to 192.168.1.0/24"));
    }

    #[test]
    fn test_rule_to_pf_reject_both() {
        let fw = MacOSFirewall::new();
        let rule = FirewallRule {
            id: "reject-both".to_string(),
            action: FirewallAction::Reject,
            direction: FirewallDirection::Both,
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            protocol: None,
            description: "Reject all".to_string(),
        };

        let pf_rule = fw.rule_to_pf(&rule).unwrap();
        assert!(pf_rule.contains("block return-rst"));
        assert!(pf_rule.contains("in out"));
        assert!(pf_rule.contains("from any"));
        assert!(pf_rule.contains("to any"));
    }
}
