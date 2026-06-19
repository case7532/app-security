// Windows netsh advfirewall firewall implementation.

use async_trait::async_trait;
use tokio::process::Command;

use super::super::rules::{FirewallAction, FirewallDirection, FirewallError, FirewallRule};
use super::FirewallPlatform;

pub struct WindowsFirewall;

impl WindowsFirewall {
    pub fn new() -> Self {
        Self
    }

    /// Convert a FirewallRule to netsh advfirewall command arguments.
    fn rule_to_netsh_args(&self, rule: &FirewallRule) -> Result<Vec<String>, FirewallError> {
        let dir = match rule.direction {
            FirewallDirection::Inbound => "in",
            FirewallDirection::Outbound => "out",
            FirewallDirection::Both => "in",  // netsh doesn't support both directly
        };

        let action = match rule.action {
            FirewallAction::Allow => "allow",
            FirewallAction::Block => "block",
            FirewallAction::Reject => "block",  // netsh uses block for reject too
        };

        let mut args = vec![
            "advfirewall".to_string(),
            "firewall".to_string(),
            "add".to_string(),
            "rule".to_string(),
            format!("name={}", rule.id),
            format!("dir={}", dir),
            format!("action={}", action),
        ];

        if let Some(ref proto) = rule.protocol {
            let protocol = match proto.to_lowercase().as_str() {
                "tcp" => "TCP",
                "udp" => "UDP",
                "icmp" => "ICMPv4",
                _ => proto,
            };
            args.push(format!("protocol={}", protocol));
        }

        if let Some(port) = rule.dst_port {
            args.push(format!("localport={}", port));
        }

        if let Some(ref src) = rule.src_ip {
            args.push(format!("remoteip={}", src));
        }

        if let Some(ref dst) = rule.dst_ip {
            args.push(format!("localip={}", dst));
        }

        Ok(args)
    }
}

impl Default for WindowsFirewall {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FirewallPlatform for WindowsFirewall {
    async fn add_rule(&self, rule: &FirewallRule) -> Result<(), FirewallError> {
        let args = self.rule_to_netsh_args(rule)?;

        let output = Command::new("netsh")
            .args(&args)
            .output()
            .await
            .map_err(|e| FirewallError::PlatformError(format!("Failed to execute netsh: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::PlatformError(format!(
                "netsh failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    async fn remove_rule(&self, rule_id: &str) -> Result<(), FirewallError> {
        let output = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={}", rule_id),
            ])
            .output()
            .await
            .map_err(|e| FirewallError::PlatformError(format!("Failed to execute netsh: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("No rules") || stderr.contains("not found") {
                return Err(FirewallError::RuleNotFound(rule_id.to_string()));
            }
            return Err(FirewallError::PlatformError(format!(
                "netsh failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    async fn list_rules(&self) -> Result<Vec<FirewallRule>, FirewallError> {
        let output = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "show",
                "rule",
                "name=all",
                "verbose",
            ])
            .output()
            .await
            .map_err(|e| FirewallError::PlatformError(format!("Failed to execute netsh: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::PlatformError(format!(
                "netsh failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut rules = Vec::new();
        let mut current_rule: Option<FirewallRule> = None;

        for line in stdout.lines() {
            let line = line.trim();

            if line.starts_with("Rule Name:") {
                if let Some(rule) = current_rule.take() {
                    rules.push(rule);
                }
                let name = line.strip_prefix("Rule Name:").unwrap_or("").trim();
                current_rule = Some(FirewallRule {
                    id: name.to_string(),
                    action: FirewallAction::Allow,
                    direction: FirewallDirection::Inbound,
                    src_ip: None,
                    dst_ip: None,
                    dst_port: None,
                    protocol: None,
                    description: name.to_string(),
                });
            } else if let Some(ref mut rule) = current_rule {
                if line.starts_with("Action:") {
                    rule.action = if line.contains("Allow") {
                        FirewallAction::Allow
                    } else {
                        FirewallAction::Block
                    };
                } else if line.starts_with("Direction:") {
                    rule.direction = if line.contains("In") {
                        FirewallDirection::Inbound
                    } else {
                        FirewallDirection::Outbound
                    };
                } else if line.starts_with("Protocol:") {
                    rule.protocol = line
                        .strip_prefix("Protocol:")
                        .map(|s| s.trim().to_string());
                } else if line.starts_with("LocalPort:") {
                    rule.dst_port = line
                        .strip_prefix("LocalPort:")
                        .and_then(|s| s.trim().parse().ok());
                } else if line.starts_with("RemoteIP:") {
                    let ip = line.strip_prefix("RemoteIP:").unwrap_or("").trim();
                    if ip != "Any" {
                        rule.src_ip = Some(ip.to_string());
                    }
                } else if line.starts_with("LocalIP:") {
                    let ip = line.strip_prefix("LocalIP:").unwrap_or("").trim();
                    if ip != "Any" {
                        rule.dst_ip = Some(ip.to_string());
                    }
                }
            }
        }

        if let Some(rule) = current_rule {
            rules.push(rule);
        }

        Ok(rules)
    }

    async fn flush_rules(&self) -> Result<(), FirewallError> {
        // netsh doesn't have a direct flush command
        // We need to delete rules one by one
        let rules = self.list_rules().await?;
        for rule in &rules {
            self.remove_rule(&rule.id).await?;
        }
        Ok(())
    }

    async fn check_rule_exists(&self, rule_id: &str) -> Result<bool, FirewallError> {
        let output = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "show",
                "rule",
                &format!("name={}", rule_id),
            ])
            .output()
            .await
            .map_err(|e| FirewallError::PlatformError(format!("Failed to execute netsh: {}", e)))?;

        Ok(output.status.success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_to_netsh_args_allow_inbound() {
        let fw = WindowsFirewall::new();
        let rule = FirewallRule {
            id: "allow-https".to_string(),
            action: FirewallAction::Allow,
            direction: FirewallDirection::Inbound,
            src_ip: Some("192.168.1.0/24".to_string()),
            dst_ip: None,
            dst_port: Some(443),
            protocol: Some("tcp".to_string()),
            description: "Allow HTTPS from LAN".to_string(),
        };

        let args = fw.rule_to_netsh_args(&rule).unwrap();
        assert!(args.contains(&"add".to_string()));
        assert!(args.contains(&"rule".to_string()));
        assert!(args.contains(&"name=allow-https".to_string()));
        assert!(args.contains(&"dir=in".to_string()));
        assert!(args.contains(&"action=allow".to_string()));
        assert!(args.contains(&"protocol=TCP".to_string()));
        assert!(args.contains(&"localport=443".to_string()));
        assert!(args.contains(&"remoteip=192.168.1.0/24".to_string()));
    }

    #[test]
    fn test_rule_to_netsh_args_block_outbound() {
        let fw = WindowsFirewall::new();
        let rule = FirewallRule {
            id: "block-out".to_string(),
            action: FirewallAction::Block,
            direction: FirewallDirection::Outbound,
            src_ip: None,
            dst_ip: Some("10.0.0.0/8".to_string()),
            dst_port: None,
            protocol: Some("udp".to_string()),
            description: "Block outbound UDP".to_string(),
        };

        let args = fw.rule_to_netsh_args(&rule).unwrap();
        assert!(args.contains(&"dir=out".to_string()));
        assert!(args.contains(&"action=block".to_string()));
        assert!(args.contains(&"protocol=UDP".to_string()));
        assert!(args.contains(&"localip=10.0.0.0/8".to_string()));
    }

    #[test]
    fn test_rule_to_netsh_args_reject() {
        let fw = WindowsFirewall::new();
        let rule = FirewallRule {
            id: "reject-all".to_string(),
            action: FirewallAction::Reject,
            direction: FirewallDirection::Inbound,
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            protocol: None,
            description: "Reject all inbound".to_string(),
        };

        let args = fw.rule_to_netsh_args(&rule).unwrap();
        // netsh uses block for reject
        assert!(args.contains(&"action=block".to_string()));
    }
}
