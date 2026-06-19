// Linux iptables firewall implementation.

use async_trait::async_trait;
use tokio::process::Command;

use super::super::rules::{FirewallAction, FirewallDirection, FirewallError, FirewallRule};
use super::FirewallPlatform;

pub struct LinuxFirewall;

impl LinuxFirewall {
    pub fn new() -> Self {
        Self
    }

    /// Convert a FirewallRule to iptables arguments.
    fn rule_to_iptables_args(&self, rule: &FirewallRule) -> Result<Vec<String>, FirewallError> {
        let chain = match rule.direction {
            FirewallDirection::Inbound => "INPUT",
            FirewallDirection::Outbound => "OUTPUT",
            FirewallDirection::Both => "FORWARD",
        };

        let mut args = vec![
            "-A".to_string(),
            chain.to_string(),
        ];

        if let Some(ref src) = rule.src_ip {
            args.push("-s".to_string());
            args.push(src.clone());
        }

        if let Some(ref dst) = rule.dst_ip {
            args.push("-d".to_string());
            args.push(dst.clone());
        }

        if let Some(ref proto) = rule.protocol {
            args.push("-p".to_string());
            args.push(proto.clone());
        }

        if let Some(port) = rule.dst_port {
            args.push("--dport".to_string());
            args.push(port.to_string());
        }

        let target = match rule.action {
            FirewallAction::Allow => "ACCEPT",
            FirewallAction::Block => "DROP",
            FirewallAction::Reject => "REJECT",
        };
        args.push("-j".to_string());
        args.push(target.to_string());

        Ok(args)
    }
}

impl Default for LinuxFirewall {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FirewallPlatform for LinuxFirewall {
    async fn add_rule(&self, rule: &FirewallRule) -> Result<(), FirewallError> {
        let args = self.rule_to_iptables_args(rule)?;

        let output = Command::new("iptables")
            .args(&args)
            .output()
            .await
            .map_err(|e| FirewallError::PlatformError(format!("Failed to execute iptables: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::PlatformError(format!(
                "iptables failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    async fn remove_rule(&self, rule_id: &str) -> Result<(), FirewallError> {
        // iptables doesn't have rule IDs, so we need to list and find by comment
        // For simplicity, we'll flush and re-add (not ideal for production)
        let rules = self.list_rules().await?;
        let filtered: Vec<&FirewallRule> = rules.iter().filter(|r| r.id != rule_id).collect();

        if filtered.len() == rules.len() {
            return Err(FirewallError::RuleNotFound(rule_id.to_string()));
        }

        // Use iptables -D to delete matching rule
        // This is simplified - production would parse the exact rule
        let output = Command::new("iptables")
            .args(["-D", "INPUT", "-m", "comment", "--comment", rule_id, "-j", "DROP"])
            .output()
            .await
            .map_err(|e| FirewallError::PlatformError(format!("Failed to execute iptables: {}", e)))?;

        if !output.status.success() {
            // Try OUTPUT chain
            let output = Command::new("iptables")
                .args(["-D", "OUTPUT", "-m", "comment", "--comment", rule_id, "-j", "DROP"])
                .output()
                .await
                .map_err(|e| FirewallError::PlatformError(format!("Failed to execute iptables: {}", e)))?;

            if !output.status.success() {
                return Err(FirewallError::RuleNotFound(rule_id.to_string()));
            }
        }

        Ok(())
    }

    async fn list_rules(&self) -> Result<Vec<FirewallRule>, FirewallError> {
        let output = Command::new("iptables")
            .args(["-L", "-n", "-v", "--line-numbers"])
            .output()
            .await
            .map_err(|e| FirewallError::PlatformError(format!("Failed to execute iptables: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::PlatformError(format!(
                "iptables failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut rules = Vec::new();

        for line in stdout.lines() {
            // Skip headers and empty lines
            if line.starts_with("Chain") || line.starts_with("num") || line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            let target = match parts[1] {
                "ACCEPT" => FirewallAction::Allow,
                "DROP" => FirewallAction::Block,
                "REJECT" => FirewallAction::Reject,
                _ => continue,
            };

            let rule_id = format!("iptables-{}", parts[0]);

            rules.push(FirewallRule {
                id: rule_id,
                action: target,
                direction: FirewallDirection::Inbound,
                src_ip: if parts[2] != "0.0.0.0/0" {
                    Some(parts[2].to_string())
                } else {
                    None
                },
                dst_ip: if parts[3] != "0.0.0.0/0" {
                    Some(parts[3].to_string())
                } else {
                    None
                },
                dst_port: None,
                protocol: None,
                description: format!("iptables rule {}", parts[0]),
            });
        }

        Ok(rules)
    }

    async fn flush_rules(&self) -> Result<(), FirewallError> {
        for chain in &["INPUT", "OUTPUT", "FORWARD"] {
            let output = Command::new("iptables")
                .args(["-F", chain])
                .output()
                .await
                .map_err(|e| FirewallError::PlatformError(format!("Failed to execute iptables: {}", e)))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(FirewallError::PlatformError(format!(
                    "iptables -F {} failed: {}",
                    chain,
                    stderr
                )));
            }
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
    fn test_rule_to_iptables_args_allow_inbound() {
        let fw = LinuxFirewall::new();
        let rule = FirewallRule {
            id: "allow-in".to_string(),
            action: FirewallAction::Allow,
            direction: FirewallDirection::Inbound,
            src_ip: Some("192.168.1.0/24".to_string()),
            dst_ip: None,
            dst_port: Some(443),
            protocol: Some("tcp".to_string()),
            description: "Allow HTTPS from LAN".to_string(),
        };

        let args = fw.rule_to_iptables_args(&rule).unwrap();
        assert_eq!(args[0], "-A");
        assert_eq!(args[1], "INPUT");
        assert!(args.contains(&"-s".to_string()));
        assert!(args.contains(&"192.168.1.0/24".to_string()));
        assert!(args.contains(&"--dport".to_string()));
        assert!(args.contains(&"443".to_string()));
        assert!(args.contains(&"-j".to_string()));
        assert!(args.contains(&"ACCEPT".to_string()));
    }

    #[test]
    fn test_rule_to_iptables_args_block_outbound() {
        let fw = LinuxFirewall::new();
        let rule = FirewallRule {
            id: "block-out".to_string(),
            action: FirewallAction::Block,
            direction: FirewallDirection::Outbound,
            src_ip: None,
            dst_ip: Some("10.0.0.0/8".to_string()),
            dst_port: None,
            protocol: Some("udp".to_string()),
            description: "Block outbound UDP to internal".to_string(),
        };

        let args = fw.rule_to_iptables_args(&rule).unwrap();
        assert_eq!(args[1], "OUTPUT");
        assert!(args.contains(&"-d".to_string()));
        assert!(args.contains(&"10.0.0.0/8".to_string()));
        assert!(args.contains(&"DROP".to_string()));
    }

    #[test]
    fn test_rule_to_iptables_args_reject_both() {
        let fw = LinuxFirewall::new();
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

        let args = fw.rule_to_iptables_args(&rule).unwrap();
        assert_eq!(args[1], "FORWARD");
        assert!(args.contains(&"REJECT".to_string()));
    }
}
