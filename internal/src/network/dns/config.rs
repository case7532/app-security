/// Configuration for the DNS-over-HTTPS module.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// The DoH resolver URL (e.g. "https://1.1.1.1/dns-query").
    pub resolver_url: String,
    /// Query timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            resolver_url: "https://1.1.1.1/dns-query".to_string(),
            timeout_secs: 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_config_default() {
        let config = DnsConfig::default();
        assert_eq!(config.resolver_url, "https://1.1.1.1/dns-query");
        assert_eq!(config.timeout_secs, 5);
    }

    #[test]
    fn test_dns_config_custom() {
        let config = DnsConfig {
            resolver_url: "https://dns.google/dns-query".to_string(),
            timeout_secs: 10,
        };
        assert_eq!(config.resolver_url, "https://dns.google/dns-query");
        assert_eq!(config.timeout_secs, 10);
    }
}
