pub mod config;
pub mod doh;

use async_trait::async_trait;
use std::net::IpAddr;

use crate::core::event_bus::EventBus;
use crate::core::mod_trait::{ModuleConfig, ModuleEvent, ModuleStatus, SecurityModule};

use self::config::DnsConfig;
use self::doh::DohClient;

pub struct DnsModule {
    event_bus: EventBus,
    status: ModuleStatus,
    doh_client: DohClient,
    config: DnsConfig,
}

impl DnsModule {
    pub fn new(event_bus: EventBus) -> Self {
        let config = DnsConfig::default();
        Self {
            event_bus,
            status: ModuleStatus::Created,
            doh_client: DohClient::new(config.resolver_url.clone()),
            config,
        }
    }

    /// Resolve a domain name via DNS-over-HTTPS.
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, String> {
        self.doh_client
            .resolve(domain)
            .await
            .map_err(|e| e.to_string())
    }

    /// Returns the current DNS configuration.
    pub fn config(&self) -> &DnsConfig {
        &self.config
    }

    /// Returns a reference to the underlying DoH client.
    pub fn doh_client(&self) -> &DohClient {
        &self.doh_client
    }
}

#[async_trait]
impl SecurityModule for DnsModule {
    fn id(&self) -> &str {
        "dns"
    }

    fn name(&self) -> &str {
        "DNS Module"
    }

    fn priority(&self) -> u32 {
        4
    }

    fn dependencies(&self) -> Vec<&str> {
        vec![]
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
        let _ = self.event_bus.publish(ModuleEvent::DohConnected {
            server: "1.1.1.1".to_string(),
        });
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Stopped;
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    async fn on_event(&mut self, _event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_module_creation() {
        let event_bus = EventBus::new(100);
        let dns = DnsModule::new(event_bus);
        assert_eq!(dns.status(), ModuleStatus::Created);
        assert_eq!(dns.id(), "dns");
        assert_eq!(dns.name(), "DNS Module");
        assert_eq!(dns.priority(), 4);
        assert!(dns.dependencies().is_empty());
    }

    #[tokio::test]
    async fn test_dns_module_initialize() {
        let event_bus = EventBus::new(100);
        let mut dns = DnsModule::new(event_bus);
        assert_eq!(dns.status(), ModuleStatus::Created);

        dns.initialize(&ModuleConfig::default()).await.unwrap();
        assert_eq!(dns.status(), ModuleStatus::Initialized);
    }

    #[tokio::test]
    async fn test_dns_module_start_stop() {
        let event_bus = EventBus::new(100);
        let mut dns = DnsModule::new(event_bus);

        dns.initialize(&ModuleConfig::default()).await.unwrap();
        dns.start().await.unwrap();
        assert_eq!(dns.status(), ModuleStatus::Running);

        dns.stop().await.unwrap();
        assert_eq!(dns.status(), ModuleStatus::Stopped);
    }

    #[tokio::test]
    async fn test_dns_module_start_publishes_doh_connected() {
        let event_bus = EventBus::new(100);
        let mut receiver = event_bus.subscribe();
        let mut dns = DnsModule::new(event_bus);

        dns.initialize(&ModuleConfig::default()).await.unwrap();
        dns.start().await.unwrap();

        let event = receiver.recv().await.unwrap();
        match event {
            ModuleEvent::DohConnected { server } => {
                assert_eq!(server, "1.1.1.1");
            }
            _ => panic!("Expected DohConnected event"),
        }
    }

    #[tokio::test]
    async fn test_dns_module_config_accessors() {
        let event_bus = EventBus::new(100);
        let dns = DnsModule::new(event_bus);
        assert_eq!(
            dns.config().resolver_url,
            "https://1.1.1.1/dns-query"
        );
        assert_eq!(dns.config().timeout_secs, 5);
    }
}
