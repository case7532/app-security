use std::collections::HashSet;
use std::net::IpAddr;
use crate::core::event_bus::EventBus;
use crate::core::mod_trait::ModuleEvent;

pub struct DnsLeakDetector {
    event_bus: EventBus,
    known_dns_servers: HashSet<IpAddr>,
}

impl DnsLeakDetector {
    pub fn new(event_bus: EventBus, known_dns_servers: HashSet<IpAddr>) -> Self {
        Self {
            event_bus,
            known_dns_servers,
        }
    }

    pub fn is_known_server(&self, ip: &IpAddr) -> bool {
        self.known_dns_servers.contains(ip)
    }

    pub async fn detect_leak(&self, dns_server: IpAddr, interface: &str) {
        if self.is_known_server(&dns_server) {
            let _ = self.event_bus.publish(ModuleEvent::DnsLeakDetected {
                dns_server: dns_server.to_string(),
                interface: interface.to_string(),
            });
        }
    }
}
