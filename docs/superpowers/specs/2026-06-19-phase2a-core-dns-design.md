# Phase 2A: Core Fixes + DNS Module Design

> **Date:** 2026-06-19
> **Status:** Approved
> **Scope:** Event dispatch, dependency ordering, DNS module

---

## 1. Overview

Phase 2A fixes architectural gaps from Phase 1 and adds DNS security features.

### Scope

| # | Feature | Priority |
|---|---------|----------|
| 1 | Event dispatch mechanism | Critical |
| 2 | Dependency-aware startup | Critical |
| 3 | DNS-over-HTTPS module | High |
| 4 | DNS leak prevention | High |

### Dependencies

- Builds on Phase 1 core engine (SecurityModule, EventBus, ModuleManager)
- DNS module requires event dispatch to publish events
- Dependency ordering ensures correct module startup sequence

---

## 2. Event Dispatch Mechanism

### Problem

ModuleManager does not automatically dispatch events to modules. When VpnModule publishes `VpnDisconnected`, no code routes it to `KillSwitchModule::on_event()`.

### Solution

Add event dispatch loop to ModuleManager:

```rust
impl ModuleManager {
    pub async fn start_event_dispatch(&self) {
        let mut receiver = self.event_bus.subscribe();
        let modules = self.modules.clone();
        
        tokio::spawn(async move {
            while let Ok(event) = receiver.recv().await {
                for module in modules.values() {
                    let mut module = module.write().await;
                    let _ = module.on_event(&event).await;
                }
            }
        });
    }
}
```

### Flow

```
Module publishes Event
    ↓
EventBus broadcasts
    ↓
Dispatch loop receives
    ↓
Iterates all registered modules
    ↓
Calls on_event() on each module
    ↓
Modules react (e.g., KillSwitch activates)
```

### Design Decisions

- **Broadcast to all modules** — Simple, each module filters relevant events
- **Fire-and-forget** — `let _ =` on on_event() result; modules handle their own errors
- **Spawned task** — Runs independently, doesn't block ModuleManager

---

## 3. Dependency-aware Startup

### Problem

`start_all()` sorts alphabetically — `arp_detector, killswitch, vpn` — wrong order (killswitch before vpn).

### Solution

Topological sort based on module dependencies:

```rust
impl ModuleManager {
    pub async fn start_all(&self) -> Result<(), String> {
        // 1. Build dependency graph
        let mut deps: HashMap<String, Vec<String>> = HashMap::new();
        for (id, module) in &self.modules {
            let module = module.read().await;
            deps.insert(id.clone(), module.dependencies().into_iter().map(String::from).collect());
        }
        
        // 2. Topological sort
        let order = topological_sort(&deps)?;
        
        // 3. Start in dependency order
        for id in order {
            self.start_module(&id).await?;
        }
        
        Ok(())
    }
}
```

### Example

```
vpn: dependencies = []
killswitch: dependencies = ["vpn"]
arp_detector: dependencies = []

Topological sort: [vpn, arp_detector, killswitch]
```

### Algorithm

Simple Kahn's algorithm:
1. Calculate in-degree for each node
2. Start with nodes that have no dependencies
3. Process nodes, reducing in-degree of dependents
4. Repeat until all nodes processed

---

## 4. DNS Module

### Architecture

```
internal/network/dns/
├── mod.rs              # DnsModule implementing SecurityModule
├── doh.rs              # DNS-over-HTTPS client
├── leak.rs             # DNS leak detection
└── config.rs           # DNS configuration
```

### DNS-over-HTTPS Client

```rust
pub struct DohClient {
    resolver_url: String,  // e.g., "https://1.1.1.1/dns-query"
    client: reqwest::Client,
}

impl DohClient {
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, DohError> {
        // 1. Encode domain to DNS wire format
        // 2. POST to resolver_url with content-type: application/dns-message
        // 3. Decode response
        // 4. Return IP addresses
    }
}
```

### DNS Leak Detection

```rust
pub struct DnsLeakDetector {
    known_dns_servers: HashSet<IpAddr>,
    event_bus: EventBus,
}

impl DnsLeakDetector {
    pub async fn monitor(&self, interface: &str) {
        // 1. Capture DNS queries on interface
        // 2. Check if destination is in known_dns_servers
        // 3. If query goes to non-VPN DNS server → publish DnsLeakDetected
    }
}
```

### Events

| Event | Description |
|-------|-------------|
| `DohConnected { server }` | DoH connection established |
| `DnsLeakDetected { dns_server, interface }` | DNS leak detected |

### Dependencies

| Crate | Purpose |
|-------|---------|
| `reqwest` | HTTP client for DoH |
| `dns-encoding` | DNS wire format encoding/decoding |
| `pcap` (optional) | Packet capture for leak detection |

### Configuration

```toml
# configs/dns.toml

[dns]
enabled = true
resolver_url = "https://1.1.1.1/dns-query"
fallback_dns = "1.1.1.1"
monitor_leaks = true

[dns.known_servers]
# Public DNS servers to monitor
"8.8.8.8" = "Google"
"1.1.1.1" = "Cloudflare"
"9.9.9.9" = "Quad9"
```

---

## 5. Implementation Order

| Task | Description | Dependencies |
|------|-------------|--------------|
| 1 | Event dispatch mechanism | None |
| 2 | Dependency-aware startup | Task 1 |
| 3 | DNS-over-HTTPS module | Task 1 |
| 4 | DNS leak prevention | Task 3 |

---

## 6. Testing Strategy

### Unit Tests

- Event dispatch: Test that events are forwarded to all modules
- Topological sort: Test various dependency graphs
- DoH client: Mock HTTP responses, test encoding/decoding
- Leak detection: Test with known/unknown DNS servers

### Integration Tests

- Full flow: VPN disconnect → KillSwitch activates (via event dispatch)
- Dependency order: Verify modules start in correct order
- DNS + VPN: DoH works through VPN tunnel

---

## 7. Open Questions

| # | Question | Status |
|---|----------|--------|
| 1 | Which DoH resolver? (Cloudflare 1.1.1.1 vs Google 8.8.8.8) | TBD |
| 2 | Should DNS leak detection be optional feature? | TBD |
| 3 | How to handle DNS queries when VPN is down? | TBD |

---

## 8. Non-Goals

- Full DNS server implementation
- DNS caching (use system resolver for now)
- DNS-based ad blocking
- Custom DNS records
