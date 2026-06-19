# Public WiFi/LAN Security App

## Mục tiêu

Phần mềm bảo vệ người dùng khi làm việc tại coworking space, quán cà phê, hoặc bất kỳ nơi nào có WiFi/LAN công cộng.

**Scope**: Chỉ bảo vệ lớp mạng (WiFi + LAN) + ẩn danh hóa thiết bị.

---

## Mối đe dọa

| Threat | Mô tả |
|--------|--------|
| Man-in-the-Middle (MITM) | Kẻ tấn công nghe lén traffic giữa thiết bị và router |
| Evil Twin AP | Giả mạo access point để lừa người dùng kết nối |
| ARP Spoofing | Giả mạo ARP để chuyển hướng traffic qua máy attacker |
| DNS Spoofing | Giả mạo DNS response để chuyển hướng sang trang giả |
| Packet Sniffing | Thu thập dữ liệu không mã hóa trên mạng |
| Session Hijacking | Chiếm phiên đăng nhập qua cookie/token bị lộ |
| Traffic Analysis | Phân tích pattern traffic để suy ra hành vi người dùng |
| Device Fingerprinting | Nhận diện thiết bị qua MAC, hostname, TLS fingerprint |

---

## Tính năng

### Nhóm A — Bảo vệ mạng

| # | Tính năng | Chống lại | Độ ưu tiên |
|---|-----------|-----------|------------|
| 1 | VPN tự động khi vào mạng lạ | MITM, sniffing | Cao |
| 2 | Kill switch (ngắt internet khi VPN mất) | Lộ traffic | Cao |
| 3 | Evil Twin detection | Giả mạo AP | Cao |
| 4 | ARP spoofing detection | MITM ở LAN | Cao |
| 5 | DNS-over-HTTPS/TLS | DNS spoofing | Trung bình |
| 6 | Network trust scoring | Kết nối mạng nguy hiểm | Trung bình |
| 7 | Firewall auto-hardening | Port scan, incoming attacks | Trung bình |
| 8 | Cảnh báo realtime | Phản ứng nhanh | Cao |

### Nhóm B — Ẩn danh hóa thiết bị

| # | Tính năng | Mục đích | Độ ưu tiên |
|---|-----------|----------|------------|
| 9 | MAC address randomization | AP không nhận diện thiết bị thật | Cao |
| 10 | Hostname spoofing | Ẩn tên máy khỏi DHCP/mDNS | Trung bình |
| 11 | Traffic padding/obfuscation | Chống phân tích pattern traffic | Thấp |
| 12 | Proxy chaining / Multi-hop | Không ai thấy cả nguồn lẫn đích | Thấp |
| 13 | Browser/device fingerprint masking | Ẩn HTTP headers, TLS fingerprint | Trung bình |
| 14 | DNS leak prevention | Không lộ DNS query ra ngoài tunnel | Cao |

---

## Kiến trúc tổng quan

```
┌──────────────────────────────────────────────────────┐
│                    User Interface                      │
│            (System tray / Dashboard)                  │
├──────────────────────────────────────────────────────┤
│                  Core Engine                           │
├────────────┬────────────┬────────────┬───────────────┤
│  Network   │  Anonymity │  Detection │   Alert       │
│  Protection│  Module    │  Module    │   System      │
│            │            │            │               │
│ • VPN      │ • MAC rand │ • Evil Twin│ • Realtime    │
│ • Kill sw  │ • Hostname │ • ARP spoof│   notifications│
│ • Firewall │ • Traffic  │ • DNS spoof│ • Log         │
│ • DoH/DoT  │   padding  │            │               │
│            │ • FP mask  │            │               │
│            │ • DNS leak │            │               │
├────────────┴────────────┴────────────┴───────────────┤
│              OS Network Stack / Drivers                │
│         (Requires admin/root privileges)              │
└──────────────────────────────────────────────────────┘
```

---

## Yêu cầu kỹ thuật

- **Quyền hạn**: Cần admin/root để thao tác MAC, firewall rules, packet capture
- **Packet capture**: Cần libpcap/npcap để detect ARP spoofing, Evil Twin
- **VPN protocol**: WireGuard (nhẹ, nhanh) hoặc OpenVPN
- **DNS encryption**: DoH (RFC 8484) hoặc DoT (RFC 7858)
- **TLS fingerprint**: Cần modify TLS client hello (uTLS library)

---

## Gợi ý Tech Stack (chưa quyết định)

| Thành phần | Lựa chọn |
|------------|----------|
| Core engine | Go hoặc Rust (performance, system-level access) |
| Packet capture | libpcap / gopacket / pnet |
| VPN | WireGuard (wireguard-go) |
| DNS | dnscrypt-proxy / DoH client |
| UI | Tauri (cross-platform) hoặc native |
| MAC spoofing | OS-specific API calls |

---

## Quyết định chưa giải quyết

- [ ] Target platform (Windows/macOS/Linux/cross-platform?)
- [ ] Kiến trúc chi tiết (monolith hay microservices?)
- [ ] VPN server tự host hay dùng provider?
- [ ] Monetization model (free/paid/freemium?)
- [ ] MVP scope — bắt đầu với tính năng nào?

---

## Tham khảo

- WireGuard: https://www.wireguard.com/
- GlassWire (đối thủ): https://www.glasswire.com/
- Tor Project (traffic obfuscation): https://www.torproject.org/
- uTLS (TLS fingerprint): https://github.com/refraction-networking/utls
- gopacket: https://github.com/google/gopacket
