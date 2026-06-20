# NetSentinel

NetSentinel is a cross-platform desktop application for network discovery, security auditing, and infrastructure monitoring. Built for Blue Team, Purple Team, and SOC analysts, it combines a high-performance Rust scanning engine with a modern native Rust GUI (Iced) to deliver real-time network intelligence without leaving your desktop.

## Features

### Host Discovery
- ARP Sweep - Layer 2 discovery via raw Ethernet frames (requires elevated privileges)
- ARP Table - Passive discovery from the system ARP cache (no privileges needed)
- ICMP Ping Sweep - Raw socket ICMP Echo Request scanning with privilege-aware fallback
- TCP Probe - Concurrent TCP connect probes on common service ports

### Port Scanning
- TCP Connect Scan - Full TCP handshake scanning (no privileges required)
- TCP SYN Stealth Scan - Half-open scanning via raw packet injection (requires root/CAP_NET_RAW)
- UDP Scan - ICMP Port Unreachable-based UDP port discovery on critical services (DNS, DHCP, NTP, SNMP, etc.)
- Timing Templates - Configurable speeds (T0 through T5) for IDS evasion or maximum speed

### Service Identification
- Banner Grabbing - Protocol-aware probes for SSH, HTTP, SMTP, FTP, MySQL, PostgreSQL, RDP, and more
- TLS/SSL Analysis - Certificate inspection including version, cipher suite, issuer, expiry, self-signed detection, and SAN domain enumeration
- OS Fingerprinting - TTL-based OS estimation from response packets
- OUI Vendor Lookup - MAC address manufacturer identified from an IEEE OUI database

### Vulnerability Assessment
- Offline CVE Matching - Known CVE entries matched against discovered service banners
- Real-time CVE Alerts - Severity-classified alerts (Critical/High/Medium/Low) with CVSS scores
- TLS Certificate Warnings - Expired, self-signed, and weak cipher suite detection

### Network Intelligence
- Baseline Snapshots - Save network state as SQLite-backed baselines and diff against future scans
- Scan History - Persistent log of past scans with device details and re-run capability
- Audit Export - CSV and JSON export

### User Experience
- Dark/Light Theme - Built-in themes optimized for readability
- Keyboard Shortcuts - Full keyboard navigation for efficient usage
- Settings Profiles - Persistent scan configurations with CRUD management
- Real-time Progress - Live progress bar, device count, and auto-scrolling scan logs

## Tech Stack

| Layer | Technologies |
|-------|-------------|
| GUI | Rust, Iced (Elm architecture) |
| Backend | Rust, Tokio (async), pnet, socket2, rusqlite |
| Storage | SQLite (local database) |

## Architecture

The project follows a unified architecture within a single Rust binary, eliminating IPC overhead and the need for a web runtime.

NetSentinel
- UI Layer: Iced Elm-architecture (Update, View, Subscription)
- Core Engine: Safe, concurrent network scanning implementation
- Storage: Local SQLite database for history, settings, and baselines

## Build from Source

### Prerequisites

| Dependency | Version | Purpose |
|------------|---------|---------|
| Rust | >= 1.77.2 | Main language runtime |
| GCC/Clang | Recent | C compiler for native crates |

**Ubuntu/Debian:**
```bash
sudo apt install build-essential pkg-config libx11-dev libasound2-dev libudev-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install dbus-devel pkgconf-pkg-config libX11-devel alsa-lib-devel systemd-devel
```

### Installation

```bash
git clone https://github.com/your-username/NetSentinel.git
cd NetSentinel

# Add the protocol repository inside a folder named "proto" to maintain the contract
git submodule add https://github.com/DanielMR-dev/nexus-protocol proto

# Git will create a hidden file named .gitmodules. Register the changes:
git add .gitmodules proto/
git commit -m "infra: added nexus-protocol as a git submodule"

cargo build --release
```

### Development

```bash
# Standard development mode
cargo run

# With elevated privileges (for SYN scan, ICMP, ARP sweep)
sudo -E ./dev-elevated.sh
```

### Testing

```bash
cargo test
```

## Privilege Levels

| Level | Capabilities |
|-------|-------------|
| Standard User | TCP Connect scan, ARP table discovery, banner grabbing, CVE matching |
| Elevated (root/Admin) | SYN stealth scan, ICMP ping sweep, active ARP sweep |

The application gracefully degrades: features requiring elevated privileges automatically fall back to unprivileged alternatives.

## Supported Platforms

- Linux - Full support (ARP via /proc/net/arp, gateway via /proc/net/route)
- Windows - Full support (ARP via arp -a, gateway via route print)
- macOS - Full support (ARP via arp -a, gateway via route -n get default)

## License

This project is licensed under the MIT License.
