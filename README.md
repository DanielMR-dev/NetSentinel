# NetSentinel

NetSentinel is a cross-platform desktop application for **network discovery, security auditing, and infrastructure monitoring**. Built for Blue Team, Purple Team, and SOC analysts, it combines a high-performance Rust scanning engine with a modern React interface to deliver real-time network intelligence without leaving your desktop.

## Features

### Host Discovery
- **ARP Sweep** — Layer 2 discovery via raw Ethernet frames (requires elevated privileges)
- **ARP Table** — Passive discovery from the system ARP cache (no privileges needed)
- **ICMP Ping Sweep** — Raw socket ICMP Echo Request scanning with privilege-aware fallback
- **TCP Probe** — Concurrent TCP connect probes on common service ports

### Port Scanning
- **TCP Connect Scan** — Full TCP handshake scanning (no privileges required)
- **TCP SYN Stealth Scan** — Half-open scanning via raw packet injection (requires root/CAP_NET_RAW)
- **UDP Scan** — ICMP Port Unreachable-based UDP port discovery on critical services (DNS, DHCP, NTP, SNMP, etc.)
- **Nmap-style Timing Templates** — T0 (Paranoid) through T5 (Insane) for IDS evasion or maximum speed

### Service Identification
- **Banner Grabbing** — Protocol-aware probes for SSH, HTTP, SMTP, FTP, MySQL, PostgreSQL, RDP, and more
- **TLS/SSL Analysis** — Certificate inspection including version, cipher suite, issuer, expiry, self-signed detection, and SAN domain enumeration
- **OS Fingerprinting** — TTL-based OS estimation from response packets
- **OUI Vendor Lookup** — MAC address manufacturer identified from a 1,000+ entry IEEE OUI database

### Vulnerability Assessment
- **Offline CVE Matching** — 130+ CVE entries matched against discovered service banners
- **Real-time CVE Alerts** — Severity-classified alerts (Critical/High/Medium/Low) with CVSS scores
- **TLS Certificate Warnings** — Expired, self-signed, and weak cipher suite detection

### Network Intelligence
- **Interactive Topology** — ReactFlow-based graph with drag, zoom, clustering by subnet/vendor, and minimap
- **Baseline Snapshots** — Save network state as SQLite-backed baselines and diff against future scans
- **Scan History** — Persistent log of past scans with device details and re-run capability
- **Audit Export** — CSV and JSON export with native file dialog

### User Experience
- **Dark/Light Theme** — System-aware with manual toggle
- **Keyboard Shortcuts** — Full keyboard navigation (Ctrl+S scan, Ctrl+F search, Ctrl+1-5 tabs)
- **Accessible UI** — WAI-ARIA compliant with screen reader support and focus management
- **Settings Profiles** — Persistent scan configurations with CRUD management
- **Real-time Progress** — Live progress bar, device count, and auto-scrolling scan logs

## Tech Stack

| Layer | Technologies |
|-------|-------------|
| **Frontend** | React 19, TypeScript (strict), Tailwind CSS, Zustand, ReactFlow |
| **Backend** | Rust, Tauri v2, Tokio (async), pnet, socket2, rusqlite |
| **Transport** | Tauri IPC (`invoke`) + Tauri Events (`emit`/`listen`) |
| **Testing** | Rust unit tests (150+), Vitest (frontend) |

## Architecture

```
NetSentinel General (Orchestrator)
├── Backend Pipeline
│   ├── Planner    → Rust architecture, data structures, concurrency
│   ├── Developer  → Safe, concurrent network scanning implementation
│   └── Reviewer   → Panic/unsafe/deadlock auditing
└── Frontend Pipeline
    ├── Planner    → Component trees, Zustand stores, IPC contracts
    ├── Developer  → React/TypeScript implementation
    └── Reviewer   → Memory leak, accessibility, performance auditing
```

## Build from Source

### Prerequisites

| Dependency | Version | Purpose |
|------------|---------|---------|
| Node.js | >= 18.0 | Frontend runtime |
| pnpm | >= 8.0 | Package manager |
| Rust | >= 1.77.2 | Backend runtime |
| GCC/Clang | Recent | C compiler for native crates |

**Ubuntu/Debian:**
```bash
sudo apt install build-essential pkg-config libdbus-1-dev libgtk-3-dev libwebkit2gtk-4.1-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install dbus-devel pkgconf-pkg-config gtk3-devel webkit2gtk4.1-devel
```

### Installation

```bash
git clone https://github.com/your-username/NetSentinel.git
cd NetSentinel
pnpm install
pnpm build
```

### Development

```bash
# Standard development mode
pnpm tauri dev

# With elevated privileges (for SYN scan, ICMP, ARP sweep)
sudo -E ./dev-elevated.sh
```

### Testing

```bash
# Backend tests
cd src-tauri && cargo test

# Frontend tests
pnpm test
```

### Production Build

```bash
pnpm tauri build
# Output: src-tauri/target/release/bundle/
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GDK_BACKEND` | wayland | Force X11 backend if Wayland issues occur |
| `RUST_BACKTRACE` | 1 | Enable Rust stack traces for debugging |

## Privilege Levels

| Level | Capabilities |
|-------|-------------|
| **Standard User** | TCP Connect scan, ARP table discovery, banner grabbing, CVE matching |
| **Elevated (root/Admin)** | SYN stealth scan, ICMP ping sweep, active ARP sweep |

The application gracefully degrades: features requiring elevated privileges automatically fall back to unprivileged alternatives.

## Supported Platforms

- **Linux** — Full support (ARP via `/proc/net/arp`, gateway via `/proc/net/route`)
- **Windows** — Full support (ARP via `arp -a`, gateway via `route print`)
- **macOS** — Full support (ARP via `arp -a`, gateway via `route -n get default`)

## License

This project is licensed under the [MIT License](LICENSE).
