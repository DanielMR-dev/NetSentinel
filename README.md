# NetSentinel 🛡️

NetSentinel is a native desktop application focused on local network auditing, control, and surveillance. Designed with a strategic vision for Blue/Purple Team roles and SOC analysis, the tool leverages the power of Tauri to unify an agile React frontend with a highly performant and secure Rust backend.

## 🚀 Key Features

* **Host Discovery (Phase 1):** Identification of live devices on the local network using ARP sweeps and Ping (ICMP) scans.
* **Port Scanning (Phase 2):** Exploration of active services through TCP Connect scans on common ports (21, 22, 80, 443, etc.).
* **Visual Topology Mapping (Phase 3):** Interactive graphical representation of the network topology using React Flow, connecting discovered devices to a central node.
* **Security & Performance:** By utilizing a Rust engine on the backend, the application asynchronously manages thousands of network requests without blocking the UI, while guaranteeing memory safety.

## 🛠️ Tech Stack

### Frontend (UI & State)
* **Framework:** React 19 + TypeScript
* **Styling:** Tailwind CSS
* **State Management:** Zustand (dynamic state) + Zod (data validation)
* **Visualization:** React Flow

### Backend (Core & Networking)
* **Language:** Rust
* **Desktop Framework:** Tauri
* **Concurrency:** Tokio (async runtime)
* **Networking:** pnet (and other Rust crates for packet manipulation)
* **Communication:** Tauri IPC (Inter-Process Communication)

## 🤖 AI-Driven Development Architecture

This project utilizes an AI-assisted development model through a system of specialized agents:
* **Planners (Frontend/Backend):** Software architects who define interfaces, state management, and data structures before implementation.
* **Developers (Frontend/Backend):** Responsible for writing strict, memory-safe code based on architectural guidelines.
* **Reviewers (Frontend/Backend):** Code auditors focused on performance, memory leaks, thread blocking, and security vulnerabilities.

## 🔧 Build from Source

### Prerequisites

| Dependency | Version | Purpose |
|------------|---------|---------|
| Node.js | ≥18.0 | Frontend runtime |
| pnpm | ≥8.0 | Package manager |
| Rust | ≥1.77.2 | Backend runtime |
| GCC/Clang | Recent | C compiler for Rust crates |

#### System-specific requirements:

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
# Clone the repository
git clone https://github.com/your-username/NetSentinel.git
cd NetSentinel

# Install frontend dependencies
pnpm install

# Build the frontend
pnpm build
```

### Development

```bash
# Run in development mode (frontend + Tauri)
pnpm tauri dev

# Or run frontend only (no desktop window)
pnpm dev
```

### Production Build

```bash
# Build for release
pnpm tauri build

# Output will be in src-tauri/target/release/bundle/
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GDK_BACKEND` | wayland | Force X11 backend if Wayland issues occur |
| `RUST_BACKTRACE` | 1 | Enable Rust stack traces for debugging |

**Force X11 on Wayland session:**
```bash
GDK_BACKEND=x11 pnpm tauri dev
```

## 📄 License

This project is open-source and intended for educational and portfolio demonstration purposes.