---
name: Frontend Standards
description: Comprehensive coding standards, patterns, and best practices for the NetSentinel frontend. This skill defines the non-negotiable rules for Rust Iced GUI development, state management, asynchronous layout updates, themes, and Elm architecture.
version: 1.0.0
project: NetSentinel
context: Rust + Iced + Tokio + Elm Architecture
---

# NetSentinel Frontend Standards (Iced)

This skill defines the authoritative rules and patterns that every frontend developer, planner, and reviewer must follow when working on the Iced-based desktop UI for the NetSentinel project.

---

## 1. The Elm Architecture (Model-View-Update)

NetSentinel's frontend uses the **Iced** framework, which implements the Elm Architecture. Every UI component or page must adhere strictly to this pattern.

```
       +------------------+
       |                  |
       v                  |
   +--------+          +--------+
   | Update | -------> | Model  |
   +--------+          +--------+
       ^                  |
       |                  v
   +--------+          +------++
   | Message| <------- | View  |
   +--------+          +-------+
```

### 1.1 Model (State)

The application state must be modeled using clean, immutable structs. Avoid nesting too deeply to keep state updates straightforward.

```rust
// GOOD — Clear, descriptive model representation
pub struct AppState {
    pub current_page: Page,
    pub scan_state: ScanUiState,
    pub theme: CustomTheme,
    pub is_elevated: bool,
}
```

### 1.2 Message (Event Enum)

Messages represent all user interactions, asynchronous task completions, and external event notifications.

* **Descriptive Naming:** Messages should use prefix patterns denoting their source page or domain (e.g., `Scan(...)`, `Settings(...)`, `Nav(...)`).
* **Variant Structuring:** Group related actions in nested enums or structures.

```rust
#[derive(Debug, Clone)]
pub enum Message {
    // Page Navigation
    NavigateTo(Page),
    
    // Scan Operations
    StartScanRequested,
    ScanProgressReceived(f32),
    DeviceDiscovered(Device),
    ScanFinished(Result<Duration, String>),
    
    // Theme
    ToggleTheme,
}
```

### 1.3 Update (State Mutation & Commands)

The `update` function handles state changes and returns `Command<Message>` to execute asynchronous side effects.

* **Purity:** Keep the state transitions fast and direct.
* **Side Effects:** Never execute blocking network requests or database queries directly within `update`. Delegate them using `Command::perform` or `Subscription`.

```rust
pub fn update(&mut self, message: Message) -> Command<Message> {
    match message {
        Message::NavigateTo(page) => {
            self.current_page = page;
            Command::none()
        }
        Message::StartScanRequested => {
            self.scan_state.is_scanning = true;
            self.scan_state.progress = 0.0;
            self.scan_state.discovered_devices.clear();
            
            // Perform asynchronous scan via Command
            Command::perform(
                run_network_scan(self.scan_state.cidr.clone()),
                Message::ScanFinished
            )
        }
        Message::DeviceDiscovered(device) => {
            self.scan_state.discovered_devices.push(device);
            Command::none()
        }
        _ => Command::none()
    }
}
```

### 1.4 View (UI Rendering)

The `view` function describes how the state is rendered. It must remain a pure function of the model.

* **No Side Effects:** Do not trigger operations or mutate state within `view`.
* **Lightweight:** Avoid expensive calculations inside `view`. Compute sorted lists or statistics ahead of time during `update` or cache them.

---

## 2. Asynchronous GUI Execution

Because network scanning is highly concurrent and involves heavy network I/O, the UI must never block. All asynchronous tasks are handled via Iced's `Command` and `Subscription` systems.

### 2.1 Command Execution

For one-off asynchronous actions (like writing a configuration profile or querying a single host), use `Command::perform`.

```rust
// GOOD — Spawning a background task with future resolution
fn save_settings(settings: Settings) -> Command<Message> {
    Command::perform(
        async move {
            backend::save_config(settings).await
        },
        |result| Message::SettingsSaved(result.map_err(|e| e.to_string()))
    )
}
```

### 2.2 Subscription (Streaming Progress)

For long-running tasks that stream multiple updates over time (like a full subnet scan emitting devices as they are found), use `iced::subscription`.

```rust
use iced::subscription::{self, Subscription};

pub fn subscription(&self) -> Subscription<Message> {
    if self.scan_state.is_scanning {
        // Subscribe to a tokio-based receiver channel mapping incoming events to messages
        subscription::channel(
            std::any::TypeId::of::<ScanUiState>(),
            100,
            |mut output| async move {
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
                
                // Spawn backend scan engine, passing the sender
                tokio::spawn(async move {
                    backend::scanner::run_subnet_scan("192.168.1.0/24", tx).await;
                });
                
                // Stream updates to the GUI event loop
                while let Some(event) = rx.recv().await {
                    match event {
                        backend::ScanEvent::DeviceFound(device) => {
                            let _ = output.send(Message::DeviceDiscovered(device)).await;
                        }
                        backend::ScanEvent::Progress(p) => {
                            let _ = output.send(Message::ScanProgressReceived(p)).await;
                        }
                        backend::ScanEvent::Finished(res) => {
                            let _ = output.send(Message::ScanFinished(res)).await;
                            break;
                        }
                    }
                }
            }
        )
    } else {
        Subscription::none()
    }
}
```

---

## 3. Layout and Widget Guidelines

Iced uses a responsive, flexible layout system based on flexbox concepts.

### 3.1 Layout Composition

Construct interfaces using layout structures instead of arbitrary coordinates:

* `Column`: Vertically stacked items.
* `Row`: Horizontally stacked items.
* `Container`: Wrap a single element, providing padding, alignment, background, and borders.
* `Scrollable`: Wrap tall content (like host results tables) to prevent layout overflows.
* `Space`: Create flexible or fixed empty spaces to align elements.

```rust
use iced::widget::{button, column, container, row, text, Scrollable};

pub fn view(&self) -> Element<Message> {
    let controls = row![
        text("Target CIDR:"),
        text(&self.scan_state.cidr),
        button("Scan").on_press(Message::StartScanRequested)
    ]
    .spacing(10)
    .align_items(Alignment::Center);

    let mut device_list = column![].spacing(5);
    for device in &self.scan_state.discovered_devices {
        device_list = device_list.push(row![
            text(&device.ip),
            text(&device.mac),
            text(device.hostname.as_deref().unwrap_or("Unknown"))
        ].spacing(20));
    }

    column![
        controls,
        Scrollable::new(device_list)
    ]
    .spacing(20)
    .padding(15)
    .into()
}
```

### 3.2 Responsive & Adaptive Rules

* Always set Scrollable boundaries on dynamic tables.
* Use `.width(Length::Fill)` and `.height(Length::Fill)` to allow containers to automatically stretch to the window boundaries.
* Avoid absolute width pixel sizes where possible; prefer percentages or grid columns.

---

## 4. Themes & Custom Styling

NetSentinel features a premium, state-of-the-art dark theme. All styling must rely on the custom color design tokens.

### 4.1 Custom Styling Tokens (RGB / HSL equivalents)

Implement standard styling using custom widgets stylesheets:

* **Primary Color:** High-contrast blue/cyan for primary actions.
* **Success Color:** Harmonious green for online/active hosts.
* **Danger Color:** Muted crimson for vulnerabilities/CVE findings.
* **Background:** Ultra dark charcoal/navy for the main window background.
* **Surface Background:** Elevated grey for cards and navigation panels.

### 4.2 Stylesheet Definitions

Avoid inline manual style parameters where possible. Define modular style structs implementing Iced widget style traits (e.g. `container::StyleSheet`, `button::StyleSheet`).

```rust
pub struct ScanCardStyle;

impl container::StyleSheet for ScanCardStyle {
    type Style = Theme;

    fn appearance(&self, _style: &Self::Style) -> container::Appearance {
        container::Appearance {
            background: Some(Background::Color(Color::from_rgb8(31, 41, 55))), // gray-800
            border: Border {
                radius: 8.0.into(),
                width: 1.0,
                color: Color::from_rgb8(55, 65, 81), // gray-700
            },
            ..Default::appearance()
        }
    }
}
```

---

## 5. Performance Checklist

To keep the application GUI running at high FPS (accelerated by the GPU):

* [ ] **No Blocking in update():** Verify that no synchronous network connections, DNS resolution, or filesystem/DB actions exist inside the UI state updates.
* [ ] **Pure view() Methods:** Make sure the `view()` function contains no nested data cloning or parsing; compute these values when the state changes in `update()`.
* [ ] **Clean Subscriptions:** Ensure that any asynchronous channel-based `Subscription` gracefully terminates and cleans up resources when the scan task stops or completes.
* [ ] **Pre-allocated Layouts:** Avoid creating huge lists in dynamic view trees without wrapping them in a `Scrollable` container.

---

## 6. Directory Structure (Frontend Layout)

```
src/
  ui/
    mod.rs             # UI module declarations & Application runner
    theme.rs           # Theme definition & widget stylesheets
    views/
      mod.rs
      dashboard.rs     # Dashboard layout
      scan.rs          # Scan targets and results panel
      history.rs       # Scanning history & details
      topology.rs      # Interactive graph visualization
      settings.rs      # Global options and permissions
    widgets/
      mod.rs             # Shared reusable UI elements
```

---

*This skill document is aligned with the NetSentinel project architecture (Rust + Iced + Tokio) and is mandatory for all frontend/UI development tasks.*