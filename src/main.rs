//! NetSentinel — Network scanning and audit application.
//!
//! Entry point that launches the Iced GUI application.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() -> iced::Result {
    // Start background capture thread
    let capture_running = Arc::new(AtomicBool::new(true));
    let capture_running_clone = capture_running.clone();
    
    // In a real scenario we'd determine the default gateway. For now, we can pass None.
    netsentinel::network::capture::spawn_capture_thread(capture_running_clone, None);
    
    let result = netsentinel::ui::run();
    
    capture_running.store(false, Ordering::Relaxed);
    result
}
