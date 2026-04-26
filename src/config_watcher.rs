//! Hot config reload via filesystem watcher.
//!
//! Spawns a background task that watches `config.toml` for changes and
//! calls `Server::reload_config()` when a write is detected.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use notify::{EventKind, Watcher};
use tokio::sync::watch;

use crate::server::Server;

/// Watch `config.toml` for changes and reload the server config.
///
/// Debounces rapid successive writes (e.g., atomic-save editors) by
/// waiting for a quiet period of 500 ms before triggering a reload.
pub fn spawn_config_watcher(
    server: Arc<Box<Server>>,
    mut shutdown: watch::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let path = Path::new("config.toml");

        // If the file doesn't exist at startup, log and exit.
        if !path.exists() {
            tracing::warn!("config watcher: config.toml not found, hot reload disabled");
            return;
        }

        // Canonicalize the parent directory so we watch the right folder.
        let canonical = match path.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("config watcher: failed to canonicalize config.toml: {e}");
                return;
            }
        };
        let parent = match canonical.parent() {
            Some(p) => p.to_path_buf(),
            None => {
                tracing::error!("config watcher: config.toml has no parent directory");
                return;
            }
        };

        let (tx, rx) = std::sync::mpsc::channel();

        let mut watcher = match notify::recommended_watcher(
            move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res {
                    // Only care about data changes (write, create)
                    match event.kind {
                        EventKind::Create(_) | EventKind::Modify(_) => {
                            for p in &event.paths {
                                if p.file_name().map_or(false, |n| n == "config.toml") {
                                    let _ = tx.send(());
                                    break;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            },
        ) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("config watcher: failed to create filesystem watcher: {e}");
                return;
            }
        };

        if let Err(e) = watcher.watch(&parent, notify::RecursiveMode::NonRecursive) {
            tracing::error!("config watcher: failed to watch directory: {e}");
            return;
        }

        tracing::info!("config watcher: watching {} for changes", parent.display());

        // Debounce: after receiving a change event, wait 500ms for the
        // filesystem to settle before reloading.
        loop {
            // Wait for the first event or shutdown.
            let received = loop {
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok(()) => break true,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break false,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                }
            };

            // Check shutdown before reloading.
            if matches!(shutdown.has_changed(), Ok(true)) {
                tracing::info!("config watcher: shutdown received, stopping");
                return;
            }

            if received {
                // Drain any additional events that arrive within 500ms
                // (debounce window).
                while rx.recv_timeout(Duration::from_millis(500)).is_ok() {}
            }

            // Check shutdown again after debounce.
            if matches!(shutdown.has_changed(), Ok(true)) {
                tracing::info!("config watcher: shutdown received, stopping");
                return;
            }

            if received {
                tracing::info!("config watcher: config.toml changed, reloading...");
                if let Err(e) = server.reload_config() {
                    tracing::error!("config watcher: reload failed: {e}");
                }
            }
        }
    })
}
