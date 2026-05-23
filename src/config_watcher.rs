//! Hot config reload via filesystem watcher.
//!
//! Spawns a background task that watches `config.toml` for changes and
//! calls `Server::reload_config()` through the Tokio runtime when a write is detected.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::{EventKind, RecommendedWatcher, Watcher};
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
    let runtime = tokio::runtime::Handle::current();
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

        let config_path = canonical.clone();
        let (tx, rx) = std::sync::mpsc::channel::<Vec<PathBuf>>();

        let mut watcher =
            match notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res {
                    match event.kind {
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                            let _ = tx.send(event.paths);
                        }
                        _ => {}
                    }
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    tracing::error!("config watcher: failed to create filesystem watcher: {e}");
                    return;
                }
            };

        let mut watched_dirs = HashSet::new();
        watch_directory(
            &mut watcher,
            &mut watched_dirs,
            parent.clone(),
            "config.toml",
        );
        watch_authenticator_directory(&mut watcher, &mut watched_dirs, &server);

        tracing::info!("config watcher: watching {} for changes", parent.display());

        // Debounce: after receiving a change event, wait 500ms for the
        // filesystem to settle before reloading.
        loop {
            // Wait for the first event or shutdown.
            let mut changed_paths = Vec::new();
            let received = loop {
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok(paths) => {
                        changed_paths.extend(paths);
                        break true;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break false,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                }
            };

            // Check shutdown before reloading.
            if !matches!(shutdown.has_changed(), Ok(false)) {
                tracing::info!("config watcher: shutdown received, stopping");
                return;
            }

            if received {
                // Drain any additional events that arrive within 500ms
                // (debounce window).
                while let Ok(paths) = rx.recv_timeout(Duration::from_millis(500)) {
                    changed_paths.extend(paths);
                }
            }

            // Check shutdown again after debounce.
            if !matches!(shutdown.has_changed(), Ok(false)) {
                tracing::info!("config watcher: shutdown received, stopping");
                return;
            }

            let should_reload = changed_paths.iter().any(|changed| {
                same_fileish(changed, &config_path)
                    || server
                        .authenticator_wasm_path()
                        .as_deref()
                        .is_some_and(|auth_path| same_fileish(changed, auth_path))
            });

            if received && should_reload {
                tracing::info!("config watcher: auth/config change detected, reloading...");
                if let Err(e) = runtime.block_on(server.reload_config()) {
                    tracing::error!("config watcher: reload failed: {e}");
                }
                watch_authenticator_directory(&mut watcher, &mut watched_dirs, &server);
            }
        }
    })
}

fn watch_authenticator_directory(
    watcher: &mut RecommendedWatcher,
    watched_dirs: &mut HashSet<PathBuf>,
    server: &Arc<Box<Server>>,
) {
    if let Some(path) = server.authenticator_wasm_path() {
        let normalized = normalize_path(&path);
        let dir = normalized
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        watch_directory(
            watcher,
            watched_dirs,
            normalize_path(&dir),
            "WASM authenticator",
        );
    }
}

fn watch_directory(
    watcher: &mut RecommendedWatcher,
    watched_dirs: &mut HashSet<PathBuf>,
    dir: PathBuf,
    label: &str,
) {
    if !watched_dirs.insert(dir.clone()) {
        return;
    }
    match watcher.watch(&dir, notify::RecursiveMode::NonRecursive) {
        Ok(()) => tracing::info!("config watcher: watching {} for {label}", dir.display()),
        Err(e) => tracing::warn!(
            "config watcher: failed to watch {} for {label}: {e}",
            dir.display()
        ),
    }
}

fn same_fileish(a: &Path, b: &Path) -> bool {
    normalize_path(a) == normalize_path(b)
}

fn normalize_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    absolute.canonicalize().unwrap_or(absolute)
}
