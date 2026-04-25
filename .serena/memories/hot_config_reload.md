# Hot Config Reload

## Architecture
- `Config` is wrapped in `Arc<RwLock<Config>>` in `Server`
- `Server::read_config()` acquires a read lock — values must be copied out before any `.await` (RwLockReadGuard is !Send)
- `Server::reload_config()` acquires a write lock and atomically swaps the config
- `config_watcher.rs` spawns a `spawn_blocking` task that uses `notify` v7 to watch `config.toml` for changes
- Debounce: 500ms quiet period after last filesystem event before triggering reload

## Hot-reloadable fields
- `welcome_text`, `allow_html`, `max_text_message_length`, `max_image_message_length`, `max_bandwidth`
- `cert_required`, `required_groups`, `send_permission_info`
- `min_client_version`, `max_users`
- `udp_voice_enabled`, `udp_ping_enabled`
- `client_idle_timeout_secs`
- `broadcast_listener_volume_adjustments`
- `default_channel`

## NOT hot-reloadable (require restart)
- `node_id`, `listen`, `cert_path`, `key_path`, `allowed_proxies`, `blob_storage_dir`
- `udp_channel_size` (channel created at startup)
- `opus_threshold`, `register_name`, `send_version`, `send_build_info`, `send_os_info`

## Files changed
- `Cargo.toml` — added `notify` v7 dependency
- `src/config.rs` — added `Config::reload()` method
- `src/server.rs` — `config: Config` → `config: Arc<RwLock<Config>>`; all accessors read through lock; added `reload_config()` with change logging
- `src/config_watcher.rs` — new file: filesystem watcher using notify v7
- `src/main.rs` — spawns config watcher on startup
- `src/client/handlers/authenticate.rs` — updated `get_welcome_text()` call (now returns `Option<String>`)
