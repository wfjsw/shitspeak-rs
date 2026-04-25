# Context Actions Framework

## Overview
Server-defined context menu actions advertised to Mumble clients via `ContextActionModify` messages. Clients trigger them via `ContextAction` messages.

## Files
- `src/context_action.rs` — Core types, `ContextActionRegistry`, callbacks, tests
- `src/client/handlers/context_action.rs` — Handler for incoming `ContextAction` messages

## Two kinds of actions

### One-shot
- Fixed label, fires once when triggered
- `ContextActionKind::OneShot { label }`
- Callback: `OneShotCallback = Arc<dyn Fn(ContextActionPayload) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>`

### Toggle
- Has on/off state, label reflects current state
- `ContextActionKind::Toggle { label_off, label_on, initial_state }`
- Callback: `ToggleCallback = Arc<dyn Fn(ContextActionPayload, bool) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>`
- State flips automatically on dispatch; callback receives new state

## Key design decisions
- **Full list reconstruction**: When toggle state changes, the entire `build_modify_list()` is rebuilt and broadcast to all clients. This preserves ordering.
- **Async callbacks**: Callbacks are async and run outside the registry lock (lock is dropped before awaiting).
- **`Arc<RwLock<>>`** for definitions and handlers — allows concurrent reads during `build_modify_list()`.

## Registry API
- `register_one_shot(action, context, label, callback)` 
- `register_toggle(action, context, label_off, label_on, initial_state, callback)`
- `build_modify_list()` → `Vec<ContextActionModify>` (ordered)
- `dispatch(payload)` → `bool` (handles one-shot or toggle)
- `toggle_state(action)` → `Option<bool>`
- `set_toggle_state(action, new_state)` → `bool` (changed?)

## Integration
- `Server` holds `context_actions: Arc<ContextActionRegistry>`
- Access via `server.context_actions()`
- Handler in `src/client/handlers/context_action.rs` dispatches and then broadcasts updated list
- Wired into `AsyncMessageHandlerExt` dispatch in `src/client/handlers/mod.rs`
