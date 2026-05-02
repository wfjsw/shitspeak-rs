//! Context actions framework.
//!
//! Provides a registry for server-defined context menu actions that are
//! advertised to Mumble clients via `ContextActionModify` messages.
//!
//! Two kinds of actions are supported:
//!
//! * **One-shot** — fires once when the client triggers it.  The action
//!   stays in the menu with a fixed label.
//!
//! * **Toggle** — has on/off state.  The label shown to the client
//!   reflects the current state, and triggering the action flips it.
//!
//! When the set of actions or any toggle state changes, the **entire**
//! list is reconstructed and re-sent to every connected client so that
//! ordering is preserved.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::Arc,
};

use parking_lot::RwLock;

use crate::messages::encoder::ContextActionModify;

// ── Context bitmask ──────────────────────────────────────────────────────

/// Bitmask values matching the protobuf `ContextActionModify.Context` enum.
pub mod context {
    /// Action is applicable to the server (root).
    pub const SERVER: u32 = 0x01;
    /// Action can target a Channel.
    pub const CHANNEL: u32 = 0x02;
    /// Action can target a User.
    pub const USER: u32 = 0x04;
}

/// Convenience type for context bitmask combinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context(pub u32);

impl Context {
    pub const SERVER: Self = Self(context::SERVER);
    pub const CHANNEL: Self = Self(context::CHANNEL);
    pub const USER: Self = Self(context::USER);

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl std::ops::BitOr for Context {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// ── Operation ────────────────────────────────────────────────────────────

/// Matches the protobuf `ContextActionModify.Operation` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Operation {
    Add = 0,
    Remove = 1,
}

// ── Action kind ──────────────────────────────────────────────────────────

/// The kind of a context action.
#[derive(Debug, Clone)]
pub enum ContextActionKind {
    /// A one-shot action: fires once, label never changes.
    OneShot {
        /// The label shown in the context menu.
        label: String,
    },
    /// A toggle action: has on/off state, label reflects current state.
    Toggle {
        /// Label shown when the toggle is **off**.
        label_off: String,
        /// Label shown when the toggle is **on**.
        label_on: String,
        /// Initial state.
        initial_state: bool,
    },
}

// ── Action definition ────────────────────────────────────────────────────

/// A registered context action.
pub struct ContextActionDef {
    /// Unique identifier for this action (sent as `action` in the protocol).
    pub action: String,
    /// Where this action appears (Server, Channel, User, or combination).
    pub context: Context,
    /// The kind of action (one-shot or toggle).
    pub kind: ContextActionKind,
}

// ── Callback types ───────────────────────────────────────────────────────

/// Payload delivered to a one-shot action handler.
#[derive(Debug, Clone)]
pub struct ContextActionPayload {
    /// The action identifier that was triggered.
    pub action: String,
    /// The session ID of the user who triggered the action.
    pub actor_session: u32,
    /// The target user session, if any.
    pub target_session: Option<u32>,
    /// The target channel ID, if any.
    pub target_channel_id: Option<u32>,
}

/// A boxed async callback for one-shot actions.
pub type OneShotCallback = Arc<
    dyn Fn(ContextActionPayload) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// A boxed async callback for toggle actions.
/// Receives the payload and the **new** state after toggling.
pub type ToggleCallback = Arc<
    dyn Fn(ContextActionPayload, bool) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

// ── Action handler enum ──────────────────────────────────────────────────

enum ActionHandler {
    OneShot(OneShotCallback),
    Toggle {
        callback: ToggleCallback,
        /// Current toggle state.
        state: bool,
    },
}

/// Deferred action extracted from the registry under the lock,
/// so the lock can be released before the async callback is awaited.
enum Action {
    OneShot(OneShotCallback),
    Toggle {
        cb: ToggleCallback,
        new_state: bool,
    },
}

// ── Registry ─────────────────────────────────────────────────────────────

/// A registry of context actions that manages the ordered list and
/// broadcasts updates to all connected clients.
pub struct ContextActionRegistry {
    /// Ordered list of action definitions (determines menu order).
    definitions: RwLock<Vec<ContextActionDef>>,
    /// Handlers keyed by action name.
    handlers: RwLock<HashMap<String, ActionHandler>>,
}

impl ContextActionRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            definitions: RwLock::new(Vec::new()),
            handlers: RwLock::new(HashMap::new()),
        }
    }

    // ── Registration ─────────────────────────────────────────────────

    /// Register a one-shot action.
    ///
    /// The action will appear in the client context menu with the given
    /// `label`.  When triggered, `callback` is invoked.
    pub async fn register_one_shot(
        &self,
        action: impl Into<String>,
        context: Context,
        label: impl Into<String>,
        callback: OneShotCallback,
    ) {
        let action = action.into();
        let def = ContextActionDef {
            action: action.clone(),
            context,
            kind: ContextActionKind::OneShot {
                label: label.into(),
            },
        };

        self.handlers
            .write()
            .insert(action, ActionHandler::OneShot(callback));
        self.definitions.write().push(def);
    }

    /// Register a toggle action.
    ///
    /// The action appears with `label_off` or `label_on` depending on
    /// state.  When triggered, the state flips and `callback` is invoked
    /// with the new state.
    pub async fn register_toggle(
        &self,
        action: impl Into<String>,
        context: Context,
        label_off: impl Into<String>,
        label_on: impl Into<String>,
        initial_state: bool,
        callback: ToggleCallback,
    ) {
        let action = action.into();
        let def = ContextActionDef {
            action: action.clone(),
            context,
            kind: ContextActionKind::Toggle {
                label_off: label_off.into(),
                label_on: label_on.into(),
                initial_state,
            },
        };

        self.handlers.write().insert(
            action,
            ActionHandler::Toggle {
                callback,
                state: initial_state,
            },
        );
        self.definitions.write().push(def);
    }

    // ── Query ────────────────────────────────────────────────────────

    /// Build the full ordered list of `ContextActionModify` messages
    /// representing the current state of all registered actions.
    ///
    /// These should be sent to a client when it first connects, or
    /// broadcast to all clients when the list changes.
    pub async fn build_modify_list(&self) -> Vec<ContextActionModify> {
        let definitions = self.definitions.read();
        let handlers = self.handlers.read();
        let mut out = Vec::with_capacity(definitions.len());

        for def in definitions.iter() {
            let text = match &def.kind {
                ContextActionKind::OneShot { label } => label.clone(),
                ContextActionKind::Toggle {
                    label_off,
                    label_on,
                    ..
                } => {
                    let state = match handlers.get(&def.action) {
                        Some(ActionHandler::Toggle { state, .. }) => *state,
                        _ => false,
                    };
                    if state {
                        label_on.clone()
                    } else {
                        label_off.clone()
                    }
                }
            };

            out.push(ContextActionModify {
                action: def.action.clone(),
                text: Some(text),
                context: Some(def.context.0),
                operation: Some(Operation::Add as i32),
            });
        }

        out
    }

    // ── Dispatch ─────────────────────────────────────────────────────

    /// Handle an incoming `ContextAction` from a client.
    ///
    /// Returns `true` if the action was recognized and dispatched.
    pub async fn dispatch(&self, payload: ContextActionPayload) -> bool {
        // Scope the lock so it's released before any .await below
        let action = {
            let mut handlers = self.handlers.write();

            match handlers.get_mut(&payload.action) {
                Some(ActionHandler::OneShot(cb)) => {
                    let cb = Arc::clone(cb);
                    Some(Action::OneShot(cb))
                }
                Some(ActionHandler::Toggle { callback, state }) => {
                    *state = !*state;
                    let new_state = *state;
                    let cb = Arc::clone(callback);
                    Some(Action::Toggle { cb, new_state })
                }
                None => None,
            }
        }; // lock released here

        match action {
            Some(Action::OneShot(cb)) => {
                cb(payload).await;
                true
            }
            Some(Action::Toggle { cb, new_state }) => {
                cb(payload, new_state).await;
                true
            }
            None => false,
        }
    }

    /// Get the current toggle state for an action.
    ///
    /// Returns `None` if the action doesn't exist or isn't a toggle.
    pub async fn toggle_state(&self, action: &str) -> Option<bool> {
        let handlers = self.handlers.read();
        match handlers.get(action) {
            Some(ActionHandler::Toggle { state, .. }) => Some(*state),
            _ => None,
        }
    }

    /// Set the toggle state for an action without firing the callback.
    ///
    /// Returns `true` if the state was changed.
    pub async fn set_toggle_state(&self, action: &str, new_state: bool) -> bool {
        let mut handlers = self.handlers.write();
        match handlers.get_mut(action) {
            Some(ActionHandler::Toggle { state, .. }) => {
                let changed = *state != new_state;
                *state = new_state;
                changed
            }
            _ => false,
        }
    }
}

impl Default for ContextActionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn noop_one_shot() -> OneShotCallback {
        Arc::new(|_payload| Box::pin(async move {}))
    }

    fn noop_toggle() -> ToggleCallback {
        Arc::new(|_payload, _state| Box::pin(async move {}))
    }

    #[tokio::test]
    async fn test_one_shot_registration_and_build() {
        let registry = ContextActionRegistry::new();
        registry
            .register_one_shot("mute_all", Context::USER, "Mute User", noop_one_shot())
            .await;

        let list = registry.build_modify_list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].action, "mute_all");
        assert_eq!(list[0].text.as_deref(), Some("Mute User"));
        assert_eq!(list[0].context, Some(context::USER));
        assert_eq!(list[0].operation, Some(Operation::Add as i32));
    }

    #[tokio::test]
    async fn test_toggle_state_reflected_in_label() {
        let registry = ContextActionRegistry::new();
        registry
            .register_toggle(
                "deafen",
                Context::USER,
                "Deafen User",
                "Undeafen User",
                false,
                noop_toggle(),
            )
            .await;

        // Initial state: off → label_off
        let list = registry.build_modify_list().await;
        assert_eq!(list[0].text.as_deref(), Some("Deafen User"));

        // Flip state
        registry.set_toggle_state("deafen", true).await;
        let list = registry.build_modify_list().await;
        assert_eq!(list[0].text.as_deref(), Some("Undeafen User"));
    }

    #[tokio::test]
    async fn test_dispatch_one_shot() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);

        let registry = ContextActionRegistry::new();
        registry
            .register_one_shot(
                "test_action",
                Context::SERVER,
                "Test",
                Arc::new(move |_payload| {
                    let c = Arc::clone(&called_clone);
                    Box::pin(async move {
                        c.store(true, Ordering::SeqCst);
                    })
                }),
            )
            .await;

        let payload = ContextActionPayload {
            action: "test_action".into(),
            actor_session: 1,
            target_session: None,
            target_channel_id: None,
        };

        let handled = registry.dispatch(payload).await;
        assert!(handled);
        assert!(called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_dispatch_toggle_flips_state() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let last_state = Arc::new(std::sync::Mutex::new(false));
        let last_state_clone = Arc::clone(&last_state);

        let registry = ContextActionRegistry::new();
        registry
            .register_toggle(
                "toggle_test",
                Context::USER,
                "Off",
                "On",
                false,
                Arc::new(move |_payload, new_state| {
                    let ls = Arc::clone(&last_state_clone);
                    Box::pin(async move {
                        *ls.lock().unwrap() = new_state;
                    })
                }),
            )
            .await;

        assert_eq!(registry.toggle_state("toggle_test").await, Some(false));

        let payload = ContextActionPayload {
            action: "toggle_test".into(),
            actor_session: 1,
            target_session: Some(2),
            target_channel_id: None,
        };

        // First dispatch: flips to true
        let handled = registry.dispatch(payload.clone()).await;
        assert!(handled);
        assert_eq!(registry.toggle_state("toggle_test").await, Some(true));
        assert_eq!(*last_state.lock().unwrap(), true);

        // Second dispatch: flips back to false
        let handled = registry.dispatch(payload).await;
        assert!(handled);
        assert_eq!(registry.toggle_state("toggle_test").await, Some(false));
        assert_eq!(*last_state.lock().unwrap(), false);
    }

    #[tokio::test]
    async fn test_unknown_action_returns_false() {
        let registry = ContextActionRegistry::new();
        let payload = ContextActionPayload {
            action: "nonexistent".into(),
            actor_session: 1,
            target_session: None,
            target_channel_id: None,
        };
        assert!(!registry.dispatch(payload).await);
    }

    #[tokio::test]
    async fn test_order_preserved() {
        let registry = ContextActionRegistry::new();
        registry
            .register_one_shot("first", Context::SERVER, "First", noop_one_shot())
            .await;
        registry
            .register_one_shot("second", Context::USER, "Second", noop_one_shot())
            .await;
        registry
            .register_one_shot("third", Context::CHANNEL, "Third", noop_one_shot())
            .await;

        let list = registry.build_modify_list().await;
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].action, "first");
        assert_eq!(list[1].action, "second");
        assert_eq!(list[2].action, "third");
    }
}
