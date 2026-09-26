//! Showing the untranslated channel name in the client's channel editor.
//!
//! Mumble opens its Edit Channel dialog when the reply to the ACL query
//! arrives, and fills the name field from the name it currently shows for the
//! channel (`MainWindow::msgACL` → `ACLEditor::ACLEditor`). With channel-name
//! translation that would be the translated name, and saving the dialog would
//! rename the channel to it. So the ACL reply is wrapped in two `ChannelState`
//! messages, queued as one unit:
//!
//! 1. the raw name, not translated, so the dialog captures it;
//! 2. the ACL reply, which opens the dialog;
//! 3. the name as the client should display it, restoring its channel tree.
//!
//! Saving an unchanged dialog then sends the raw name back, which the
//! `ChannelState` handler ignores as a no-op.
//!
//! # Races
//!
//! The name is read before the batch is queued, while renames and translation
//! updates reach the client through its projection, which queues
//! independently. A projection message queued between the read and the
//! batch would be overwritten by an older name. Every such message reflects
//! state that was already visible (repositories apply before they publish,
//! and translations are swapped before the refresh is published), so after
//! queueing the name is read again:
//!
//! - raw name changed: the dialog may hold a stale name, so the whole batch is
//!   sent again (Mumble replaces an open editor when an ACL reply arrives);
//! - only the displayed name changed (translation update or language change):
//!   the current displayed name is sent again.
//!
//! This repeats until a re-read matches what was sent last. Later changes are
//! queued by the projection after the batch and need no help.

use async_trait::async_trait;
use shitspeak_messages::messages::Message;
use shitspeak_messages::messages::encoder::ChannelState;

use crate::errors::MessageHandlerError;

/// Upper bound on corrective re-sends when the name keeps changing while the
/// reply is queued.
const MAX_CORRECTIONS: usize = 8;

/// The state the editor reply reads and the queue it writes to.
#[async_trait]
pub(super) trait EditorReplyTarget: Sync {
    /// Current raw name of the channel, or `None` when it no longer exists.
    async fn raw_name(&self) -> Option<String>;

    /// `raw` as the client should see it right now (its translation, or
    /// `raw` itself).
    fn displayed(&self, raw: &str) -> String;

    /// Queue `batch` for the client as one unit, without translating names.
    async fn queue(&self, batch: Vec<Message>) -> Result<(), MessageHandlerError>;
}

fn name_state(channel_id: u32, name: &str) -> Message {
    ChannelState {
        channel_id: Some(channel_id),
        name: Some(name.to_owned()),
        ..Default::default()
    }
    .into()
}

fn editor_batch(channel_id: u32, raw: &str, displayed: &str, acl: &Message) -> Vec<Message> {
    vec![
        name_state(channel_id, raw),
        acl.clone(),
        name_state(channel_id, displayed),
    ]
}

/// Send the ACL query reply for `channel_id` so the client's editor shows the
/// raw channel name. See the module documentation.
pub(super) async fn send_channel_editor_reply(
    target: &impl EditorReplyTarget,
    channel_id: u32,
    acl: Message,
) -> Result<(), MessageHandlerError> {
    let Some(mut raw) = target.raw_name().await else {
        return target.queue(vec![acl]).await;
    };
    let mut shown = target.displayed(&raw);
    target
        .queue(editor_batch(channel_id, &raw, &shown, &acl))
        .await?;

    for _ in 0..MAX_CORRECTIONS {
        // The removal reaches the client through its projection.
        let Some(latest) = target.raw_name().await else {
            return Ok(());
        };
        if latest != raw {
            raw = latest;
            shown = target.displayed(&raw);
            target
                .queue(editor_batch(channel_id, &raw, &shown, &acl))
                .await?;
            continue;
        }
        let displayed = target.displayed(&raw);
        if displayed == shown {
            return Ok(());
        }
        shown = displayed;
        target.queue(vec![name_state(channel_id, &shown)]).await?;
    }
    tracing::debug!(
        channel_id,
        "channel name kept changing while the editor reply was queued"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use parking_lot::Mutex;
    use shitspeak_messages::messages::encoder::Acl;

    use super::*;

    /// Scripted state: each `queue` call applies the next scripted change,
    /// modelling a projection rename or translation update that lands while
    /// the batch is being queued.
    struct Scripted {
        raw: Mutex<Option<String>>,
        translation: Mutex<Option<String>>,
        changes_on_queue: Mutex<VecDeque<Change>>,
        queued: Mutex<Vec<Vec<Message>>>,
    }

    enum Change {
        Rename(&'static str),
        Translate(&'static str),
        Remove,
        Churn,
    }

    impl Scripted {
        fn new(raw: &str, translation: Option<&str>, changes: Vec<Change>) -> Self {
            Self {
                raw: Mutex::new(Some(raw.to_owned())),
                translation: Mutex::new(translation.map(str::to_owned)),
                changes_on_queue: Mutex::new(changes.into()),
                queued: Mutex::new(Vec::new()),
            }
        }

        fn queued(&self) -> Vec<Vec<String>> {
            self.queued
                .lock()
                .iter()
                .map(|batch| batch.iter().map(describe).collect())
                .collect()
        }
    }

    #[async_trait]
    impl EditorReplyTarget for Scripted {
        async fn raw_name(&self) -> Option<String> {
            self.raw.lock().clone()
        }

        fn displayed(&self, raw: &str) -> String {
            match self.translation.lock().as_deref() {
                Some(translation) => format!("{translation}({raw})"),
                None => raw.to_owned(),
            }
        }

        async fn queue(&self, batch: Vec<Message>) -> Result<(), MessageHandlerError> {
            self.queued.lock().push(batch);
            let change = self.changes_on_queue.lock().pop_front();
            match change {
                Some(Change::Rename(name)) => *self.raw.lock() = Some(name.to_owned()),
                Some(Change::Translate(translation)) => {
                    *self.translation.lock() = Some(translation.to_owned());
                }
                Some(Change::Remove) => *self.raw.lock() = None,
                Some(Change::Churn) => {
                    let next = format!("{}+", self.raw.lock().clone().unwrap_or_default());
                    *self.raw.lock() = Some(next);
                    self.changes_on_queue.lock().push_back(Change::Churn);
                }
                None => {}
            }
            Ok(())
        }
    }

    fn describe(message: &Message) -> String {
        match message {
            Message::ChannelState(state) => format!("name:{}", state.name.as_deref().unwrap_or("")),
            Message::ACL(_) => "acl".to_owned(),
            other => format!("{other:?}"),
        }
    }

    fn acl() -> Message {
        Acl {
            channel_id: 5,
            inherit_acls: Some(true),
            groups: Vec::new(),
            acls: Vec::new(),
            query: None,
        }
        .into()
    }

    #[tokio::test]
    async fn reply_wraps_the_acl_in_raw_then_displayed_names() {
        let target = Scripted::new("Lobby", Some("es"), Vec::new());

        send_channel_editor_reply(&target, 5, acl()).await.unwrap();

        assert_eq!(
            target.queued(),
            vec![vec!["name:Lobby", "acl", "name:es(Lobby)"]]
        );
    }

    #[tokio::test]
    async fn a_rename_queued_during_the_reply_reopens_the_editor_with_the_new_name() {
        let target = Scripted::new("Lobby", Some("es"), vec![Change::Rename("Hall")]);

        send_channel_editor_reply(&target, 5, acl()).await.unwrap();

        assert_eq!(
            target.queued(),
            vec![
                vec!["name:Lobby", "acl", "name:es(Lobby)"],
                vec!["name:Hall", "acl", "name:es(Hall)"],
            ],
            "the editor must not keep a name older than one the client already received"
        );
    }

    #[tokio::test]
    async fn a_translation_update_during_the_reply_restores_the_current_translation() {
        let target = Scripted::new("Lobby", Some("es"), vec![Change::Translate("es2")]);

        send_channel_editor_reply(&target, 5, acl()).await.unwrap();

        assert_eq!(
            target.queued(),
            vec![
                vec!["name:Lobby", "acl", "name:es(Lobby)"],
                vec!["name:es2(Lobby)"],
            ]
        );
    }

    #[tokio::test]
    async fn a_removed_channel_needs_no_correction() {
        let target = Scripted::new("Lobby", None, vec![Change::Remove]);

        send_channel_editor_reply(&target, 5, acl()).await.unwrap();

        assert_eq!(target.queued(), vec![vec!["name:Lobby", "acl", "name:Lobby"]]);
    }

    #[tokio::test]
    async fn continuous_renames_are_bounded() {
        let target = Scripted::new("Lobby", None, vec![Change::Churn]);

        send_channel_editor_reply(&target, 5, acl()).await.unwrap();

        assert_eq!(target.queued().len(), MAX_CORRECTIONS + 1);
    }
}
