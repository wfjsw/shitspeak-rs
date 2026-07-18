//! Canonical topic names for channel and channel-blob replications.
//!
//! The default server retains its legacy unscoped topics. Dynamic server IDs
//! are encoded into a bounded, control-character-free topic suffix so topic
//! resolvers can safely construct replication runtimes from inbound traffic.

use shitspeak_core::DEFAULT_SERVER_ID;

const MAX_DYNAMIC_CHANNEL_SERVER_ID_BYTES: usize = 256;

/// Returns the server ID represented by a channel replication topic.
pub fn server_id_from_channel_topic(topic: &str) -> Option<String> {
    if topic == "channels" {
        Some(DEFAULT_SERVER_ID.to_owned())
    } else {
        let server_id = validated_dynamic_channel_server_id(topic.strip_prefix("channels:")?)?;
        (channel_topic(server_id) == topic).then(|| server_id.to_owned())
    }
}

/// Returns the server ID represented by a channel-blob replication topic.
pub fn server_id_from_channel_blob_topic(topic: &str) -> Option<String> {
    if topic == "channel_blobs" {
        Some(DEFAULT_SERVER_ID.to_owned())
    } else {
        let server_id = validated_dynamic_channel_server_id(topic.strip_prefix("channel_blobs:")?)?;
        (channel_blob_topic(server_id) == topic).then(|| server_id.to_owned())
    }
}

fn validated_dynamic_channel_server_id(server_id: &str) -> Option<&str> {
    (!server_id.is_empty()
        && server_id.len() <= MAX_DYNAMIC_CHANNEL_SERVER_ID_BYTES
        && !server_id.chars().any(char::is_control))
    .then_some(server_id)
}

/// Produces the canonical strict replication topic for a server's channels.
pub fn channel_topic(server_id: &str) -> String {
    if server_id == DEFAULT_SERVER_ID {
        "channels".to_owned()
    } else {
        format!("channels:{server_id}")
    }
}

/// Produces the canonical blob replication topic for a server's channel data.
pub fn channel_blob_topic(server_id: &str) -> String {
    if server_id == DEFAULT_SERVER_ID {
        "channel_blobs".to_owned()
    } else {
        format!("channel_blobs:{server_id}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_channel_topics_are_canonical_bounded_and_control_free() {
        assert_eq!(
            server_id_from_channel_topic("channels"),
            Some(DEFAULT_SERVER_ID.to_owned())
        );
        assert_eq!(
            server_id_from_channel_topic("channels:tenant-a"),
            Some("tenant-a".to_owned())
        );
        assert_eq!(
            server_id_from_channel_blob_topic("channel_blobs:tenant-a"),
            Some("tenant-a".to_owned())
        );
        assert!(server_id_from_channel_topic("channels:default").is_none());
        assert!(server_id_from_channel_topic("channels:").is_none());
        assert!(server_id_from_channel_topic("channels:tenant\nnext").is_none());
        assert!(
            server_id_from_channel_topic(&format!(
                "channels:{}",
                "x".repeat(MAX_DYNAMIC_CHANNEL_SERVER_ID_BYTES + 1)
            ))
            .is_none()
        );
    }
}
