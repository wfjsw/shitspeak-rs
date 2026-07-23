use std::borrow::Cow;

use shitspeak_messages::messages::encoder::{DenyType, RejectType};

pub use shitspeak_core::Language;

#[derive(Debug, Clone, Copy)]
pub enum TextKey {
    MissingRequiredGroup,
    NoRootTraverse,
    CryptSetupFailed,
    WriteAclRequired,
    CannotDeleteRootChannel,
    ChannelNameRequired,
    CannotRenameRootChannel,
    ChannelDoesNotExist,
}

include!(concat!(env!("OUT_DIR"), "/localization_catalog.rs"));

pub fn text(language: Language, key: TextKey) -> Cow<'static, str> {
    Cow::Borrowed(generated_text(language, key))
}

pub fn channel_does_not_exist(language: Language, channel_id: u32) -> Cow<'static, str> {
    Cow::Owned(
        text(language, TextKey::ChannelDoesNotExist)
            .replace("{channel_id}", &channel_id.to_string()),
    )
}

pub fn reject_reason(language: Language, reject_type: RejectType) -> Cow<'static, str> {
    Cow::Borrowed(generated_reject_reason(language, reject_type))
}

pub fn permission_denied_reason(language: Language, deny_type: DenyType) -> Cow<'static, str> {
    Cow::Borrowed(generated_permission_denied_reason(language, deny_type))
}
