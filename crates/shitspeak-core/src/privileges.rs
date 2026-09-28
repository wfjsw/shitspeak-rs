//! Authenticator-assigned privileges.
//!
//! A privilege grants one narrowly scoped capability outside of the channel
//! ACL model, so a deployment does not have to make a partially trusted user
//! a superuser to delegate a single moderation or visibility capability.
//! Authenticators name privileges with the stable strings returned by
//! [`Privilege::name`].

use std::collections::HashSet;
use std::fmt;

use enumflags2::{BitFlags, bitflags};

use crate::ACLPermissions;

#[bitflags]
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Privilege {
    /// Ignore user and channel visibility rules, including hidden superusers.
    /// Users with the `invisible` privilege remain hidden.
    SeeAll = 1 << 0,
    /// Suppress or unsuppress any visible user regardless of the ACL.
    Suppress = 1 << 1,
    /// Moderation actions by this user are attributed to the server.
    ServerModeration = 1 << 2,
    /// Text messages from this user are attributed to the server.
    ServerText = 1 << 3,
    /// Hidden from every other user and excluded from user capacity.
    /// Implies [`Privilege::ServerModeration`] and [`Privilege::ServerText`].
    Invisible = 1 << 4,
    /// Mute, deafen, and undo either on any visible user regardless of the ACL.
    MuteDeafen = 1 << 5,
    /// Move any visible user between channels regardless of the ACL.
    Move = 1 << 6,
    /// Grant or revoke priority speaker on any visible user regardless of the
    /// ACL.
    PrioritySpeaker = 1 << 7,
    /// Create, edit, reparent, and link channels regardless of the ACL.
    /// Removing channels and editing ACLs still require ACL permissions.
    EditChannels = 1 << 8,
    /// Send text messages to any visible user or channel regardless of the ACL.
    TextMessage = 1 << 9,
    /// Use the Hide me / Show me toggle, which hides this user from everyone
    /// except superusers and `see_all` viewers.
    HideSelf = 1 << 10,
}

impl Privilege {
    pub const ALL: [Privilege; 11] = [
        Privilege::SeeAll,
        Privilege::Suppress,
        Privilege::ServerModeration,
        Privilege::ServerText,
        Privilege::Invisible,
        Privilege::MuteDeafen,
        Privilege::Move,
        Privilege::PrioritySpeaker,
        Privilege::EditChannels,
        Privilege::TextMessage,
        Privilege::HideSelf,
    ];

    /// Stable name used by authenticators and replication.
    pub fn name(self) -> &'static str {
        match self {
            Privilege::SeeAll => "see_all",
            Privilege::Suppress => "suppress",
            Privilege::ServerModeration => "server_moderation",
            Privilege::ServerText => "server_text",
            Privilege::Invisible => "invisible",
            Privilege::MuteDeafen => "mute_deafen",
            Privilege::Move => "move",
            Privilege::PrioritySpeaker => "priority_speaker",
            Privilege::EditChannels => "edit_channels",
            Privilege::TextMessage => "text_message",
            Privilege::HideSelf => "hide_self",
        }
    }

    /// Parses a privilege name. Matching ignores ASCII case and surrounding
    /// whitespace.
    pub fn parse(name: &str) -> Option<Self> {
        let name = name.trim();
        Self::ALL
            .into_iter()
            .find(|privilege| privilege.name().eq_ignore_ascii_case(name))
    }

    fn implied(self) -> BitFlags<Privilege> {
        match self {
            Privilege::Invisible => {
                Privilege::Invisible | Privilege::ServerModeration | Privilege::ServerText
            }
            privilege => privilege.into(),
        }
    }
}

impl fmt::Display for Privilege {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A set of privileges with implications already applied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Privileges(BitFlags<Privilege>);

impl Privileges {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn contains(self, privilege: Privilege) -> bool {
        self.0.contains(privilege)
    }

    pub fn is_empty(self) -> bool {
        self.0.is_empty()
    }

    pub fn insert(&mut self, privilege: Privilege) {
        self.0 |= privilege.implied();
    }

    pub fn iter(self) -> impl Iterator<Item = Privilege> {
        self.0.iter()
    }

    /// Parses privilege names, returning the recognized set and the names that
    /// were not recognized.
    pub fn parse<'a>(names: impl IntoIterator<Item = &'a str>) -> (Self, Vec<&'a str>) {
        let mut privileges = Self::empty();
        let mut unknown = Vec::new();
        for name in names {
            match Privilege::parse(name) {
                Some(privilege) => privileges.insert(privilege),
                None => unknown.push(name),
            }
        }
        (privileges, unknown)
    }

    /// Parses privilege names, ignoring names that are not recognized.
    pub fn from_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        Self::parse(names).0
    }

    pub fn names(self) -> HashSet<String> {
        self.iter()
            .map(|privilege| privilege.name().to_owned())
            .collect()
    }

    /// ACL permissions to add when reporting permissions to the client so the
    /// client exposes the actions these privileges allow. The server enforces
    /// each privilege separately; this value never widens enforcement.
    pub fn advertised_permissions(self) -> BitFlags<ACLPermissions> {
        let mut permissions = BitFlags::empty();
        if self.contains(Privilege::Suppress)
            || self.contains(Privilege::MuteDeafen)
            || self.contains(Privilege::PrioritySpeaker)
        {
            permissions |= ACLPermissions::MuteDeafen;
        }
        if self.contains(Privilege::Move) {
            permissions |= ACLPermissions::Move;
        }
        if self.contains(Privilege::EditChannels) {
            permissions |= ACLPermissions::Write
                | ACLPermissions::MakeChannel
                | ACLPermissions::TempChannel
                | ACLPermissions::LinkChannel;
        }
        if self.contains(Privilege::TextMessage) {
            permissions |= ACLPermissions::TextMessage;
        }
        permissions
    }
}

impl From<Privilege> for Privileges {
    fn from(privilege: Privilege) -> Self {
        let mut privileges = Self::empty();
        privileges.insert(privilege);
        privileges
    }
}

impl FromIterator<Privilege> for Privileges {
    fn from_iter<T: IntoIterator<Item = Privilege>>(iter: T) -> Self {
        let mut privileges = Self::empty();
        for privilege in iter {
            privileges.insert(privilege);
        }
        privileges
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for privilege in Privilege::ALL {
            assert_eq!(Privilege::parse(privilege.name()), Some(privilege));
        }
        assert_eq!(Privilege::parse(" See_All "), Some(Privilege::SeeAll));
        assert_eq!(Privilege::parse("superuser"), None);
    }

    #[test]
    fn invisible_implies_server_attribution() {
        let privileges = Privileges::from(Privilege::Invisible);

        assert!(privileges.contains(Privilege::Invisible));
        assert!(privileges.contains(Privilege::ServerModeration));
        assert!(privileges.contains(Privilege::ServerText));
        assert!(!privileges.contains(Privilege::SeeAll));
    }

    #[test]
    fn parse_reports_unknown_names() {
        let (privileges, unknown) = Privileges::parse(["move", "fly", "text_message"]);

        assert!(privileges.contains(Privilege::Move));
        assert!(privileges.contains(Privilege::TextMessage));
        assert_eq!(unknown, vec!["fly"]);
    }

    #[test]
    fn names_are_canonical_and_include_implications() {
        let names = Privileges::from_names(["INVISIBLE"]).names();

        assert_eq!(
            names,
            HashSet::from([
                "invisible".to_owned(),
                "server_moderation".to_owned(),
                "server_text".to_owned(),
            ])
        );
        assert_eq!(Privileges::from_names(names.iter().map(String::as_str)), {
            Privileges::from(Privilege::Invisible)
        });
    }

    #[test]
    fn advertised_permissions_only_cover_delegated_actions() {
        assert!(Privileges::empty().advertised_permissions().is_empty());
        let edit = Privileges::from(Privilege::EditChannels).advertised_permissions();
        assert!(edit.contains(ACLPermissions::Write));
        assert!(!edit.contains(ACLPermissions::Kick));
        assert_eq!(
            Privileges::from(Privilege::Suppress).advertised_permissions(),
            BitFlags::from(ACLPermissions::MuteDeafen)
        );
        assert!(
            Privileges::from(Privilege::SeeAll)
                .advertised_permissions()
                .is_empty()
        );
    }
}
