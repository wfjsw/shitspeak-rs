use std::sync::OnceLock;

use crate::messages::Message;
use crate::protocol_version::ProtocolVersion;

#[derive(Debug)]
struct CachedOsInfo {
    os: String,
    os_version: String,
}

static SERVER_OS_INFO: OnceLock<CachedOsInfo> = OnceLock::new();

fn server_os_info() -> &'static CachedOsInfo {
    SERVER_OS_INFO.get_or_init(|| {
        let info = os_info::get();
        CachedOsInfo {
            os: info.os_type().to_string(),
            os_version: info.version().to_string(),
        }
    })
}

pub struct Version {
    pub version: Option<ProtocolVersion>,
    pub release: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
}

impl From<crate::mumble_proto::Version> for Version {
    fn from(proto: crate::mumble_proto::Version) -> Self {
        Self {
            version: match (proto.version_v2, proto.version_v1) {
                (Some(v2), _) => Some(ProtocolVersion::from(v2)),
                (_, Some(v1)) => Some(ProtocolVersion::from(v1)),
                _ => None,
            },
            release: proto.release.clone(),
            os: proto.os.clone(),
            os_version: proto.os_version.clone(),
        }
    }
}

impl Version {
    pub fn cache_server_os_info() {
        let _ = server_os_info();
    }

    pub fn for_server(
        send_version: bool,
        send_build_info: bool,
        send_os_info: bool,
        server_protocol_version: ProtocolVersion,
    ) -> Self {
        Self::for_server_with_release(
            send_version,
            send_build_info,
            send_os_info,
            server_protocol_version,
            crate::constants::release,
        )
    }

    pub fn for_server_with_release(
        send_version: bool,
        send_build_info: bool,
        send_os_info: bool,
        server_protocol_version: ProtocolVersion,
        release: impl FnOnce() -> String,
    ) -> Self {
        let (os, os_version) = if send_os_info {
            let info = server_os_info();
            (Some(info.os.clone()), Some(info.os_version.clone()))
        } else {
            (None, None)
        };

        Version {
            version: if send_version {
                Some(server_protocol_version)
            } else {
                None
            },
            release: if send_build_info {
                Some(release())
            } else {
                None
            },
            os,
            os_version,
        }
    }
}

impl From<Version> for crate::mumble_proto::Version {
    fn from(version: Version) -> Self {
        crate::mumble_proto::Version {
            version_v1: version.version.map(u32::from),
            version_v2: version.version.map(u64::from),
            release: version.release,
            os: version.os,
            os_version: version.os_version,
        }
    }
}

impl From<Version> for Message {
    fn from(version: Version) -> Self {
        Message::Version(version.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_server_reuses_cached_os_info() {
        Version::cache_server_os_info();
        let cached = server_os_info() as *const CachedOsInfo;

        let version = Version::for_server(false, false, true, ProtocolVersion::new(1, 0, 0));

        assert_eq!(server_os_info() as *const CachedOsInfo, cached);
        let info = server_os_info();
        assert_eq!(version.os.as_deref(), Some(info.os.as_str()));
        assert_eq!(
            version.os_version.as_deref(),
            Some(info.os_version.as_str())
        );
    }

    #[test]
    fn for_server_omits_os_info_when_disabled() {
        let version = Version::for_server(false, false, false, ProtocolVersion::new(1, 0, 0));

        assert_eq!(version.os, None);
        assert_eq!(version.os_version, None);
    }
}
