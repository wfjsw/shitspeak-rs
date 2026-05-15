use crate::{constants::release, messages::Message, protocol_version::ProtocolVersion};

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
    pub fn for_server(
        send_version: bool,
        send_build_info: bool,
        send_os_info: bool,
        server_protocol_version: ProtocolVersion,
    ) -> Self {
        let os_info = os_info::get();

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
            os: if send_os_info {
                Some(os_info.os_type().to_string())
            } else {
                None
            },
            os_version: if send_os_info {
                Some(os_info.version().to_string())
            } else {
                None
            },
        }
    }
}

impl Into<crate::mumble_proto::Version> for Version {
    fn into(self) -> crate::mumble_proto::Version {
        crate::mumble_proto::Version {
            version_v1: self.version.map(|v| v.into()),
            version_v2: self.version.map(|v| v.into()),
            release: self.release,
            os: self.os,
            os_version: self.os_version,
        }
    }
}

impl Into<Message> for Version {
    fn into(self) -> Message {
        Message::Version(self.into())
    }
}
