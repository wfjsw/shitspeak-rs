use crate::{
    constants::{APP_PROTO_VER, release}, messages::Message
};

pub struct Version {
    pub version_v1: Option<u32>,
    pub version_v2: Option<u64>,
    pub release: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
}

impl From<crate::mumble_proto::Version> for Version {
    fn from(proto: crate::mumble_proto::Version) -> Self {
        Self {
            version_v1: proto.version_v1,
            version_v2: proto.version_v2,
            release: proto.release.clone(),
            os: proto.os.clone(),
            os_version: proto.os_version.clone(),
        }
    }
}

impl Version {
    pub fn for_server(send_version: bool, send_build_info: bool, send_os_info: bool) -> Self {
        let os_info = os_info::get();

        Version {
            version_v1: if send_version {
                Some(APP_PROTO_VER.into())
            } else {
                None
            },
            version_v2: if send_version {
                Some(APP_PROTO_VER.into())
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
            version_v1: self.version_v1,
            version_v2: self.version_v2,
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
