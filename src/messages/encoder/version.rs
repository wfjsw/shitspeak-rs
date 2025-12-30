use crate::{
    constants::{APP_PROTO_VER, release}, messages::Message, mumble_proto::Version as WireVersion
};

pub struct Version {
    version_v1: Option<u32>,
    version_v2: Option<u64>,
    release: Option<String>,
    os: Option<String>,
    os_version: Option<String>,
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

impl Into<WireVersion> for Version {
    fn into(self) -> WireVersion {
        WireVersion {
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
