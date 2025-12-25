use crate::protocol_version::ProtocolVersion;


pub const MAX_NODE_ID: u16 = 0x0FFF;
pub const MAX_LOCAL_SESSION_ID: u32 = 0x0FFFFF;
pub const MTU: usize = 1600;

pub const APP_NAME_FROM_ENV: Option<&str> = option_env!("APP_NAME");
pub const APP_VERSION_FROM_ENV: Option<&str> = option_env!("APP_VERSION");
pub const APP_PROTO_VER: ProtocolVersion = ProtocolVersion {
    major: 1,
    minor: 4,
    patch: 0,
};

pub const BUILD_DATE: &str = env!("BUILD_DATE");
pub const COMMIT_HASH: &str = env!("COMMIT_HASH");
pub const COMMIT_DATE: &str = env!("COMMIT_DATE");

pub fn app_name() -> &'static str {
    APP_NAME_FROM_ENV.unwrap_or("ShitSpeak")
}

pub fn app_version() -> &'static str {
    APP_VERSION_FROM_ENV.unwrap_or("0.1.0")
}

pub fn release() -> String {
    let app_name = app_name();
    let app_version = app_version();
    let short_sha = &COMMIT_HASH[..7];
    let build_date = BUILD_DATE;

    format!("{} {} ({}) [{}]", app_name, app_version, short_sha, build_date)
}


