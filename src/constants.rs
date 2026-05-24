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

pub const PROTOBUF_INTRODUCED_VERSION: ProtocolVersion = ProtocolVersion {
    major: 1,
    minor: 5,
    patch: 0,
};

#[cfg(test)]
const FIXED_TEST_BUILD_DATE: &str = "1970-01-01T00:00:00+00:00";

#[cfg(test)]
pub const BUILD_DATE: &str = FIXED_TEST_BUILD_DATE;

#[cfg(not(test))]
pub const BUILD_DATE: &str = env!("BUILD_DATE");
pub const COMMIT_HASH: &str = env!("COMMIT_HASH");
pub const COMMIT_DATE: &str = env!("COMMIT_DATE");

pub fn app_name() -> &'static str {
    APP_NAME_FROM_ENV.unwrap_or("ShitSpeak")
}

pub fn app_version() -> &'static str {
    APP_VERSION_FROM_ENV.unwrap_or("0.1.0")
}

fn non_empty_prefix<'a>(value: &'a str, max_len: usize, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        return fallback;
    }

    value.get(..max_len).unwrap_or(value)
}

pub fn release() -> String {
    let app_name = app_name();
    let app_version = app_version();
    let short_sha = non_empty_prefix(COMMIT_HASH.trim(), 7, "unknown");
    let build_date = non_empty_prefix(BUILD_DATE.trim(), 19, "unknown");

    format!(
        "{} {} ({}) [{}]",
        app_name, app_version, short_sha, build_date
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_metadata_prefix_handles_empty_values() {
        assert_eq!(non_empty_prefix("", 7, "unknown"), "unknown");
        assert_eq!(non_empty_prefix("abcd", 7, "unknown"), "abcd");
        assert_eq!(non_empty_prefix("abcdefghi", 7, "unknown"), "abcdefg");
    }

    #[test]
    fn build_date_is_fixed_for_tests() {
        assert_eq!(BUILD_DATE, FIXED_TEST_BUILD_DATE);
    }
}
