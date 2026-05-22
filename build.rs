use std::{collections::BTreeMap, env, error::Error, fs, io, path::PathBuf, process::Command};

use serde::Deserialize;

fn main() -> Result<(), Box<dyn Error>> {
    generate_localization_catalog()?;
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    // Generate `bytes::Bytes` instead of `Vec<u8>` for opaque-blob fields on
    // hot paths so cloning becomes an Arc-bump and decode→forward chains do
    // not need Vec↔Bytes wrappers:
    //   - voice packets (opus payload, S2S voice envelope)
    //   - every S2S transport / overlay envelope payload
    //   - replication op/snapshot blobs (msgpack-encoded, sometimes large)
    //   - user-stats cert chain (Vec↔Bytes loop in encoder)
    // Package-level entry `.s2s_replication` covers all op_msgpack /
    // snapshot_msgpack fields in that package.
    config.bytes([
        ".MumbleUDP.Audio.opus_data",
        ".MumbleProto.PluginDataTransmission.data",
        ".MumbleProto.UserStats.certificates",
        ".s2s_transport.Frame.payload",
        ".s2s_overlay.OverlayData.payload",
        ".s2s_application.PluginDataEnvelope.data",
        ".s2s_application.VoiceFrame.payload",
        // UserStatsReply.payload is an already-encoded MumbleProto.UserStats
        // body that the originator forwards as-is to the moderator's TLS
        // stream — keep it as `Bytes` to skip a Vec↔Bytes copy.
        ".s2s_application.UserStatsReply.payload",
        ".s2s_replication",
    ]);
    let proto_files = [
        "src/protos/Mumble.proto",
        "src/protos/MumbleUDP.proto",
        "src/protos/S2STransport.proto",
        "src/protos/S2SOverlay.proto",
        "src/protos/S2SReplication.proto",
        "src/protos/S2SApplication.proto",
    ];
    for proto in &proto_files {
        println!("cargo:rerun-if-changed={proto}");
    }
    config.compile_protos(&proto_files, &["src/"])?;

    let commit_hash = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=COMMIT_HASH={commit_hash}");

    let commit_date = Command::new("git")
        .args(["log", "-1", "--format=%cd", "--date=iso"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=COMMIT_DATE={commit_date}");

    let current_date = chrono::Utc::now().to_rfc3339();
    println!("cargo:rustc-env=BUILD_DATE={}", current_date);

    Ok(())
}

#[derive(Deserialize)]
struct LocalizationCatalog {
    languages: BTreeMap<String, TranslationSet>,
}

#[derive(Deserialize)]
struct TranslationSet {
    text: BTreeMap<String, String>,
    reject: BTreeMap<String, String>,
    deny: BTreeMap<String, String>,
}

#[derive(Clone, Copy)]
enum CatalogSection {
    Text,
    Reject,
    Deny,
}

struct CatalogKey {
    json_key: &'static str,
    rust_variant: &'static str,
}

const LANGUAGES: &[(&str, &str)] = &[
    ("en", "English"),
    ("es", "Spanish"),
    ("fr", "French"),
    ("de", "German"),
    ("zh", "ChineseSimplified"),
];

const TEXT_KEYS: &[CatalogKey] = &[
    CatalogKey {
        json_key: "MissingRequiredGroup",
        rust_variant: "MissingRequiredGroup",
    },
    CatalogKey {
        json_key: "NoRootTraverse",
        rust_variant: "NoRootTraverse",
    },
    CatalogKey {
        json_key: "CryptSetupFailed",
        rust_variant: "CryptSetupFailed",
    },
    CatalogKey {
        json_key: "WriteAclRequired",
        rust_variant: "WriteAclRequired",
    },
    CatalogKey {
        json_key: "CannotDeleteRootChannel",
        rust_variant: "CannotDeleteRootChannel",
    },
    CatalogKey {
        json_key: "ChannelNameRequired",
        rust_variant: "ChannelNameRequired",
    },
    CatalogKey {
        json_key: "CannotRenameRootChannel",
        rust_variant: "CannotRenameRootChannel",
    },
    CatalogKey {
        json_key: "ChannelDoesNotExist",
        rust_variant: "ChannelDoesNotExist",
    },
];

const REJECT_KEYS: &[CatalogKey] = &[
    CatalogKey {
        json_key: "None",
        rust_variant: "None",
    },
    CatalogKey {
        json_key: "WrongVersion",
        rust_variant: "WrongVersion",
    },
    CatalogKey {
        json_key: "InvalidUsername",
        rust_variant: "InvalidUsername",
    },
    CatalogKey {
        json_key: "WrongUserPw",
        rust_variant: "WrongUserPw",
    },
    CatalogKey {
        json_key: "WrongServerPw",
        rust_variant: "WrongServerPw",
    },
    CatalogKey {
        json_key: "UsernameInUse",
        rust_variant: "UsernameInUse",
    },
    CatalogKey {
        json_key: "ServerFull",
        rust_variant: "ServerFull",
    },
    CatalogKey {
        json_key: "NoCertificate",
        rust_variant: "NoCertificate",
    },
    CatalogKey {
        json_key: "AuthenticatorFail",
        rust_variant: "AuthenticatorFail",
    },
    CatalogKey {
        json_key: "NoNewConnections",
        rust_variant: "NoNewConnections",
    },
];

const DENY_KEYS: &[CatalogKey] = &[
    CatalogKey {
        json_key: "Text",
        rust_variant: "Text",
    },
    CatalogKey {
        json_key: "Permission",
        rust_variant: "Permission",
    },
    CatalogKey {
        json_key: "SuperUser",
        rust_variant: "SuperUser",
    },
    CatalogKey {
        json_key: "ChannelName",
        rust_variant: "ChannelName",
    },
    CatalogKey {
        json_key: "TextTooLong",
        rust_variant: "TextTooLong",
    },
    CatalogKey {
        json_key: "H9k",
        rust_variant: "H9k",
    },
    CatalogKey {
        json_key: "TemporaryChannel",
        rust_variant: "TemporaryChannel",
    },
    CatalogKey {
        json_key: "MissingCertificate",
        rust_variant: "MissingCertificate",
    },
    CatalogKey {
        json_key: "UserName",
        rust_variant: "UserName",
    },
    CatalogKey {
        json_key: "ChannelFull",
        rust_variant: "ChannelFull",
    },
    CatalogKey {
        json_key: "NestingLimit",
        rust_variant: "NestingLimit",
    },
    CatalogKey {
        json_key: "ChannelCountLimit",
        rust_variant: "ChannelCountLimit",
    },
    CatalogKey {
        json_key: "ChannelListenerLimit",
        rust_variant: "ChannelListenerLimit",
    },
    CatalogKey {
        json_key: "UserListenerLimit",
        rust_variant: "UserListenerLimit",
    },
];

fn generate_localization_catalog() -> Result<(), Box<dyn Error>> {
    let catalog_path = PathBuf::from("translations/client_text.json");
    println!("cargo:rerun-if-changed={}", catalog_path.display());

    let catalog_json = fs::read_to_string(&catalog_path)?;
    let catalog: LocalizationCatalog = serde_json::from_str(&catalog_json)?;
    validate_catalog(&catalog)?;

    let mut generated = String::from(
        "pub(crate) fn generated_text(language: Language, key: TextKey) -> &'static str {\n    match (language, key) {\n",
    );
    write_match_arms(
        &mut generated,
        &catalog,
        CatalogSection::Text,
        TEXT_KEYS,
        "TextKey",
    )?;
    generated.push_str("    }\n}\n\n");

    generated.push_str(
        "pub(crate) fn generated_reject_reason(language: Language, reject_type: RejectType) -> &'static str {\n    match (language, reject_type) {\n",
    );
    write_match_arms(
        &mut generated,
        &catalog,
        CatalogSection::Reject,
        REJECT_KEYS,
        "RejectType",
    )?;
    generated.push_str("    }\n}\n\n");

    generated.push_str(
        "pub(crate) fn generated_permission_denied_reason(language: Language, deny_type: DenyType) -> &'static str {\n    match (language, deny_type) {\n",
    );
    write_match_arms(
        &mut generated,
        &catalog,
        CatalogSection::Deny,
        DENY_KEYS,
        "DenyType",
    )?;
    generated.push_str("    }\n}\n");

    let out_dir = env::var_os("OUT_DIR").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "OUT_DIR environment variable is missing",
        )
    })?;
    fs::write(
        PathBuf::from(out_dir).join("localization_catalog.rs"),
        generated,
    )?;

    Ok(())
}

fn validate_catalog(catalog: &LocalizationCatalog) -> Result<(), Box<dyn Error>> {
    for (language_code, _) in LANGUAGES {
        let translations = catalog.languages.get(*language_code).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing localization language '{language_code}'"),
            )
        })?;

        validate_section(language_code, "text", &translations.text, TEXT_KEYS)?;
        validate_section(language_code, "reject", &translations.reject, REJECT_KEYS)?;
        validate_section(language_code, "deny", &translations.deny, DENY_KEYS)?;
    }

    Ok(())
}

fn validate_section(
    language_code: &str,
    section_name: &str,
    translations: &BTreeMap<String, String>,
    keys: &[CatalogKey],
) -> Result<(), Box<dyn Error>> {
    for key in keys {
        if !translations.contains_key(key.json_key) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "missing localization key '{section_name}.{}' for language '{language_code}'",
                    key.json_key
                ),
            )
            .into());
        }
    }

    Ok(())
}

fn write_match_arms(
    generated: &mut String,
    catalog: &LocalizationCatalog,
    section: CatalogSection,
    keys: &[CatalogKey],
    key_type: &str,
) -> Result<(), Box<dyn Error>> {
    for (language_code, language_variant) in LANGUAGES {
        let translations = catalog.languages.get(*language_code).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing localization language '{language_code}'"),
            )
        })?;

        let section_translations = match section {
            CatalogSection::Text => &translations.text,
            CatalogSection::Reject => &translations.reject,
            CatalogSection::Deny => &translations.deny,
        };

        for key in keys {
            let value = section_translations.get(key.json_key).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "missing localization key '{}.{}' for language '{language_code}'",
                        section.name(),
                        key.json_key
                    ),
                )
            })?;
            let value = serde_json::to_string(value)?;
            generated.push_str(&format!(
                "        (Language::{language_variant}, {key_type}::{}) => {value},\n",
                key.rust_variant
            ));
        }
    }

    Ok(())
}

impl CatalogSection {
    fn name(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Reject => "reject",
            Self::Deny => "deny",
        }
    }
}
