use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

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

    emit_git_metadata_rerun_hints();

    let commit_hash = resolve_commit_hash();
    println!("cargo:rustc-env=COMMIT_HASH={commit_hash}");

    let commit_date = resolve_commit_date(&commit_hash);
    println!("cargo:rustc-env=COMMIT_DATE={commit_date}");

    let current_date = chrono::Utc::now().to_rfc3339();
    println!("cargo:rustc-env=BUILD_DATE={}", current_date);

    Ok(())
}

fn resolve_commit_hash() -> String {
    if let Some(value) = metadata_env("COMMIT_HASH").or_else(|| metadata_env("GITHUB_SHA")) {
        return value;
    }

    match git_head_from_filesystem() {
        Ok(value) => value,
        Err(error) => {
            println!("cargo:warning=commit hash unavailable; git metadata read failed ({error})");
            "unknown".to_owned()
        }
    }
}

fn resolve_commit_date(commit_hash: &str) -> String {
    if let Some(value) = metadata_env("COMMIT_DATE").or_else(source_date_epoch) {
        return value;
    }

    match git_commit_date_from_filesystem(commit_hash) {
        Ok(date) => date,
        Err(error) => {
            println!("cargo:warning=commit date unavailable; git metadata read failed ({error})");
            "unknown".to_owned()
        }
    }
}

fn metadata_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn source_date_epoch() -> Option<String> {
    let seconds = metadata_env("SOURCE_DATE_EPOCH")?.parse().ok()?;
    chrono::DateTime::from_timestamp(seconds, 0).map(|date| date.to_rfc3339())
}

fn emit_git_metadata_rerun_hints() {
    for var in [
        "COMMIT_HASH",
        "COMMIT_DATE",
        "GITHUB_SHA",
        "SOURCE_DATE_EPOCH",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }

    let manifest_dir = manifest_dir();
    let dot_git = manifest_dir.join(".git");
    println!("cargo:rerun-if-changed={}", dot_git.display());

    let Ok(git_dir) = git_dir(&manifest_dir) else {
        return;
    };

    let head_path = git_dir.join("HEAD");
    println!("cargo:rerun-if-changed={}", head_path.display());

    let Ok(head) = fs::read_to_string(&head_path) else {
        return;
    };

    if let Some(ref_name) = head.trim().strip_prefix("ref: ") {
        println!(
            "cargo:rerun-if-changed={}",
            git_ref_path(&git_dir, ref_name).display()
        );
        println!(
            "cargo:rerun-if-changed={}",
            git_dir.join("packed-refs").display()
        );
    }
    println!(
        "cargo:rerun-if-changed={}",
        git_dir.join("objects").join("pack").display()
    );

    if let Ok(commit_hash) = git_head_from_filesystem() {
        if commit_hash.len() == 40 {
            println!(
                "cargo:rerun-if-changed={}",
                git_dir
                    .join("objects")
                    .join(&commit_hash[..2])
                    .join(&commit_hash[2..])
                    .display()
            );
        }
    }
}

fn git_head_from_filesystem() -> Result<String, String> {
    let git_dir = git_dir(&manifest_dir())?;
    let head_path = git_dir.join("HEAD");
    let head = fs::read_to_string(&head_path)
        .map_err(|error| format!("failed to read {}: {error}", head_path.display()))?;
    let head = head.trim();

    if is_git_object_id(head) {
        return Ok(head.to_owned());
    }

    let ref_name = head
        .strip_prefix("ref: ")
        .ok_or_else(|| format!("HEAD had unsupported content: {head}"))?;

    let loose_ref_path = git_ref_path(&git_dir, ref_name);
    if let Ok(value) = fs::read_to_string(&loose_ref_path) {
        let value = value.trim();
        if is_git_object_id(value) {
            return Ok(value.to_owned());
        }
    }

    let packed_refs_path = git_dir.join("packed-refs");
    let packed_refs = fs::read_to_string(&packed_refs_path).map_err(|error| {
        format!(
            "failed to read loose ref {} and packed refs {}: {error}",
            loose_ref_path.display(),
            packed_refs_path.display()
        )
    })?;

    for line in packed_refs.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(object_id) = parts.next() else {
            continue;
        };
        let Some(packed_ref_name) = parts.next() else {
            continue;
        };

        if packed_ref_name == ref_name && is_git_object_id(object_id) {
            return Ok(object_id.to_owned());
        }
    }

    Err(format!(
        "ref {ref_name} was not found in loose or packed refs"
    ))
}

fn git_commit_date_from_filesystem(commit_hash: &str) -> Result<String, String> {
    let git_dir = git_dir(&manifest_dir())?;
    let commit = read_git_object(&git_dir, commit_hash)?;
    let body = parse_git_object(&commit, "commit")?;
    let timestamp = committer_timestamp_from_commit_body(body)?;

    format_git_timestamp(timestamp)
}

fn read_git_object(git_dir: &Path, object_id: &str) -> Result<Vec<u8>, String> {
    read_loose_git_object(git_dir, object_id).or_else(|loose_error| {
        read_packed_git_object(git_dir, object_id)
            .map_err(|packed_error| format!("{loose_error}; {packed_error}"))
    })
}

fn read_loose_git_object(git_dir: &Path, object_id: &str) -> Result<Vec<u8>, String> {
    if object_id.len() != 40 {
        return Err(format!(
            "only loose SHA-1 objects are supported for commit date parsing, got {} hex chars",
            object_id.len()
        ));
    }

    let object_path = git_dir
        .join("objects")
        .join(&object_id[..2])
        .join(&object_id[2..]);
    let compressed = fs::read(&object_path)
        .map_err(|error| format!("failed to read {}: {error}", object_path.display()))?;

    miniz_oxide::inflate::decompress_to_vec_zlib(&compressed)
        .map_err(|error| format!("failed to inflate {}: {error:?}", object_path.display()))
}

fn read_packed_git_object(git_dir: &Path, object_id: &str) -> Result<Vec<u8>, String> {
    let object_id = decode_hex_object_id(object_id)?;
    let pack_dir = git_dir.join("objects").join("pack");
    let entries = fs::read_dir(&pack_dir)
        .map_err(|error| format!("failed to read {}: {error}", pack_dir.display()))?;

    let mut errors = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(format!("failed to read a pack directory entry: {error}"));
                continue;
            }
        };
        let idx_path = entry.path();
        if idx_path
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("idx")
        {
            continue;
        }

        match pack_index_offset(&idx_path, &object_id) {
            Ok(Some(offset)) => {
                let pack_path = idx_path.with_extension("pack");
                return read_pack_object(&pack_path, offset);
            }
            Ok(None) => {}
            Err(error) => errors.push(error),
        }
    }

    if errors.is_empty() {
        Err(format!("object was not found in {}", pack_dir.display()))
    } else {
        Err(format!(
            "object was not found in {}; index errors: {}",
            pack_dir.display(),
            errors.join("; ")
        ))
    }
}

fn pack_index_offset(idx_path: &Path, object_id: &[u8; 20]) -> Result<Option<u64>, String> {
    let idx = fs::read(idx_path)
        .map_err(|error| format!("failed to read {}: {error}", idx_path.display()))?;
    if idx.len() < 8 + 256 * 4 {
        return Err(format!(
            "{} was too small to be a pack index",
            idx_path.display()
        ));
    }
    if &idx[..4] != b"\xfftOc" {
        return Err(format!(
            "{} was not a version 2 pack index",
            idx_path.display()
        ));
    }

    let version = read_be_u32(&idx, 4, idx_path)?;
    if version != 2 {
        return Err(format!(
            "{} had unsupported pack index version {version}",
            idx_path.display()
        ));
    }

    let fanout_start = 8;
    let object_count = read_be_u32(&idx, fanout_start + 255 * 4, idx_path)? as usize;
    let names_start = fanout_start + 256 * 4;
    let names_len = object_count
        .checked_mul(20)
        .ok_or_else(|| format!("{} object count overflowed", idx_path.display()))?;
    let names_end = checked_add(names_start, names_len, idx_path)?;
    ensure_len(&idx, names_end, idx_path)?;

    let names = &idx[names_start..names_end];
    let search = names
        .chunks_exact(20)
        .binary_search_by(|candidate| candidate.cmp(object_id.as_slice()));
    let object_index = match search {
        Ok(index) => index,
        Err(_) => return Ok(None),
    };

    let crcs_start = names_end;
    let offsets32_start = checked_add(crcs_start, object_count * 4, idx_path)?;
    let offsets32_end = checked_add(offsets32_start, object_count * 4, idx_path)?;
    ensure_len(&idx, offsets32_end, idx_path)?;

    let offset32 = read_be_u32(&idx, offsets32_start + object_index * 4, idx_path)?;
    if offset32 & 0x8000_0000 == 0 {
        return Ok(Some(offset32 as u64));
    }

    let large_index = (offset32 & 0x7fff_ffff) as usize;
    let large_offsets_start = offsets32_end;
    let large_offset_position = checked_add(large_offsets_start, large_index * 8, idx_path)?;
    ensure_len(&idx, large_offset_position + 8, idx_path)?;

    Ok(Some(read_be_u64(&idx, large_offset_position, idx_path)?))
}

fn read_pack_object(pack_path: &Path, offset: u64) -> Result<Vec<u8>, String> {
    let pack = fs::read(pack_path)
        .map_err(|error| format!("failed to read {}: {error}", pack_path.display()))?;
    if pack.len() < 12 || &pack[..4] != b"PACK" {
        return Err(format!("{} was not a pack file", pack_path.display()));
    }

    let mut position = usize::try_from(offset)
        .map_err(|_| format!("pack offset {offset} did not fit in usize"))?;
    if position >= pack.len() {
        return Err(format!(
            "pack offset {offset} was outside {}",
            pack_path.display()
        ));
    }

    let first = pack[position];
    position += 1;
    let object_type = (first >> 4) & 0b111;
    let mut declared_size = (first & 0b1111) as usize;
    let mut shift = 4;
    let mut byte = first;
    while byte & 0x80 != 0 {
        byte = *pack.get(position).ok_or_else(|| {
            format!(
                "packed object header was truncated in {}",
                pack_path.display()
            )
        })?;
        position += 1;
        declared_size |= ((byte & 0x7f) as usize) << shift;
        shift += 7;
    }

    if object_type != 1 {
        return Err(format!(
            "packed object in {} had type {object_type}; only commit objects are supported",
            pack_path.display()
        ));
    }

    let object =
        miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&pack[position..], declared_size)
            .map_err(|error| {
            format!(
                "failed to inflate packed object in {}: {error:?}",
                pack_path.display()
            )
        })?;

    if object.len() != declared_size {
        return Err(format!(
            "packed object in {} declared {declared_size} bytes but inflated to {}",
            pack_path.display(),
            object.len()
        ));
    }

    let header = format!("commit {}\0", object.len());
    let mut loose_shape = Vec::with_capacity(header.len() + object.len());
    loose_shape.extend_from_slice(header.as_bytes());
    loose_shape.extend_from_slice(&object);
    Ok(loose_shape)
}

fn parse_git_object<'a>(object: &'a [u8], expected_kind: &str) -> Result<&'a [u8], String> {
    let header_end = object
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "git object did not contain a header terminator".to_owned())?;
    let header = std::str::from_utf8(&object[..header_end])
        .map_err(|error| format!("git object header was not UTF-8: {error}"))?;
    let (kind, size) = header
        .split_once(' ')
        .ok_or_else(|| format!("git object header had unexpected shape: {header}"))?;

    if kind != expected_kind {
        return Err(format!("expected a {expected_kind} object, found {kind}"));
    }

    let body = &object[header_end + 1..];
    let declared_size = size
        .parse::<usize>()
        .map_err(|error| format!("git object size was invalid: {error}"))?;
    if declared_size != body.len() {
        return Err(format!(
            "git object declared {declared_size} body bytes but contained {}",
            body.len()
        ));
    }

    Ok(body)
}

fn committer_timestamp_from_commit_body(body: &[u8]) -> Result<(i64, i32), String> {
    for line in body.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            break;
        }

        if let Some(committer) = line.strip_prefix(b"committer ") {
            return parse_git_timestamp(committer);
        }
    }

    Err("commit object did not contain a committer line".to_owned())
}

fn parse_git_timestamp(committer: &[u8]) -> Result<(i64, i32), String> {
    let committer = committer.strip_suffix(b"\r").unwrap_or(committer);
    let (prefix, offset) = split_once_from_right(committer, b' ')
        .ok_or_else(|| "committer line missing timezone".to_owned())?;
    let (_, seconds) = split_once_from_right(prefix, b' ')
        .ok_or_else(|| "committer line missing timestamp".to_owned())?;

    let seconds = std::str::from_utf8(seconds)
        .map_err(|error| format!("committer timestamp was not UTF-8: {error}"))?
        .parse::<i64>()
        .map_err(|error| format!("committer timestamp was invalid: {error}"))?;
    let offset = std::str::from_utf8(offset)
        .map_err(|error| format!("committer timezone was not UTF-8: {error}"))?;

    Ok((seconds, parse_git_timezone_offset(offset)?))
}

fn split_once_from_right(value: &[u8], needle: u8) -> Option<(&[u8], &[u8])> {
    let index = value.iter().rposition(|byte| *byte == needle)?;
    Some((&value[..index], &value[index + 1..]))
}

fn decode_hex_object_id(value: &str) -> Result<[u8; 20], String> {
    if value.len() != 40 {
        return Err(format!(
            "only SHA-1 pack index lookup is supported, got {} hex chars",
            value.len()
        ));
    }

    let mut decoded = [0; 20];
    for (index, byte) in decoded.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = (hex_nibble(value.as_bytes()[offset])? << 4)
            | hex_nibble(value.as_bytes()[offset + 1])?;
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex byte: {byte}")),
    }
}

fn parse_git_timezone_offset(offset: &str) -> Result<i32, String> {
    let bytes = offset.as_bytes();
    if bytes.len() != 5 || !matches!(bytes[0], b'+' | b'-') {
        return Err(format!(
            "git timezone offset had unexpected shape: {offset}"
        ));
    }

    let hours = offset[1..3]
        .parse::<i32>()
        .map_err(|error| format!("git timezone hours were invalid: {error}"))?;
    let minutes = offset[3..5]
        .parse::<i32>()
        .map_err(|error| format!("git timezone minutes were invalid: {error}"))?;
    if hours > 23 || minutes > 59 {
        return Err(format!("git timezone offset was out of range: {offset}"));
    }

    let seconds = hours * 3600 + minutes * 60;
    if bytes[0] == b'-' {
        Ok(-seconds)
    } else {
        Ok(seconds)
    }
}

fn format_git_timestamp((seconds, offset_seconds): (i64, i32)) -> Result<String, String> {
    let offset = chrono::FixedOffset::east_opt(offset_seconds)
        .ok_or_else(|| format!("timezone offset was invalid: {offset_seconds}"))?;
    let utc = chrono::DateTime::from_timestamp(seconds, 0)
        .ok_or_else(|| format!("commit timestamp was invalid: {seconds}"))?;

    Ok(utc
        .with_timezone(&offset)
        .format("%Y-%m-%d %H:%M:%S %z")
        .to_string())
}

fn git_dir(manifest_dir: &Path) -> Result<PathBuf, String> {
    let dot_git = manifest_dir.join(".git");
    if dot_git.is_dir() {
        return Ok(dot_git);
    }

    let git_file = fs::read_to_string(&dot_git)
        .map_err(|error| format!("failed to read {}: {error}", dot_git.display()))?;
    let git_dir = git_file
        .trim()
        .strip_prefix("gitdir:")
        .ok_or_else(|| format!("{} did not contain a gitdir entry", dot_git.display()))?
        .trim();
    let git_dir = PathBuf::from(git_dir);

    if git_dir.is_absolute() {
        Ok(git_dir)
    } else {
        Ok(manifest_dir.join(git_dir))
    }
}

fn git_ref_path(git_dir: &Path, ref_name: &str) -> PathBuf {
    ref_name
        .split('/')
        .fold(git_dir.to_path_buf(), |path, segment| path.join(segment))
}

fn is_git_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn manifest_dir() -> PathBuf {
    env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn checked_add(left: usize, right: usize, path: &Path) -> Result<usize, String> {
    left.checked_add(right)
        .ok_or_else(|| format!("{} offset overflowed", path.display()))
}

fn ensure_len(bytes: &[u8], len: usize, path: &Path) -> Result<(), String> {
    if bytes.len() < len {
        Err(format!(
            "{} was truncated: needed {len} bytes, got {}",
            path.display(),
            bytes.len()
        ))
    } else {
        Ok(())
    }
}

fn read_be_u32(bytes: &[u8], offset: usize, path: &Path) -> Result<u32, String> {
    ensure_len(bytes, offset + 4, path)?;
    Ok(u32::from_be_bytes(
        bytes[offset..offset + 4].try_into().unwrap(),
    ))
}

fn read_be_u64(bytes: &[u8], offset: usize, path: &Path) -> Result<u64, String> {
    ensure_len(bytes, offset + 8, path)?;
    Ok(u64::from_be_bytes(
        bytes[offset..offset + 8].try_into().unwrap(),
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_commit_object_committer_date() {
        let body = "tree 3679fcf84b4c63811b7de096b0d2410ff71066a7\nparent ea8f9c578f72540f7b3cc13fb5f43ab968c2f184\ncommitter wfjsw <wfjsw@users.noreply.github.com> 1782195750 -0500\n\nmessage\n";
        let object = format!("commit {}\0{}", body.len(), body);

        let body = parse_git_object(object.as_bytes(), "commit").unwrap();

        assert_eq!(
            format_git_timestamp(committer_timestamp_from_commit_body(body).unwrap()).unwrap(),
            "2026-06-23 01:22:30 -0500"
        );
    }

    #[test]
    fn rejects_non_hex_object_ids() {
        assert!(is_git_object_id("931041c0a9ec3f90e958c4b4aaff119315701f55"));
        assert!(!is_git_object_id(
            "931041c0a9ec3f90e958c4b4aaff119315701f5z"
        ));
        assert_eq!(
            decode_hex_object_id("931041c0a9ec3f90e958c4b4aaff119315701f55").unwrap(),
            [
                0x93, 0x10, 0x41, 0xc0, 0xa9, 0xec, 0x3f, 0x90, 0xe9, 0x58, 0xc4, 0xb4, 0xaa, 0xff,
                0x11, 0x93, 0x15, 0x70, 0x1f, 0x55
            ]
        );
    }

    #[test]
    fn parses_git_timezone_offsets() {
        assert_eq!(parse_git_timezone_offset("+0530").unwrap(), 19_800);
        assert_eq!(parse_git_timezone_offset("-0500").unwrap(), -18_000);
        assert!(parse_git_timezone_offset("+2460").is_err());
    }
}
