use std::{io::Result, process::Command};
fn main() -> Result<()> {
    let mut config = prost_build::Config::new();
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
        ".MumbleProto.UserStats.certificates",
        ".s2s_transport.Frame.payload",
        ".s2s_overlay.OverlayData.payload",
        ".s2s_application.VoiceFrame.payload",
        // UserStatsReply.payload is an already-encoded MumbleProto.UserStats
        // body that the originator forwards as-is to the moderator's TLS
        // stream — keep it as `Bytes` to skip a Vec↔Bytes copy.
        ".s2s_application.UserStatsReply.payload",
        ".s2s_replication",
    ]);
    config.compile_protos(
        &[
            "src/protos/Mumble.proto",
            "src/protos/MumbleUDP.proto",
            "src/protos/S2STransport.proto",
            "src/protos/S2SOverlay.proto",
            "src/protos/S2SReplication.proto",
            "src/protos/S2SApplication.proto",
        ],
        &["src/"],
    )?;
    
    if let Ok(output) =Command::new("git").args(&["rev-parse", "HEAD"]).output() {
        let git_hash = String::from_utf8(output.stdout).unwrap();
        println!("cargo:rustc-env=COMMIT_HASH={}", git_hash);
    }

    if let Ok(output) = Command::new("git").args(&["log", "-1", "--format=%cd", "--date=iso"]).output() {
        let commit_date = String::from_utf8(output.stdout).unwrap();
        println!("cargo:rustc-env=COMMIT_DATE={}", commit_date.trim());
    }

    let current_date = chrono::Utc::now().to_rfc3339();
    println!("cargo:rustc-env=BUILD_DATE={}", current_date);

    Ok(())
}
