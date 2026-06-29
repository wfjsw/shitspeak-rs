use std::{env, error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let proto_dir = manifest_dir.join("protos");
    let proto_files = [
        proto_dir.join("Mumble.proto"),
        proto_dir.join("MumbleUDP.proto"),
        proto_dir.join("S2STransport.proto"),
        proto_dir.join("S2SOverlay.proto"),
        proto_dir.join("S2SReplication.proto"),
        proto_dir.join("S2SApplication.proto"),
    ];

    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    config.bytes([
        ".MumbleUDP.Audio.opus_data",
        ".MumbleProto.PluginDataTransmission.data",
        ".MumbleProto.UserStats.certificates",
        ".s2s_transport.Frame.payload",
        ".s2s_overlay.OverlayData.payload",
        ".s2s_application.PluginDataEnvelope.data",
        ".s2s_application.VoiceFrame.payload",
        ".s2s_application.UserStatsReply.payload",
        ".s2s_replication",
    ]);

    for proto in &proto_files {
        println!("cargo:rerun-if-changed={}", proto.display());
    }
    config.compile_protos(&proto_files, &[proto_dir])?;

    Ok(())
}
