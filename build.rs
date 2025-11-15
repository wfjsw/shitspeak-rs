use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(&["src/protos/Mumble.proto", "src/protos/MumbleUDP.proto"], &["src/"])?;
    
    Ok(())
}
