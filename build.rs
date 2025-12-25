use std::{io::Result, process::Command};
fn main() -> Result<()> {
    prost_build::compile_protos(&["src/protos/Mumble.proto", "src/protos/MumbleUDP.proto"], &["src/"])?;
    
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
