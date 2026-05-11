//! Generate self-signed test certificates in PEM format.
//!
//! Usage:
//!   cargo run --example gen-test-certs
//!
//! Requires the `rcgen` crate.  If not available, use OpenSSL instead:
//!   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a self-signed certificate using rcgen
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;

    std::fs::write("cert.pem", cert.cert.pem())?;
    std::fs::write("key.pem", cert.key_pair.serialize_pem())?;

    println!("Generated cert.pem and key.pem for localhost");
    Ok(())
}
