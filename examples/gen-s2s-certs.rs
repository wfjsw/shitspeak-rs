//! Generate S2S CA and per-node certificates for local cluster testing.
//!
//! Usage:
//!   cargo run --example gen-s2s-certs -- --node 1
//!   cargo run --example gen-s2s-certs -- --node 1 --node 2 --node 3
//!
//! This flow is additive and keeps `gen-test-certs` untouched.

use std::fs;
use std::path::Path;

const DEFAULT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 55555, 1, 1];
const MAX_NODE_ID: u16 = 0x0fff;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let nodes = parse_nodes_from_args()?;
    if nodes.is_empty() {
        return Err("no node IDs provided; pass --node <id>".into());
    }

    let (ca_cert_pem, ca_key_pem) = ensure_ca_exists()?;
    for node_id in nodes {
        mint_node_cert(node_id, &ca_cert_pem, &ca_key_pem)?;
    }

    println!("S2S certificate generation complete.");
    Ok(())
}

fn parse_nodes_from_args() -> Result<Vec<u16>, Box<dyn std::error::Error>> {
    let mut nodes = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--node" {
            let value = args.next().ok_or("missing value after --node")?;
            let node_id: u16 = value.parse()?;
            if node_id > MAX_NODE_ID {
                return Err(format!("node id out of range: {node_id} > {MAX_NODE_ID}").into());
            }
            nodes.push(node_id);
            continue;
        }
        return Err(format!("unknown argument: {arg}").into());
    }
    Ok(nodes)
}

fn ensure_ca_exists() -> Result<(String, String), Box<dyn std::error::Error>> {
    let cert_path = Path::new("s2s-ca-cert.pem");
    let key_path = Path::new("s2s-ca-key.pem");

    if cert_path.exists() && key_path.exists() {
        let cert = fs::read_to_string(cert_path)?;
        let key = fs::read_to_string(key_path)?;
        println!("Using existing S2S CA files.");
        return Ok((cert, key));
    }

    let mut params = rcgen::CertificateParams::new(vec!["s2s-ca.local".to_owned()])?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ShitSpeak S2S Test CA");

    let ca_key = rcgen::KeyPair::generate()?;
    let ca_cert = params.self_signed(&ca_key)?;

    let ca_cert_pem = ca_cert.pem();
    let ca_key_pem = ca_key.serialize_pem();
    fs::write(cert_path, &ca_cert_pem)?;
    fs::write(key_path, &ca_key_pem)?;
    println!("Created new S2S CA: s2s-ca-cert.pem / s2s-ca-key.pem");

    Ok((ca_cert_pem, ca_key_pem))
}

fn mint_node_cert(
    node_id: u16,
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ca_key = rcgen::KeyPair::from_pem(ca_key_pem)?;
    let ca_params = rcgen::CertificateParams::from_ca_cert_pem(ca_cert_pem)?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let mut params = rcgen::CertificateParams::new(vec![format!("s2s-node-{node_id}.local")])?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, format!("s2s-node-{node_id}"));
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];

    // Node identity extension, DER INTEGER encoded for S2S parser compatibility.
    let der_value = if node_id <= 0x7f {
        vec![0x02, 0x01, node_id as u8]
    } else {
        let [high, low] = node_id.to_be_bytes();
        vec![0x02, 0x02, high, low]
    };
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(DEFAULT_OID, der_value));

    let node_key = rcgen::KeyPair::generate()?;
    let node_cert = params.signed_by(&node_key, &ca_cert, &ca_key)?;

    let cert_path = format!("s2s-node-{node_id}-cert.pem");
    let key_path = format!("s2s-node-{node_id}-key.pem");
    fs::write(&cert_path, node_cert.pem())?;
    fs::write(&key_path, node_key.serialize_pem())?;

    println!("Minted S2S certificate for node {node_id}: {cert_path}, {key_path}");
    Ok(())
}
