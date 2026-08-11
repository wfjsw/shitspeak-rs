use std::io;
use std::io::Cursor;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

const TLS_HANDSHAKE_RECORD: u8 = 22;
const TLS_CLIENT_HELLO_HANDSHAKE: u8 = 1;
const TLS_EXTENSION_SERVER_NAME: u16 = 0;
const TLS_EXTENSION_ALPN: u16 = 16;
const TLS_EXTENSION_SIGNATURE_ALGORITHMS: u16 = 13;
const TLS_EXTENSION_SUPPORTED_VERSIONS: u16 = 43;
const MAX_HANDSHAKE_BYTES: usize = 128 * 1024;

enum ClientHelloRecordParse {
    Complete(Vec<u8>),
    Incomplete,
    Invalid,
}

#[derive(Debug)]
struct ClientHelloData {
    legacy_version: u16,
    cipher_suites: Vec<u16>,
    extensions: Vec<u16>,
    supported_versions: Vec<u16>,
    signature_algorithms: Vec<u16>,
    alpn_protocols: Vec<Vec<u8>>,
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    fn read_u8(&mut self) -> Option<u8> {
        let value = *self.data.get(self.offset)?;
        self.offset += 1;
        Some(value)
    }

    fn read_u16(&mut self) -> Option<u16> {
        let bytes = self.read_exact(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_exact(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(len)?;
        let bytes = self.data.get(self.offset..end)?;
        self.offset = end;
        Some(bytes)
    }

    fn skip(&mut self, len: usize) -> Option<()> {
        self.read_exact(len).map(|_| ())
    }
}

/// Accept a TLS connection while retaining the complete ClientHello used to
/// derive its JA4 fingerprint.
///
/// The ClientHello is consumed by rustls's pre-acceptor, then its resulting
/// state is transferred to the normal rustls handshake. This avoids the
/// timing-dependent `TcpStream::peek` capture that could miss a fragmented
/// ClientHello.
pub async fn accept_tls_with_ja4<IO>(
    mut stream: IO,
    tls_acceptor: &TlsAcceptor,
) -> io::Result<(TlsStream<IO>, String)>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut acceptor = rustls::server::Acceptor::default();
    let mut tls_records = Vec::new();

    loop {
        let mut record_header = [0u8; 5];
        stream.read_exact(&mut record_header).await?;
        if record_header[0] != TLS_HANDSHAKE_RECORD {
            return Err(invalid_client_hello(
                "TLS ClientHello did not begin with a handshake record",
            ));
        }
        let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
        let record_end = tls_records
            .len()
            .checked_add(record_header.len())
            .and_then(|len| len.checked_add(record_len))
            .ok_or_else(|| invalid_client_hello("TLS ClientHello size overflow"))?;
        if record_end > MAX_HANDSHAKE_BYTES {
            return Err(invalid_client_hello(
                "TLS ClientHello exceeds the size limit",
            ));
        }

        let mut record = Vec::with_capacity(record_header.len() + record_len);
        record.extend_from_slice(&record_header);
        record.resize(record_header.len() + record_len, 0);
        stream
            .read_exact(&mut record[record_header.len()..])
            .await?;
        tls_records.extend_from_slice(&record);

        let mut record_reader = Cursor::new(record.as_slice());
        while (record_reader.position() as usize) < record.len() {
            let bytes_read = acceptor.read_tls(&mut record_reader)?;
            if bytes_read == 0 {
                return Err(invalid_client_hello(
                    "rustls stopped reading the TLS ClientHello record",
                ));
            }
        }

        match acceptor.accept() {
            Ok(Some(accepted)) => {
                let ClientHelloRecordParse::Complete(handshake) =
                    parse_tls_client_hello_records(&tls_records)
                else {
                    return Err(invalid_client_hello(
                        "rustls accepted a ClientHello that could not be fingerprinted",
                    ));
                };
                let client_hello = parse_client_hello(&handshake).ok_or_else(|| {
                    invalid_client_hello("could not parse the accepted TLS ClientHello")
                })?;
                let tls_ja4 = ja4_from_client_hello(&client_hello);
                let tls_stream = tokio_rustls::server::StartHandshake::from_parts(accepted, stream)
                    .into_stream(tls_acceptor.config().clone())
                    .await?;
                return Ok((tls_stream, tls_ja4));
            }
            Ok(None) => {}
            Err((error, _alert)) => {
                return Err(invalid_client_hello(format!(
                    "rustls rejected the TLS ClientHello: {error}"
                )));
            }
        }
    }
}

fn invalid_client_hello(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn parse_tls_client_hello_records(input: &[u8]) -> ClientHelloRecordParse {
    let mut offset = 0;
    let mut handshake = Vec::new();
    let mut expected_handshake_len = None;

    loop {
        let Some(record_header) = input.get(offset..offset + 5) else {
            return ClientHelloRecordParse::Incomplete;
        };
        if record_header[0] != TLS_HANDSHAKE_RECORD {
            return ClientHelloRecordParse::Invalid;
        }

        let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
        offset += 5;
        let Some(record_payload) = input.get(offset..offset + record_len) else {
            return ClientHelloRecordParse::Incomplete;
        };
        offset += record_len;

        handshake.extend_from_slice(record_payload);
        if handshake.len() > MAX_HANDSHAKE_BYTES {
            return ClientHelloRecordParse::Invalid;
        }

        if expected_handshake_len.is_none() && handshake.len() >= 4 {
            if handshake[0] != TLS_CLIENT_HELLO_HANDSHAKE {
                return ClientHelloRecordParse::Invalid;
            }
            let body_len = read_u24(&handshake[1..4]);
            expected_handshake_len = Some(4 + body_len);
        }

        if let Some(expected) = expected_handshake_len {
            if handshake.len() >= expected {
                handshake.truncate(expected);
                return ClientHelloRecordParse::Complete(handshake);
            }
        }
    }
}

fn parse_client_hello(handshake: &[u8]) -> Option<ClientHelloData> {
    if handshake.len() < 4 || handshake[0] != TLS_CLIENT_HELLO_HANDSHAKE {
        return None;
    }
    let body_len = read_u24(&handshake[1..4]);
    let body = handshake.get(4..4 + body_len)?;
    let mut reader = Reader::new(body);

    let legacy_version = reader.read_u16()?;
    reader.skip(32)?;
    let session_id_len = reader.read_u8()? as usize;
    reader.skip(session_id_len)?;

    let cipher_suites_len = reader.read_u16()? as usize;
    if cipher_suites_len % 2 != 0 {
        return None;
    }
    let mut cipher_suites = Vec::with_capacity(cipher_suites_len / 2);
    for _ in 0..cipher_suites_len / 2 {
        cipher_suites.push(reader.read_u16()?);
    }

    let compression_methods_len = reader.read_u8()? as usize;
    reader.skip(compression_methods_len)?;

    let mut extensions = Vec::new();
    let mut supported_versions = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut alpn_protocols = Vec::new();

    if reader.remaining() == 0 {
        return Some(ClientHelloData {
            legacy_version,
            cipher_suites,
            extensions,
            supported_versions,
            signature_algorithms,
            alpn_protocols,
        });
    }

    let extensions_len = reader.read_u16()? as usize;
    let extensions_end = reader.offset.checked_add(extensions_len)?;
    if extensions_end > body.len() {
        return None;
    }

    while reader.offset < extensions_end {
        let extension_type = reader.read_u16()?;
        let extension_len = reader.read_u16()? as usize;
        let extension_data = reader.read_exact(extension_len)?;

        extensions.push(extension_type);
        match extension_type {
            TLS_EXTENSION_SUPPORTED_VERSIONS => {
                supported_versions = parse_supported_versions(extension_data);
            }
            TLS_EXTENSION_SIGNATURE_ALGORITHMS => {
                signature_algorithms = parse_u16_vector(extension_data);
            }
            TLS_EXTENSION_ALPN => {
                alpn_protocols = parse_alpn_protocols(extension_data);
            }
            _ => {}
        }
    }

    if reader.offset != extensions_end {
        return None;
    }

    Some(ClientHelloData {
        legacy_version,
        cipher_suites,
        extensions,
        supported_versions,
        signature_algorithms,
        alpn_protocols,
    })
}

fn parse_supported_versions(data: &[u8]) -> Vec<u16> {
    let Some((&len, versions)) = data.split_first() else {
        return Vec::new();
    };
    parse_u16_list(versions.get(..len as usize).unwrap_or_default())
}

fn parse_u16_vector(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    parse_u16_list(data.get(2..2 + len).unwrap_or_default())
}

fn parse_u16_list(data: &[u8]) -> Vec<u16> {
    data.chunks_exact(2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .collect()
}

fn parse_alpn_protocols(data: &[u8]) -> Vec<Vec<u8>> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let Some(list) = data.get(2..2 + list_len) else {
        return Vec::new();
    };

    let mut protocols = Vec::new();
    let mut offset = 0;
    while offset < list.len() {
        let len = list[offset] as usize;
        offset += 1;
        let Some(protocol) = list.get(offset..offset + len) else {
            return Vec::new();
        };
        offset += len;
        protocols.push(protocol.to_vec());
    }
    protocols
}

fn ja4_from_client_hello(hello: &ClientHelloData) -> String {
    let version = ja4_tls_version(hello);
    let cipher_suites = non_grease_sorted(&hello.cipher_suites);
    let extensions = non_grease_sorted(
        &hello
            .extensions
            .iter()
            .filter(|extension| **extension != TLS_EXTENSION_SERVER_NAME)
            .copied()
            .collect::<Vec<_>>(),
    );
    let signature_algorithms = non_grease_sorted(&hello.signature_algorithms);
    let alpn = ja4_alpn(&hello.alpn_protocols);

    let cipher_hash = sha256_12_hex(&format_u16_list(&cipher_suites));
    let extension_hash_input = format!(
        "{}_{}",
        format_u16_list(&extensions),
        format_u16_list(&signature_algorithms)
    );
    let extension_hash = sha256_12_hex(&extension_hash_input);

    format!(
        "t{}x{:02}{:02}{}_{}_{}",
        version,
        cipher_suites.len(),
        extensions.len(),
        alpn,
        cipher_hash,
        extension_hash
    )
}

fn ja4_tls_version(hello: &ClientHelloData) -> String {
    let version = hello
        .supported_versions
        .iter()
        .filter(|version| !is_grease(**version))
        .copied()
        .max()
        .unwrap_or(hello.legacy_version);

    match version {
        0x0304 => "13".to_owned(),
        0x0303 => "12".to_owned(),
        0x0302 => "11".to_owned(),
        0x0301 => "10".to_owned(),
        value => format!("{value:04x}"),
    }
}

fn ja4_alpn(protocols: &[Vec<u8>]) -> String {
    let Some(protocol) = protocols.first() else {
        return "00".to_owned();
    };
    let alnum: Vec<char> = protocol
        .iter()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .copied()
        .map(|byte| (byte as char).to_ascii_lowercase())
        .collect();

    match alnum.as_slice() {
        [] => "00".to_owned(),
        [single] => format!("{single}{single}"),
        [first, .., last] => format!("{first}{last}"),
    }
}

fn non_grease_sorted(values: &[u16]) -> Vec<u16> {
    let mut values = values
        .iter()
        .filter(|value| !is_grease(**value))
        .copied()
        .collect::<Vec<_>>();
    values.sort_unstable();
    values
}

fn is_grease(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0x00ff)
}

fn format_u16_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn sha256_12_hex(input: &str) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, input.as_bytes());
    hex::encode(&digest.as_ref()[..6])
}

fn read_u24(bytes: &[u8]) -> usize {
    ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject as _};
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
    use tokio_rustls::TlsConnector;

    struct FragmentingIo {
        inner: DuplexStream,
        max_write_bytes: usize,
    }

    impl FragmentingIo {
        fn new(inner: DuplexStream, max_write_bytes: usize) -> Self {
            Self {
                inner,
                max_write_bytes,
            }
        }
    }

    impl AsyncRead for FragmentingIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for FragmentingIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let len = buf.len().min(self.max_write_bytes);
            Pin::new(&mut self.inner).poll_write(cx, &buf[..len])
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[test]
    fn ja4_excludes_sni_from_count_and_hash() {
        let without_sni = test_client_hello(vec![(
            TLS_EXTENSION_ALPN,
            vec![0x00, 0x03, 0x02, b'h', b'2'],
        )]);
        let with_sni = test_client_hello(vec![
            (
                TLS_EXTENSION_SERVER_NAME,
                vec![
                    0x00, 0x10, 0x00, 0x00, 0x0d, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.',
                    b't', b'e', b's', b't',
                ],
            ),
            (TLS_EXTENSION_ALPN, vec![0x00, 0x03, 0x02, b'h', b'2']),
        ]);

        let without_sni = parse_client_hello(&without_sni).expect("parse without SNI");
        let with_sni = parse_client_hello(&with_sni).expect("parse with SNI");

        assert_eq!(
            ja4_from_client_hello(&without_sni),
            ja4_from_client_hello(&with_sni)
        );
    }

    #[tokio::test]
    async fn fragmented_client_hello_is_fingerprinted_before_tls_accept() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate test certificate");
        let cert_pem = certificate.cert.pem();
        let cert_der = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .next()
            .expect("certificate PEM entry")
            .expect("parse certificate PEM");
        let key_pem = certificate.key_pair.serialize_pem();
        let key_der = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("parse key PEM");
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("build server TLS config");
        let server_acceptor = TlsAcceptor::from(Arc::new(server_config));

        let mut roots = RootCertStore::empty();
        roots.add(cert_der).expect("add test certificate as root");
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let client_connector = TlsConnector::from(Arc::new(client_config));

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_handshake = accept_tls_with_ja4(server_io, &server_acceptor);
        let client_handshake = client_connector.connect(
            ServerName::try_from("localhost").expect("static server name"),
            FragmentingIo::new(client_io, 1),
        );
        let (server_result, client_result) = tokio::join!(server_handshake, client_handshake);

        let (_server_tls, tls_ja4) = server_result.expect("server TLS handshake");
        let _client_tls = client_result.expect("client TLS handshake");
        assert!(
            tls_ja4.starts_with("t13x"),
            "fragmented TLS ClientHello JA4: {tls_ja4}"
        );
    }

    fn test_client_hello(extensions: Vec<(u16, Vec<u8>)>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.extend_from_slice(&0x1302u16.to_be_bytes());
        body.push(1);
        body.push(0);

        let mut encoded_extensions = Vec::new();
        for (extension_type, extension_data) in extensions {
            encoded_extensions.extend_from_slice(&extension_type.to_be_bytes());
            encoded_extensions.extend_from_slice(&(extension_data.len() as u16).to_be_bytes());
            encoded_extensions.extend_from_slice(&extension_data);
        }
        body.extend_from_slice(&(encoded_extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&encoded_extensions);

        let mut handshake = Vec::new();
        handshake.push(TLS_CLIENT_HELLO_HANDSHAKE);
        handshake.push(((body.len() >> 16) & 0xff) as u8);
        handshake.push(((body.len() >> 8) & 0xff) as u8);
        handshake.push((body.len() & 0xff) as u8);
        handshake.extend_from_slice(&body);
        handshake
    }
}
