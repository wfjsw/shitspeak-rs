use std::fmt::Write as _;
use std::io;
use std::io::Cursor;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use x509_parser::prelude::parse_x509_certificate;

const TLS_HANDSHAKE_RECORD: u8 = 22;
const TLS_CLIENT_HELLO_HANDSHAKE: u8 = 1;
const TLS_EXTENSION_SERVER_NAME: u16 = 0;
const TLS_EXTENSION_ALPN: u16 = 16;
const TLS_EXTENSION_SIGNATURE_ALGORITHMS: u16 = 13;
const TLS_EXTENSION_SUPPORTED_GROUPS: u16 = 10;
const TLS_EXTENSION_EC_POINT_FORMATS: u16 = 11;
const TLS_EXTENSION_SUPPORTED_VERSIONS: u16 = 43;
const MAX_HANDSHAKE_BYTES: usize = 128 * 1024;

/// Capture backends the process can activate, ordered from most precise to
/// least invasive. The probe runs once during server construction.
pub(crate) fn available_packet_capture_backends() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        let capabilities = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("CapEff:\t"))
                    .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
            })
            .unwrap_or_default();
        let has = |bit| capabilities & (1u64 << bit) != 0u64;
        let mut backends = Vec::new();
        // The eBPF socket filter is attached to an AF_PACKET socket, so it
        // needs CAP_NET_RAW as well as the capabilities needed to load and
        // attach the BPF program. CAP_NET_RAW alone permits the AF_PACKET
        // fallback.
        if has(39) && has(38) && has(12) && has(13) {
            backends.push("ebpf".to_owned());
        }
        if has(13) {
            backends.push("af_packet".to_owned());
        }
        backends
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

enum ClientHelloRecordParse {
    Complete(Vec<u8>),
    Incomplete,
    Invalid,
}

#[derive(Debug)]
struct ClientHelloData<'a> {
    legacy_version: u16,
    cipher_suites: &'a [u8],
    extensions: &'a [u8],
    supported_versions: Option<&'a [u8]>,
    signature_algorithms: Option<&'a [u8]>,
    supported_groups: Option<&'a [u8]>,
    ec_point_formats: Option<&'a [u8]>,
    alpn_protocols: Option<&'a [u8]>,
    sni: Option<&'a str>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TlsFingerprints {
    pub(crate) ja3: Option<String>,
    pub(crate) ja4: Option<String>,
    pub(crate) ja4t: Option<String>,
    pub(crate) ja4x: Option<String>,
    pub(crate) ja4l: Option<String>,
    pub(crate) sni: Option<String>,
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
pub(crate) async fn accept_tls_with_fingerprints<IO>(
    mut stream: IO,
    tls_acceptor: &TlsAcceptor,
) -> io::Result<(TlsStream<IO>, TlsFingerprints)>
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

        let record_start = tls_records.len();
        tls_records.extend_from_slice(&record_header);
        tls_records.resize(record_end, 0);
        stream
            .read_exact(&mut tls_records[record_start + record_header.len()..])
            .await?;

        let record = &tls_records[record_start..];
        let mut record_reader = Cursor::new(record);
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
                let fingerprints = TlsFingerprints {
                    ja3: Some(ja3_from_client_hello(&client_hello)),
                    ja4: Some(ja4_from_client_hello(&client_hello)),
                    ja4t: None,
                    ja4x: None,
                    ja4l: None,
                    sni: client_hello.sni.map(str::to_ascii_lowercase),
                };
                let tls_stream = tokio_rustls::server::StartHandshake::from_parts(accepted, stream)
                    .into_stream(tls_acceptor.config().clone())
                    .await?;
                return Ok((tls_stream, fingerprints));
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
    let mut handshake = Vec::with_capacity(input.len().min(MAX_HANDSHAKE_BYTES));
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

fn parse_client_hello(handshake: &[u8]) -> Option<ClientHelloData<'_>> {
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
    let cipher_suites = reader.read_exact(cipher_suites_len)?;

    let compression_methods_len = reader.read_u8()? as usize;
    reader.skip(compression_methods_len)?;

    if reader.remaining() == 0 {
        return Some(ClientHelloData {
            legacy_version,
            cipher_suites,
            extensions: &[],
            supported_versions: None,
            signature_algorithms: None,
            supported_groups: None,
            ec_point_formats: None,
            alpn_protocols: None,
            sni: None,
        });
    }

    let extensions_len = reader.read_u16()? as usize;
    let extensions = reader.read_exact(extensions_len)?;
    if reader.remaining() != 0 || !valid_extensions(extensions) {
        return None;
    }

    Some(ClientHelloData {
        legacy_version,
        cipher_suites,
        extensions,
        supported_versions: extension_data(extensions, TLS_EXTENSION_SUPPORTED_VERSIONS),
        signature_algorithms: extension_data(extensions, TLS_EXTENSION_SIGNATURE_ALGORITHMS),
        supported_groups: extension_data(extensions, TLS_EXTENSION_SUPPORTED_GROUPS),
        ec_point_formats: extension_data(extensions, TLS_EXTENSION_EC_POINT_FORMATS),
        alpn_protocols: extension_data(extensions, TLS_EXTENSION_ALPN),
        sni: extension_data(extensions, TLS_EXTENSION_SERVER_NAME).and_then(parse_sni),
    })
}

fn valid_extensions(data: &[u8]) -> bool {
    let mut reader = Reader::new(data);
    while reader.remaining() != 0 {
        let Some(_) = reader.read_u16() else {
            return false;
        };
        let Some(len) = reader.read_u16() else {
            return false;
        };
        if reader.skip(len as usize).is_none() {
            return false;
        }
    }
    true
}

fn extension_data(extensions: &[u8], wanted: u16) -> Option<&[u8]> {
    let mut reader = Reader::new(extensions);
    let mut result = None;
    while reader.remaining() != 0 {
        let extension_type = reader.read_u16()?;
        let extension_len = reader.read_u16()? as usize;
        let extension_data = reader.read_exact(extension_len)?;
        if extension_type == wanted {
            result = Some(extension_data);
        }
    }
    result
}

fn extension_types(extensions: &[u8], exclude: Option<u16>) -> Vec<u16> {
    let mut reader = Reader::new(extensions);
    let mut types = Vec::with_capacity(extensions.len() / 4);
    while reader.remaining() != 0 {
        let extension_type = reader.read_u16().expect("validated extension type");
        let extension_len = reader.read_u16().expect("validated extension length");
        reader
            .skip(extension_len as usize)
            .expect("validated extension data");
        if Some(extension_type) != exclude {
            types.push(extension_type);
        }
    }
    types
}

fn u16_vector(data: Option<&[u8]>) -> &[u8] {
    let Some(data) = data else { return &[] };
    let Some(length) = data.get(..2) else {
        return &[];
    };
    let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
    data.get(2..2 + length)
        .filter(|values| values.len() % 2 == 0)
        .unwrap_or_default()
}

fn parse_sni(data: &[u8]) -> Option<&str> {
    let list_len = usize::from(u16::from_be_bytes([*data.first()?, *data.get(1)?]));
    let list = data.get(2..2 + list_len)?;
    let mut reader = Reader::new(list);
    while reader.remaining() > 0 {
        let name_type = reader.read_u8()?;
        let name_len = reader.read_u16()? as usize;
        let name = reader.read_exact(name_len)?;
        if name_type == 0 {
            let name = std::str::from_utf8(name).ok()?;
            return (!name.is_empty()).then_some(name);
        }
    }
    None
}

fn ja4_from_client_hello(hello: &ClientHelloData<'_>) -> String {
    let version = ja4_tls_version(hello);
    let cipher_suites = non_grease_sorted_bytes(hello.cipher_suites);
    let extensions = non_grease_sorted(&extension_types(
        hello.extensions,
        Some(TLS_EXTENSION_SERVER_NAME),
    ));
    let signature_algorithms = non_grease_sorted_bytes(u16_vector(hello.signature_algorithms));
    let alpn = ja4_alpn(hello.alpn_protocols);

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

fn ja3_from_client_hello(hello: &ClientHelloData<'_>) -> String {
    format!(
        "{},{},{},{},{}",
        hello.legacy_version,
        format_u16_decimal_bytes(hello.cipher_suites),
        format_u16_decimal_list(&non_grease_in_order(&extension_types(
            hello.extensions,
            Some(TLS_EXTENSION_SERVER_NAME),
        ))),
        format_u16_decimal_bytes(u16_vector(hello.supported_groups)),
        format_u8_decimal_list(u8_vector(hello.ec_point_formats)),
    )
}

fn ja4_tls_version(hello: &ClientHelloData<'_>) -> String {
    let version = supported_versions(hello.supported_versions)
        .chunks_exact(2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .filter(|version| !is_grease(*version))
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

fn ja4_alpn(data: Option<&[u8]>) -> String {
    let Some(protocol) = first_alpn_protocol(data) else {
        return "00".to_owned();
    };
    let mut alphanumeric = protocol
        .iter()
        .copied()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| byte.to_ascii_lowercase());
    let Some(first) = alphanumeric.next() else {
        return "00".to_owned();
    };
    let last = alphanumeric.last().unwrap_or(first);
    String::from_utf8(vec![first, last]).expect("ASCII ALPN characters")
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

fn non_grease_in_order(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .filter(|value| !is_grease(**value))
        .copied()
        .collect()
}

fn non_grease_sorted_bytes(values: &[u8]) -> Vec<u16> {
    let mut values = values
        .chunks_exact(2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .filter(|value| !is_grease(*value))
        .collect::<Vec<_>>();
    values.sort_unstable();
    values
}

fn is_grease(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0x00ff)
}

fn format_u16_list(values: &[u16]) -> String {
    let mut output = String::with_capacity(values.len().saturating_mul(5));
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write!(output, "{value:04x}").expect("writing to String cannot fail");
    }
    output
}

fn format_u16_decimal_list(values: &[u16]) -> String {
    let mut output = String::new();
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push('-');
        }
        write!(output, "{value}").expect("writing to String cannot fail");
    }
    output
}

fn format_u16_decimal_bytes(values: &[u8]) -> String {
    let mut output = String::new();
    for value in values
        .chunks_exact(2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .filter(|value| !is_grease(*value))
    {
        if !output.is_empty() {
            output.push('-');
        }
        write!(output, "{value}").expect("writing to String cannot fail");
    }
    output
}

fn u8_vector(data: Option<&[u8]>) -> &[u8] {
    let Some(data) = data else { return &[] };
    let Some((&length, values)) = data.split_first() else {
        return &[];
    };
    values.get(..usize::from(length)).unwrap_or_default()
}

fn supported_versions(data: Option<&[u8]>) -> &[u8] {
    let Some(data) = data else { return &[] };
    let Some((&length, values)) = data.split_first() else {
        return &[];
    };
    values
        .get(..usize::from(length))
        .filter(|versions| versions.len() % 2 == 0)
        .unwrap_or_default()
}

fn first_alpn_protocol(data: Option<&[u8]>) -> Option<&[u8]> {
    let data = data?;
    let length = usize::from(u16::from_be_bytes([*data.first()?, *data.get(1)?]));
    let list = data.get(2..2 + length)?;
    let (&protocol_length, protocol) = list.split_first()?;
    protocol.get(..usize::from(protocol_length))
}

fn format_u8_decimal_list(values: &[u8]) -> String {
    let mut output = String::new();
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push('-');
        }
        write!(output, "{value}").expect("writing to String cannot fail");
    }
    output
}

fn sha256_12_hex(input: &str) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, input.as_bytes());
    hex::encode(&digest.as_ref()[..6])
}

fn read_u24(bytes: &[u8]) -> usize {
    ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize
}

/// Return the JA4X construction fingerprint for one DER X.509 certificate.
///
/// JA4X deliberately excludes attribute and extension values; it fingerprints
/// the ordered issuer RDN OIDs, subject RDN OIDs, and extension OIDs instead.
pub(crate) fn ja4x_from_certificate(certificate_der: &[u8]) -> Option<String> {
    let (_, certificate) = parse_x509_certificate(certificate_der).ok()?;
    let issuer = certificate
        .issuer()
        .iter_attributes()
        .map(|attribute| oid_content_hex(attribute.attr_type().to_id_string()))
        .collect::<Option<Vec<_>>>()?;
    let subject = certificate
        .subject()
        .iter_attributes()
        .map(|attribute| oid_content_hex(attribute.attr_type().to_id_string()))
        .collect::<Option<Vec<_>>>()?;
    let extensions = certificate
        .extensions()
        .iter()
        .map(|extension| oid_content_hex(extension.oid.to_id_string()))
        .collect::<Option<Vec<_>>>()?;
    Some(format!(
        "{}_{}_{}",
        sha256_12_hex(&issuer.join(",")),
        sha256_12_hex(&subject.join(",")),
        sha256_12_hex(&extensions.join(","))
    ))
}

fn oid_content_hex(oid: String) -> Option<String> {
    let mut arcs = oid.split('.').map(str::parse::<u64>);
    let first = arcs.next()?.ok()?;
    let second = arcs.next()?.ok()?;
    if first > 2 || (first < 2 && second > 39) {
        return None;
    }
    let mut bytes = Vec::new();
    encode_base128(first * 40 + second, &mut bytes);
    for arc in arcs {
        encode_base128(arc.ok()?, &mut bytes);
    }
    Some(hex::encode(bytes))
}

fn encode_base128(value: u64, output: &mut Vec<u8>) {
    let mut bytes = [0u8; 10];
    let mut start = bytes.len() - 1;
    bytes[start] = (value & 0x7f) as u8;
    let mut remaining = value >> 7;
    while remaining != 0 {
        start -= 1;
        bytes[start] = ((remaining & 0x7f) as u8) | 0x80;
        remaining >>= 7;
    }
    output.extend_from_slice(&bytes[start..]);
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
        assert_eq!(
            ja3_from_client_hello(&without_sni),
            ja3_from_client_hello(&with_sni)
        );
    }

    #[test]
    fn ja3_uses_ordered_non_grease_tls_parameters() {
        let hello = test_client_hello(vec![
            (TLS_EXTENSION_SUPPORTED_GROUPS, vec![0x00, 0x02, 0x00, 0x17]),
            (TLS_EXTENSION_EC_POINT_FORMATS, vec![0x01, 0x00]),
        ]);
        let hello = parse_client_hello(&hello).expect("parse ClientHello");

        assert_eq!(ja3_from_client_hello(&hello), "771,4865-4866,10-11,23,0");
    }

    #[test]
    fn ja4x_ignores_certificate_attribute_values() {
        let first = rcgen::generate_simple_self_signed(vec!["first.example".to_owned()])
            .expect("generate first certificate");
        let second = rcgen::generate_simple_self_signed(vec!["second.example".to_owned()])
            .expect("generate second certificate");

        let first = ja4x_from_certificate(first.cert.der()).expect("first JA4X");
        let second = ja4x_from_certificate(second.cert.der()).expect("second JA4X");
        assert_eq!(first, second);
        assert!(
            first.split('_').all(|part| part.len() == 12),
            "JA4X must contain three 12-character SHA-256 prefixes: {first}"
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
        let server_handshake = accept_tls_with_fingerprints(server_io, &server_acceptor);
        let client_handshake = client_connector.connect(
            ServerName::try_from("localhost").expect("static server name"),
            FragmentingIo::new(client_io, 1),
        );
        let (server_result, client_result) = tokio::join!(server_handshake, client_handshake);

        let (_server_tls, fingerprints) = server_result.expect("server TLS handshake");
        let tls_ja4 = fingerprints.ja4.expect("JA4");
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
