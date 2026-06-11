use std::io;

use tokio::net::TcpStream;

const TLS_HANDSHAKE_RECORD: u8 = 22;
const TLS_CLIENT_HELLO_HANDSHAKE: u8 = 1;
const TLS_EXTENSION_SERVER_NAME: u16 = 0;
const TLS_EXTENSION_ALPN: u16 = 16;
const TLS_EXTENSION_SIGNATURE_ALGORITHMS: u16 = 13;
const TLS_EXTENSION_SUPPORTED_VERSIONS: u16 = 43;
const INITIAL_CLIENT_HELLO_PEEK_BYTES: usize = 4096;
const MAX_CLIENT_HELLO_PEEK_BYTES: usize = 128 * 1024;
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

pub async fn peek_tls_ja4(tcp_stream: &TcpStream) -> io::Result<Option<String>> {
    let mut capacity = INITIAL_CLIENT_HELLO_PEEK_BYTES;
    loop {
        let mut buffer = vec![0u8; capacity];
        let len = tcp_stream.peek(&mut buffer).await?;
        if len == 0 {
            return Ok(None);
        }

        match parse_tls_client_hello_records(&buffer[..len]) {
            ClientHelloRecordParse::Complete(handshake) => {
                return Ok(parse_client_hello(&handshake).map(|hello| ja4_from_client_hello(&hello)));
            }
            ClientHelloRecordParse::Invalid => return Ok(None),
            ClientHelloRecordParse::Incomplete if len < capacity => return Ok(None),
            ClientHelloRecordParse::Incomplete => {
                if capacity >= MAX_CLIENT_HELLO_PEEK_BYTES {
                    return Ok(None);
                }
                capacity = (capacity * 2).min(MAX_CLIENT_HELLO_PEEK_BYTES);
            }
        }
    }
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
            .copied()
            .filter(|extension| *extension != TLS_EXTENSION_SERVER_NAME)
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
        .copied()
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

fn ja4_alpn(protocols: &[Vec<u8>]) -> String {
    let Some(protocol) = protocols.first() else {
        return "00".to_owned();
    };
    let alnum: Vec<char> = protocol
        .iter()
        .copied()
        .filter(u8::is_ascii_alphanumeric)
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
        .copied()
        .filter(|value| !is_grease(*value))
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

    #[test]
    fn ja4_excludes_sni_from_count_and_hash() {
        let mut without_sni = test_client_hello(vec![(
            TLS_EXTENSION_ALPN,
            vec![0x00, 0x03, 0x02, b'h', b'2'],
        )]);
        let mut with_sni = test_client_hello(vec![
            (
                TLS_EXTENSION_SERVER_NAME,
                vec![
                    0x00, 0x10, 0x00, 0x00, 0x0d, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
                    b'.', b't', b'e', b's', b't',
                ],
            ),
            (
                TLS_EXTENSION_ALPN,
                vec![0x00, 0x03, 0x02, b'h', b'2'],
            ),
        ]);

        let without_sni = parse_client_hello(&without_sni).expect("parse without SNI");
        let with_sni = parse_client_hello(&with_sni).expect("parse with SNI");

        assert_eq!(ja4_from_client_hello(&without_sni), ja4_from_client_hello(&with_sni));
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
