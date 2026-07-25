use std::{fmt::Display, result::Result};

use crate::errors::ProxyProtocolHeaderTooLargeError;
use ppp::{HeaderResult, PartialResult as _};
use tokio::io::AsyncReadExt as _;

const PROXY_PROTOCOL_MAX_HEADER_LEN: usize = 16_384;
const PROXY_PROTOCOL_V2_MINIMUM_LENGTH: usize = 16;

#[derive(Clone, Copy, Debug)]
pub struct ProxiedClientAddress {
    ip: std::net::IpAddr,
    port: u16,
}

impl ProxiedClientAddress {
    pub fn ip(&self) -> std::net::IpAddr {
        self.ip
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ProxyProtocolConnectionInfo {
    client_address: Option<ProxiedClientAddress>,
    header_len: usize,
}

impl ProxyProtocolConnectionInfo {
    pub fn client_address(&self) -> Option<ProxiedClientAddress> {
        self.client_address
    }

    pub fn header_len(&self) -> usize {
        self.header_len
    }
}

pub fn convert_v1_addresses_to_ipaddr(addresses: ppp::v1::Addresses) -> Option<std::net::IpAddr> {
    convert_v1_addresses_to_client_address(addresses).map(|addr| addr.ip())
}

pub fn convert_v1_addresses_to_client_address(
    addresses: ppp::v1::Addresses,
) -> Option<ProxiedClientAddress> {
    match addresses {
        ppp::v1::Addresses::Tcp4(addr) => Some(ProxiedClientAddress {
            ip: std::net::IpAddr::V4(addr.source_address),
            port: addr.source_port,
        }),
        ppp::v1::Addresses::Tcp6(addr) => Some(ProxiedClientAddress {
            ip: std::net::IpAddr::V6(addr.source_address),
            port: addr.source_port,
        }),
        _ => None,
    }
}

pub fn convert_v2_addresses_to_ipaddr(addresses: ppp::v2::Addresses) -> Option<std::net::IpAddr> {
    convert_v2_addresses_to_client_address(addresses).map(|addr| addr.ip())
}

pub fn convert_v2_addresses_to_client_address(
    addresses: ppp::v2::Addresses,
) -> Option<ProxiedClientAddress> {
    match addresses {
        ppp::v2::Addresses::IPv4(addr) => Some(ProxiedClientAddress {
            ip: std::net::IpAddr::V4(addr.source_address),
            port: addr.source_port,
        }),
        ppp::v2::Addresses::IPv6(addr) => Some(ProxiedClientAddress {
            ip: std::net::IpAddr::V6(addr.source_address),
            port: addr.source_port,
        }),
        _ => None,
    }
}

#[derive(Debug)]
pub enum GetProxyProtocolRealIpError {
    ProxyProtocolHeaderTooLarge(ProxyProtocolHeaderTooLargeError),
    IOError(std::io::Error),
}

impl From<std::io::Error> for GetProxyProtocolRealIpError {
    fn from(err: std::io::Error) -> Self {
        GetProxyProtocolRealIpError::IOError(err)
    }
}

impl From<ProxyProtocolHeaderTooLargeError> for GetProxyProtocolRealIpError {
    fn from(err: ProxyProtocolHeaderTooLargeError) -> Self {
        GetProxyProtocolRealIpError::ProxyProtocolHeaderTooLarge(err)
    }
}

impl Display for GetProxyProtocolRealIpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetProxyProtocolRealIpError::IOError(err) => write!(f, "IO error: {}", err),
            GetProxyProtocolRealIpError::ProxyProtocolHeaderTooLarge(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for GetProxyProtocolRealIpError {}

pub async fn get_proxy_protocol_real_ip(
    tcp_stream: &tokio::net::TcpStream,
) -> Result<Option<std::net::IpAddr>, GetProxyProtocolRealIpError> {
    Ok(get_proxy_protocol_client_address(tcp_stream)
        .await?
        .map(|addr| addr.ip()))
}

pub async fn get_proxy_protocol_client_address(
    tcp_stream: &tokio::net::TcpStream,
) -> Result<Option<ProxiedClientAddress>, GetProxyProtocolRealIpError> {
    Ok(peek_proxy_protocol_connection_info(tcp_stream)
        .await?
        .and_then(|info| info.client_address()))
}

pub async fn consume_proxy_protocol_connection_info(
    tcp_stream: &mut tokio::net::TcpStream,
) -> Result<Option<ProxyProtocolConnectionInfo>, GetProxyProtocolRealIpError> {
    let mut first = [0u8; 1];
    if tcp_stream.peek(&mut first).await? == 0 {
        return Ok(None);
    }

    match first[0] {
        b'P' => consume_proxy_protocol_v1(tcp_stream).await,
        b'\r' => consume_proxy_protocol_v2(tcp_stream).await,
        _ => Ok(None),
    }
}

async fn consume_proxy_protocol_v1(
    tcp_stream: &mut tokio::net::TcpStream,
) -> Result<Option<ProxyProtocolConnectionInfo>, GetProxyProtocolRealIpError> {
    let mut buffer = Vec::new();
    loop {
        if buffer.len() >= PROXY_PROTOCOL_MAX_HEADER_LEN {
            return Err(ProxyProtocolHeaderTooLargeError::new(
                PROXY_PROTOCOL_MAX_HEADER_LEN,
                buffer.len(),
            )
            .into());
        }

        let mut byte = [0u8; 1];
        tcp_stream.read_exact(&mut byte).await?;
        buffer.push(byte[0]);

        if !starts_with_or_is_prefix(&buffer, ppp::v1::PROTOCOL_PREFIX.as_bytes()) {
            return Err(invalid_proxy_protocol_header_error().into());
        }

        if buffer.ends_with(ppp::v1::PROTOCOL_SUFFIX.as_bytes()) {
            return proxy_protocol_connection_info(HeaderResult::parse(&buffer))
                .ok_or_else(|| invalid_proxy_protocol_header_error().into())
                .map(Some);
        }
    }
}

async fn consume_proxy_protocol_v2(
    tcp_stream: &mut tokio::net::TcpStream,
) -> Result<Option<ProxyProtocolConnectionInfo>, GetProxyProtocolRealIpError> {
    let mut header = vec![0u8; PROXY_PROTOCOL_V2_MINIMUM_LENGTH];
    tcp_stream.read_exact(&mut header).await?;
    if !header.starts_with(ppp::v2::PROTOCOL_PREFIX) {
        return Err(invalid_proxy_protocol_header_error().into());
    }

    let payload_len = u16::from_be_bytes([header[14], header[15]]) as usize;
    let header_len = PROXY_PROTOCOL_V2_MINIMUM_LENGTH + payload_len;
    if header_len > PROXY_PROTOCOL_MAX_HEADER_LEN {
        return Err(ProxyProtocolHeaderTooLargeError::new(
            PROXY_PROTOCOL_MAX_HEADER_LEN,
            header_len,
        )
        .into());
    }

    header.resize(header_len, 0);
    tcp_stream
        .read_exact(&mut header[PROXY_PROTOCOL_V2_MINIMUM_LENGTH..])
        .await?;
    proxy_protocol_connection_info(HeaderResult::parse(&header))
        .ok_or_else(|| invalid_proxy_protocol_header_error().into())
        .map(Some)
}

async fn peek_proxy_protocol_connection_info(
    tcp_stream: &tokio::net::TcpStream,
) -> Result<Option<ProxyProtocolConnectionInfo>, GetProxyProtocolRealIpError> {
    let mut buffer = vec![0u8; 1600];

    loop {
        let read = tcp_stream.peek(&mut buffer).await?;
        if read == 0 {
            return Ok(None);
        }

        let peeked = &buffer[..read];
        if !could_start_proxy_protocol_header(peeked) {
            return Ok(None);
        }

        let header = HeaderResult::parse(peeked);
        if header.is_complete() {
            return Ok(proxy_protocol_connection_info(header));
        }

        if buffer.len() >= PROXY_PROTOCOL_MAX_HEADER_LEN {
            return Err(ProxyProtocolHeaderTooLargeError::new(
                PROXY_PROTOCOL_MAX_HEADER_LEN,
                buffer.len(),
            )
            .into());
        }

        let next_len = (buffer.len() * 2).min(PROXY_PROTOCOL_MAX_HEADER_LEN);
        buffer.resize(next_len, 0);
    }
}

fn proxy_protocol_connection_info(header: HeaderResult<'_>) -> Option<ProxyProtocolConnectionInfo> {
    match header {
        HeaderResult::V2(Ok(header)) => Some(ProxyProtocolConnectionInfo {
            client_address: convert_v2_addresses_to_client_address(header.addresses),
            header_len: header.len(),
        }),
        HeaderResult::V1(Ok(header)) => Some(ProxyProtocolConnectionInfo {
            client_address: convert_v1_addresses_to_client_address(header.addresses),
            header_len: header.header.len(),
        }),
        _ => None,
    }
}

fn could_start_proxy_protocol_header(input: &[u8]) -> bool {
    starts_with_or_is_prefix(input, ppp::v1::PROTOCOL_PREFIX.as_bytes())
        || starts_with_or_is_prefix(input, ppp::v2::PROTOCOL_PREFIX)
}

fn starts_with_or_is_prefix(input: &[u8], prefix: &[u8]) -> bool {
    input.starts_with(prefix) || input.len() <= prefix.len() && prefix.starts_with(input)
}

fn invalid_proxy_protocol_header_error() -> GetProxyProtocolRealIpError {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid PROXY protocol header",
    )
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::{TcpListener, TcpStream};

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("test listener addr");
        let client = tokio::spawn(async move { TcpStream::connect(addr).await });
        let (server, _) = listener.accept().await.expect("accept test stream");
        let client = client
            .await
            .expect("connect task")
            .expect("connect test stream");
        (server, client)
    }

    #[tokio::test]
    async fn consume_proxy_protocol_missing_header_leaves_stream_untouched() {
        let (mut server, mut client) = tcp_pair().await;
        let tls_prefix = [0x16, 0x03, 0x03, 0x00, 0x2a];
        client
            .write_all(&tls_prefix)
            .await
            .expect("write TLS-looking prefix");

        let info = consume_proxy_protocol_connection_info(&mut server)
            .await
            .expect("missing PROXY header is not an error");
        assert!(info.is_none());

        let mut observed = [0u8; 5];
        server
            .read_exact(&mut observed)
            .await
            .expect("read untouched TLS-looking prefix");
        assert_eq!(observed, tls_prefix);
    }

    #[tokio::test]
    async fn consume_proxy_protocol_corrupt_v1_header_errors() {
        let (mut server, mut client) = tcp_pair().await;
        client
            .write_all(b"PROX nope\r\n")
            .await
            .expect("write corrupt v1 header");

        let err = consume_proxy_protocol_connection_info(&mut server)
            .await
            .expect_err("corrupt PROXY header should error");
        assert!(matches!(
            err,
            GetProxyProtocolRealIpError::IOError(error)
                if error.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[tokio::test]
    async fn consume_proxy_protocol_valid_v1_header_consumes_only_header() {
        let (mut server, mut client) = tcp_pair().await;
        let tls_prefix = [0x16, 0x03, 0x03, 0x00, 0x2a];
        client
            .write_all(b"PROXY TCP4 192.0.2.10 192.0.2.20 12345 64738\r\n")
            .await
            .expect("write valid v1 header");
        client
            .write_all(&tls_prefix)
            .await
            .expect("write TLS-looking prefix");

        let info = consume_proxy_protocol_connection_info(&mut server)
            .await
            .expect("valid PROXY header")
            .expect("PROXY header present");
        let client_address = info.client_address().expect("proxied client address");
        assert_eq!(
            client_address.ip(),
            "192.0.2.10".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(client_address.port(), 12345);

        let mut observed = [0u8; 5];
        server
            .read_exact(&mut observed)
            .await
            .expect("read untouched TLS-looking prefix");
        assert_eq!(observed, tls_prefix);
    }
}
