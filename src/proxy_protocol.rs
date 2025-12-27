use std::{fmt::Display, future::poll_fn, result::Result};

use ppp::{HeaderResult, PartialResult as _};
use tokio::io::ReadBuf;

use crate::errors::ProxyProtocolHeaderTooLargeError;

pub fn convert_v1_addresses_to_ipaddr(addresses: ppp::v1::Addresses) -> Option<std::net::IpAddr> {
    match addresses {
        ppp::v1::Addresses::Tcp4(addr) => Some(std::net::IpAddr::V4(addr.source_address)),
        ppp::v1::Addresses::Tcp6(addr) => Some(std::net::IpAddr::V6(addr.source_address)),
        _ => None,
    }
}

pub fn convert_v2_addresses_to_ipaddr(addresses: ppp::v2::Addresses) -> Option<std::net::IpAddr> {
    match addresses {
        ppp::v2::Addresses::IPv4(addr) => Some(std::net::IpAddr::V4(addr.source_address)),
        ppp::v2::Addresses::IPv6(addr) => Some(std::net::IpAddr::V6(addr.source_address)),
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
    let mut buffer = Vec::with_capacity(1600);
    let header = {
        let mut read = 0;

        loop {
            let mut buffer_bufread = ReadBuf::new(&mut buffer[read..]);

            read += poll_fn(|cx| tcp_stream.poll_peek(cx, &mut buffer_bufread)).await?;

            let header = HeaderResult::parse(&buffer[..read]);

            if header.is_complete() {
                break header;
            }

            if buffer.len() > 16384 {
                return Err(ProxyProtocolHeaderTooLargeError::new(16384, buffer.len()).into());
            }

            if buffer.len() == buffer.capacity() {
                buffer.reserve(1600);
            }
        }
    };

    match header {
        HeaderResult::V2(Ok(header)) => Ok(convert_v2_addresses_to_ipaddr(header.addresses)),
        HeaderResult::V1(Ok(header)) => Ok(convert_v1_addresses_to_ipaddr(header.addresses)),
        _ => Ok(None),
    }
}
