use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::future::join_all;
use tokio::net::{UdpSocket, lookup_host};
use tokio::time::timeout;
use tracing::debug;

use crate::geoip::{NodeGeo, valid_coordinates};
use crate::http_client;

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const STUN_HEADER_LEN: usize = 20;
const STUN_MAX_RESPONSE_LEN: usize = 1500;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_SERVERS: &[&str] = &[
    "stun.cloudflare.com:3478",
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
];
const IPV4_PROBE_URLS: &[&str] = &["https://ipv4-check-perf.radar.cloudflare.com/"];
const IPV6_PROBE_URLS: &[&str] = &["https://ipv6-check-perf.radar.cloudflare.com/"];

#[derive(Debug, Clone, Copy)]
enum IpFamily {
    V4,
    V6,
}

static STUN_TRANSACTION_COUNTER: AtomicU64 = AtomicU64::new(1);

pub(crate) async fn discover_public_ips() -> Vec<IpAddr> {
    let (stun_ips, https_ips) = tokio::join!(
        discover_public_ips_via_stun(),
        discover_public_ips_via_https()
    );

    let mut out = Vec::new();
    extend_unique(&mut out, stun_ips);
    extend_unique(&mut out, https_ips);
    out
}

pub(crate) async fn discover_public_geo() -> Option<NodeGeo> {
    let client = match http_client::build_with_webpki_fallback(PROBE_TIMEOUT, "public geo probe") {
        Ok(client) => client,
        Err(e) => {
            debug!(error=%e, "failed to build public geo probe HTTP client");
            return None;
        }
    };

    let probes = IPV4_PROBE_URLS
        .iter()
        .copied()
        .map(|url| probe_geo_url(&client, url, IpFamily::V4))
        .chain(
            IPV6_PROBE_URLS
                .iter()
                .copied()
                .map(|url| probe_geo_url(&client, url, IpFamily::V6)),
        );

    join_all(probes).await.into_iter().flatten().next()
}

async fn discover_public_ips_via_stun() -> Vec<IpAddr> {
    let probes = STUN_SERVERS.iter().copied().map(probe_stun_server);

    let mut out = Vec::new();
    for ip in join_all(probes).await.into_iter().flatten() {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

async fn probe_stun_server(server: &str) -> Vec<IpAddr> {
    let addrs = match timeout(PROBE_TIMEOUT, lookup_host(server)).await {
        Ok(Ok(addrs)) => addrs.collect::<Vec<_>>(),
        Ok(Err(e)) => {
            debug!(server, error=%e, "STUN public IP probe DNS lookup failed");
            return Vec::new();
        }
        Err(_) => {
            debug!(server, "STUN public IP probe DNS lookup timed out");
            return Vec::new();
        }
    };

    let probes = addrs.into_iter().map(|addr| probe_stun_addr(server, addr));
    let mut out = Vec::new();
    for ip in join_all(probes).await.into_iter().flatten() {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

async fn probe_stun_addr(server: &str, remote: SocketAddr) -> Option<IpAddr> {
    let local = if remote.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let socket = match UdpSocket::bind(local).await {
        Ok(socket) => socket,
        Err(e) => {
            debug!(server, %remote, error=%e, "STUN public IP probe bind failed");
            return None;
        }
    };
    if let Err(e) = socket.connect(remote).await {
        debug!(server, %remote, error=%e, "STUN public IP probe connect failed");
        return None;
    }

    let transaction_id = new_stun_transaction_id();
    let request = build_stun_binding_request(transaction_id);
    match timeout(PROBE_TIMEOUT, socket.send(&request)).await {
        Ok(Ok(sent)) if sent == request.len() => {}
        Ok(Ok(sent)) => {
            debug!(
                server,
                %remote,
                sent,
                expected = request.len(),
                "STUN public IP probe sent partial request"
            );
            return None;
        }
        Ok(Err(e)) => {
            debug!(server, %remote, error=%e, "STUN public IP probe send failed");
            return None;
        }
        Err(_) => {
            debug!(server, %remote, "STUN public IP probe send timed out");
            return None;
        }
    }

    let mut buf = [0u8; STUN_MAX_RESPONSE_LEN];
    let len = match timeout(PROBE_TIMEOUT, socket.recv(&mut buf)).await {
        Ok(Ok(len)) => len,
        Ok(Err(e)) => {
            debug!(server, %remote, error=%e, "STUN public IP probe receive failed");
            return None;
        }
        Err(_) => {
            debug!(server, %remote, "STUN public IP probe timed out");
            return None;
        }
    };

    parse_stun_binding_response(&buf[..len], transaction_id).or_else(|| {
        debug!(server, %remote, response_len = len, "STUN public IP probe response was unusable");
        None
    })
}

fn new_stun_transaction_id() -> [u8; 12] {
    let counter = STUN_TRANSACTION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let value = now ^ u128::from(counter);
    let bytes = value.to_be_bytes();
    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&bytes[4..]);
    transaction_id
}

fn build_stun_binding_request(transaction_id: [u8; 12]) -> [u8; STUN_HEADER_LEN] {
    let mut request = [0u8; STUN_HEADER_LEN];
    request[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    request[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    request[8..20].copy_from_slice(&transaction_id);
    request
}

fn parse_stun_binding_response(buf: &[u8], transaction_id: [u8; 12]) -> Option<IpAddr> {
    if buf.len() < STUN_HEADER_LEN {
        return None;
    }

    let message_type = u16::from_be_bytes([buf[0], buf[1]]);
    if message_type != STUN_BINDING_SUCCESS_RESPONSE {
        return None;
    }

    let message_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let attrs_end = STUN_HEADER_LEN.checked_add(message_len)?;
    if attrs_end > buf.len() {
        return None;
    }

    let magic_cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if magic_cookie != STUN_MAGIC_COOKIE || buf[8..20] != transaction_id[..] {
        return None;
    }

    let mut mapped_address = None;
    let mut offset = STUN_HEADER_LEN;
    while offset + 4 <= attrs_end {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        let value_start = offset + 4;
        let value_end = value_start.checked_add(attr_len)?;
        if value_end > attrs_end {
            return None;
        }

        let value = &buf[value_start..value_end];
        match attr_type {
            STUN_ATTR_XOR_MAPPED_ADDRESS => {
                return parse_xor_mapped_address(value, transaction_id)
                    .filter(|ip| is_publicly_routable_ip(*ip));
            }
            STUN_ATTR_MAPPED_ADDRESS if mapped_address.is_none() => {
                mapped_address =
                    parse_mapped_address(value).filter(|ip| is_publicly_routable_ip(*ip));
            }
            _ => {}
        }

        offset = value_end.checked_add(stun_padding(attr_len))?;
    }

    mapped_address
}

fn parse_xor_mapped_address(value: &[u8], transaction_id: [u8; 12]) -> Option<IpAddr> {
    if value.len() < 4 || value[0] != 0 {
        return None;
    }

    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
    match value[1] {
        0x01 => {
            if value.len() < 8 {
                return None;
            }
            let mut octets = [0u8; 4];
            for i in 0..4 {
                octets[i] = value[4 + i] ^ cookie[i];
            }
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        0x02 => {
            if value.len() < 20 {
                return None;
            }
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&cookie);
            mask[4..].copy_from_slice(&transaction_id);
            let mut octets = [0u8; 16];
            for i in 0..16 {
                octets[i] = value[4 + i] ^ mask[i];
            }
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn parse_mapped_address(value: &[u8]) -> Option<IpAddr> {
    if value.len() < 4 || value[0] != 0 {
        return None;
    }

    match value[1] {
        0x01 => {
            if value.len() < 8 {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                value[4], value[5], value[6], value[7],
            )))
        }
        0x02 => {
            if value.len() < 20 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn stun_padding(attr_len: usize) -> usize {
    (4 - (attr_len % 4)) % 4
}

async fn discover_public_ips_via_https() -> Vec<IpAddr> {
    let client = match http_client::build_with_webpki_fallback(PROBE_TIMEOUT, "public IP probe") {
        Ok(client) => client,
        Err(e) => {
            debug!(error=%e, "failed to build public IP probe HTTP client");
            return Vec::new();
        }
    };

    let probes = IPV4_PROBE_URLS
        .iter()
        .copied()
        .map(|url| probe_url(&client, url, IpFamily::V4))
        .chain(
            IPV6_PROBE_URLS
                .iter()
                .copied()
                .map(|url| probe_url(&client, url, IpFamily::V6)),
        );

    let mut out = Vec::new();
    for ip in join_all(probes).await.into_iter().flatten() {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

fn extend_unique(out: &mut Vec<IpAddr>, ips: impl IntoIterator<Item = IpAddr>) {
    for ip in ips {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
}

async fn probe_url(client: &reqwest::Client, url: &str, family: IpFamily) -> Option<IpAddr> {
    let response = match client.get(url).send().await {
        Ok(response) => response,
        Err(e) => {
            debug!(url, error=%e, "public IP probe request failed");
            return None;
        }
    };
    let response = match response.error_for_status() {
        Ok(response) => response,
        Err(e) => {
            debug!(url, error=%e, "public IP probe returned error status");
            return None;
        }
    };
    let body = match response.text().await {
        Ok(body) => body,
        Err(e) => {
            debug!(url, error=%e, "public IP probe body read failed");
            return None;
        }
    };
    parse_public_ip(&body, family).or_else(|| {
        debug!(url, body=%body.trim(), ?family, "public IP probe response was not a usable IP");
        None
    })
}

async fn probe_geo_url(client: &reqwest::Client, url: &str, family: IpFamily) -> Option<NodeGeo> {
    let response = match client.get(url).send().await {
        Ok(response) => response,
        Err(e) => {
            debug!(url, error=%e, "public geo probe request failed");
            return None;
        }
    };
    let response = match response.error_for_status() {
        Ok(response) => response,
        Err(e) => {
            debug!(url, error=%e, "public geo probe returned error status");
            return None;
        }
    };
    let body = match response.text().await {
        Ok(body) => body,
        Err(e) => {
            debug!(url, error=%e, "public geo probe body read failed");
            return None;
        }
    };
    parse_cloudflare_check_perf_geo(&body, family).or_else(|| {
        debug!(url, body=%body.trim(), ?family, "public geo probe response was not usable");
        None
    })
}

fn parse_public_ip(value: &str, family: IpFamily) -> Option<IpAddr> {
    let ip =
        parse_public_ip_literal(value).or_else(|| parse_cloudflare_ip_check_response(value))?;
    match (family, ip) {
        (IpFamily::V4, IpAddr::V4(_)) | (IpFamily::V6, IpAddr::V6(_)) => {
            is_publicly_routable_ip(ip).then_some(ip)
        }
        _ => None,
    }
}

fn parse_public_ip_literal(value: &str) -> Option<IpAddr> {
    value.split_whitespace().next()?.parse::<IpAddr>().ok()
}

fn parse_cloudflare_ip_check_response(value: &str) -> Option<IpAddr> {
    let response = serde_json::from_str::<serde_json::Value>(value).ok()?;
    response.get("ip_address")?.as_str()?.parse::<IpAddr>().ok()
}

#[derive(serde::Deserialize)]
struct CloudflareCheckPerfResponse {
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
    latitude: Option<String>,
    longitude: Option<String>,
    ip_address: Option<String>,
    ip_version: Option<String>,
}

fn parse_cloudflare_check_perf_geo(value: &str, family: IpFamily) -> Option<NodeGeo> {
    let response = serde_json::from_str::<CloudflareCheckPerfResponse>(value).ok()?;
    let ip = response.ip_address.as_deref()?.parse::<IpAddr>().ok()?;
    if !matches_probe_family(ip, family) || !is_publicly_routable_ip(ip) {
        return None;
    }
    if !response_ip_version_matches(response.ip_version.as_deref(), family) {
        return None;
    }
    let latitude = response.latitude.as_deref()?.parse::<f64>().ok()?;
    let longitude = response.longitude.as_deref()?.parse::<f64>().ok()?;
    if !valid_coordinates(latitude, longitude) {
        return None;
    }
    NodeGeo::new(
        latitude,
        longitude,
        response.city,
        response.region,
        response.country,
        "cloudflare_check_perf",
    )
}

fn matches_probe_family(ip: IpAddr, family: IpFamily) -> bool {
    matches!(
        (family, ip),
        (IpFamily::V4, IpAddr::V4(_)) | (IpFamily::V6, IpAddr::V6(_))
    )
}

fn response_ip_version_matches(ip_version: Option<&str>, family: IpFamily) -> bool {
    match (ip_version.map(str::trim), family) {
        (None, _) => true,
        (Some("IPv4"), IpFamily::V4) | (Some("IPv6"), IpFamily::V6) => true,
        _ => false,
    }
}

fn is_publicly_routable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_private()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && octets[0] != 0
                && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
                && !(octets[0] == 198 && (18..=19).contains(&octets[1]))
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !((segments[0] & 0xfe00) == 0xfc00)
                && !((segments[0] & 0xffc0) == 0xfe80)
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ip_probe_urls_are_family_specific() {
        assert_eq!(
            IPV4_PROBE_URLS,
            &["https://ipv4-check-perf.radar.cloudflare.com/"]
        );
        assert_eq!(
            IPV6_PROBE_URLS,
            &["https://ipv6-check-perf.radar.cloudflare.com/"]
        );
    }

    #[test]
    fn parse_public_ip_accepts_matching_public_family() {
        assert_eq!(
            parse_public_ip("8.8.8.8\n", IpFamily::V4),
            Some("8.8.8.8".parse().unwrap())
        );
        assert_eq!(
            parse_public_ip("2001:4860:4860::8888\n", IpFamily::V6),
            Some("2001:4860:4860::8888".parse().unwrap())
        );
    }

    #[test]
    fn parse_public_ip_accepts_cloudflare_check_response() {
        assert_eq!(
            parse_public_ip(
                r#"{"ip_address":"1.1.1.1","ip_version":"IPv4"}"#,
                IpFamily::V4
            ),
            Some("1.1.1.1".parse().unwrap())
        );
        assert_eq!(
            parse_public_ip(
                r#"{"ip_address":"2606:4700:4700::1111","ip_version":"IPv6"}"#,
                IpFamily::V6,
            ),
            Some("2606:4700:4700::1111".parse().unwrap())
        );
    }

    #[test]
    fn parse_public_ip_rejects_wrong_family_from_probe_endpoint() {
        assert_eq!(
            parse_public_ip(
                r#"{
                    "ip_address": "2607:5300:205:200::80fa",
                    "ip_version": "IPv6"
                }"#,
                IpFamily::V4,
            ),
            None
        );
    }

    #[test]
    fn parse_public_ip_rejects_wrong_or_private_family() {
        assert_eq!(parse_public_ip("8.8.8.8", IpFamily::V6), None);
        assert_eq!(parse_public_ip("10.0.0.1", IpFamily::V4), None);
        assert_eq!(parse_public_ip("::1", IpFamily::V6), None);
    }

    #[test]
    fn parse_cloudflare_check_perf_geo_accepts_location_payload() {
        let geo = parse_cloudflare_check_perf_geo(
            r#"{
                "colo": "IAH",
                "asn": 11427,
                "continent": "NA",
                "country": "US",
                "region": "Texas",
                "city": "Plano",
                "latitude": "33.01984",
                "longitude": "-96.69889",
                "ip_address": "76.187.192.63",
                "ip_version": "IPv4"
            }"#,
            IpFamily::V4,
        )
        .expect("geo");

        assert_eq!(geo.latitude(), 33.01984);
        assert_eq!(geo.longitude(), -96.69889);
        assert_eq!(geo.city(), Some("Plano"));
        assert_eq!(geo.region(), Some("Texas"));
        assert_eq!(geo.country(), Some("US"));
        assert_eq!(geo.source(), "cloudflare_check_perf");
    }

    #[test]
    fn parse_cloudflare_check_perf_geo_rejects_wrong_family() {
        assert_eq!(
            parse_cloudflare_check_perf_geo(
                r#"{
                    "country": "US",
                    "region": "Texas",
                    "city": "Plano",
                    "latitude": "33.01984",
                    "longitude": "-96.69889",
                    "ip_address": "2606:4700:4700::1111",
                    "ip_version": "IPv6"
                }"#,
                IpFamily::V4,
            ),
            None
        );
    }

    #[test]
    fn parse_stun_binding_response_accepts_xor_mapped_ipv4() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));
        let response = stun_response(
            transaction_id,
            STUN_ATTR_XOR_MAPPED_ADDRESS,
            xor_mapped_attr(ip, transaction_id),
        );

        assert_eq!(
            parse_stun_binding_response(&response, transaction_id),
            Some(ip)
        );
    }

    #[test]
    fn parse_stun_binding_response_accepts_xor_mapped_ipv6() {
        let transaction_id = [12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
        let ip = IpAddr::V6("2001:4860:4860::8888".parse().unwrap());
        let response = stun_response(
            transaction_id,
            STUN_ATTR_XOR_MAPPED_ADDRESS,
            xor_mapped_attr(ip, transaction_id),
        );

        assert_eq!(
            parse_stun_binding_response(&response, transaction_id),
            Some(ip)
        );
    }

    #[test]
    fn parse_stun_binding_response_uses_mapped_address_fallback() {
        let transaction_id = [7, 7, 7, 7, 6, 6, 6, 6, 5, 5, 5, 5];
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let response = stun_response(transaction_id, STUN_ATTR_MAPPED_ADDRESS, mapped_attr(ip));

        assert_eq!(
            parse_stun_binding_response(&response, transaction_id),
            Some(ip)
        );
    }

    #[test]
    fn parse_stun_binding_response_rejects_wrong_transaction_id() {
        let transaction_id = [1; 12];
        let response = stun_response(
            transaction_id,
            STUN_ATTR_XOR_MAPPED_ADDRESS,
            xor_mapped_attr(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), transaction_id),
        );

        assert_eq!(parse_stun_binding_response(&response, [2; 12]), None);
    }

    fn stun_response(transaction_id: [u8; 12], attr_type: u16, attr_value: Vec<u8>) -> Vec<u8> {
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&attr_type.to_be_bytes());
        attrs.extend_from_slice(&(attr_value.len() as u16).to_be_bytes());
        attrs.extend_from_slice(&attr_value);
        attrs.resize(attrs.len() + stun_padding(attr_value.len()), 0);

        let mut response = vec![0u8; STUN_HEADER_LEN];
        response[0..2].copy_from_slice(&STUN_BINDING_SUCCESS_RESPONSE.to_be_bytes());
        response[2..4].copy_from_slice(&(attrs.len() as u16).to_be_bytes());
        response[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response[8..20].copy_from_slice(&transaction_id);
        response.extend_from_slice(&attrs);
        response
    }

    fn xor_mapped_attr(ip: IpAddr, transaction_id: [u8; 12]) -> Vec<u8> {
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        let mut value = Vec::new();
        value.push(0);
        match ip {
            IpAddr::V4(ip) => {
                value.push(0x01);
                value.extend_from_slice(
                    &(9999u16 ^ ((STUN_MAGIC_COOKIE >> 16) as u16)).to_be_bytes(),
                );
                value.extend(
                    ip.octets()
                        .iter()
                        .enumerate()
                        .map(|(i, octet)| *octet ^ cookie[i]),
                );
            }
            IpAddr::V6(ip) => {
                value.push(0x02);
                value.extend_from_slice(
                    &(9999u16 ^ ((STUN_MAGIC_COOKIE >> 16) as u16)).to_be_bytes(),
                );
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&cookie);
                mask[4..].copy_from_slice(&transaction_id);
                value.extend(
                    ip.octets()
                        .iter()
                        .enumerate()
                        .map(|(i, octet)| *octet ^ mask[i]),
                );
            }
        }
        value
    }

    fn mapped_attr(ip: IpAddr) -> Vec<u8> {
        let mut value = Vec::new();
        value.push(0);
        match ip {
            IpAddr::V4(ip) => {
                value.push(0x01);
                value.extend_from_slice(&9999u16.to_be_bytes());
                value.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                value.push(0x02);
                value.extend_from_slice(&9999u16.to_be_bytes());
                value.extend_from_slice(&ip.octets());
            }
        }
        value
    }
}
