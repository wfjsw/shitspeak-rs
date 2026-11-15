//! Per-client UDP link loss, exposed as Prometheus series.
//!
//! Loss is not measured here: the OCB2 decryptor already classifies every
//! inbound datagram against its nonce window, so a gap in the sequence is a
//! lost packet, a datagram that fills an earlier gap is a late one, and a
//! nonce resync is a window resynchronisation — the key is unchanged, only the
//! nonce is reset. The server-side counters (`local_*`) describe the
//! client→server direction, the counters a client reports in its own pings
//! (`remote_*`) describe the server→client direction. Both live on the
//! client's crypt state, which is why a client without crypt state
//! contributes no series.
//!
//! Series carry `session` (one client) and, around it, the dimensions that
//! decide whether a bad link is one client, a whole population, a region, a
//! city, a network, or one ingress path: `region`, `city`, `lat`/`lon`,
//! `asn`, `subnet`, `entrypoint`. Sessions are the series identity: a
//! reconnect or re-key mints a new session id, so a reset counter never
//! aliases the previous link.

use std::net::{IpAddr, SocketAddr};

use shitspeak_s2s::status::PrometheusSample;

use crate::geoip::ClientGeo;

use super::Client;

pub(crate) const UDP_LINK_UPLINK: &str = "uplink";
pub(crate) const UDP_LINK_DOWNLINK: &str = "downlink";

/// Label used when GeoIP has no answer for a client (private ranges, disabled
/// database, missing record). The label stays present so aggregation never
/// silently drops clients.
pub(crate) const GEO_UNKNOWN: &str = "unknown";

/// Prefix lengths the `subnet` label aggregates to. A /24 for IPv4 and a /48
/// for IPv6 group one customer LAN or one provider allocation without putting
/// a per-IP, fast-churning address into the label set.
const SUBNET_PREFIX_LEN_V4: u8 = 24;
const SUBNET_PREFIX_LEN_V6: u8 = 48;

/// Counter set for one direction of one client's UDP link.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct UdpLinkCounters {
    good: u64,
    late: u64,
    lost: u64,
    resync: u64,
}

impl UdpLinkCounters {
    pub(crate) const fn new(good: u64, late: u64, lost: u64, resync: u64) -> Self {
        Self {
            good,
            late,
            lost,
            resync,
        }
    }

    /// Packets the sender emitted, as far as the nonce window can tell: every
    /// packet is good, late, or never arrived.
    fn sent(&self) -> u64 {
        self.good + self.late + self.lost
    }

    /// Fraction of the sender's packets that never arrived. A gap that a later
    /// packet fills moves the count from `lost` to `late`, so the ratio settles
    /// once reordering has been observed.
    fn loss_ratio(&self) -> f64 {
        let sent = self.sent();
        if sent == 0 {
            return 0.0;
        }
        self.lost as f64 / sent as f64
    }
}

/// GeoIP answer for one client, flattened to label values.
///
/// Coordinates are formatted once here so every dial hashes the same string
/// for the same city instead of a float print per sample.
pub(crate) struct ClientLocation {
    region: String,
    city: String,
    latitude: String,
    longitude: String,
    asn: String,
}

impl ClientLocation {
    pub(crate) fn unknown() -> Self {
        Self {
            region: GEO_UNKNOWN.to_owned(),
            city: GEO_UNKNOWN.to_owned(),
            latitude: String::new(),
            longitude: String::new(),
            asn: GEO_UNKNOWN.to_owned(),
        }
    }

    pub(crate) fn from_geo(geo: Option<&ClientGeo>) -> Self {
        let Some(geo) = geo else {
            return Self::unknown();
        };
        Self {
            region: geo.country().unwrap_or(GEO_UNKNOWN).to_owned(),
            city: geo.city().unwrap_or(GEO_UNKNOWN).to_owned(),
            latitude: geo
                .latitude()
                .map(|latitude| format!("{latitude:.4}"))
                .unwrap_or_default(),
            longitude: geo
                .longitude()
                .map(|longitude| format!("{longitude:.4}"))
                .unwrap_or_default(),
            asn: geo
                .asn()
                .map(|asn| asn.to_string())
                .unwrap_or_else(|| GEO_UNKNOWN.to_owned()),
        }
    }
    pub(crate) fn asn(&self) -> &str {
        &self.asn
    }

    pub(crate) fn region(&self) -> &str {
        &self.region
    }

    pub(crate) fn city(&self) -> &str {
        &self.city
    }

    pub(crate) fn latitude(&self) -> &str {
        &self.latitude
    }

    pub(crate) fn longitude(&self) -> &str {
        &self.longitude
    }
}

/// Where one client's link sits: the dimensions that separate an individual
/// client from a region-wide, city-wide, or path-wide problem.
pub(crate) struct UdpLinkIdentity {
    node_id: u16,
    server_id: String,
    session: u32,
    location: ClientLocation,
    subnet: String,
    entrypoint: SocketAddr,
}

impl UdpLinkIdentity {
    pub(crate) fn new(
        node_id: u16,
        server_id: String,
        session: u32,
        location: ClientLocation,
        subnet: String,
        entrypoint: SocketAddr,
    ) -> Self {
        Self {
            node_id,
            server_id,
            session,
            location,
            subnet,
            entrypoint,
        }
    }
}

/// One client's UDP link, in both directions, ready to render.
pub(crate) struct UdpLinkSeries {
    identity: UdpLinkIdentity,
    uplink: UdpLinkCounters,
    downlink: UdpLinkCounters,
}

impl UdpLinkSeries {
    pub(crate) const fn new(
        identity: UdpLinkIdentity,
        uplink: UdpLinkCounters,
        downlink: UdpLinkCounters,
    ) -> Self {
        Self {
            identity,
            uplink,
            downlink,
        }
    }

    fn labels(&self, direction: &str, result: Option<&str>) -> Vec<(String, String)> {
        let mut labels = Vec::with_capacity(12);
        let location = &self.identity.location;
        labels.push(("node".to_owned(), self.identity.node_id.to_string()));
        labels.push(("server_id".to_owned(), self.identity.server_id.clone()));
        labels.push(("session".to_owned(), self.identity.session.to_string()));
        labels.push(("region".to_owned(), location.region().to_owned()));
        labels.push(("city".to_owned(), location.city().to_owned()));
        labels.push(("lat".to_owned(), location.latitude().to_owned()));
        labels.push(("lon".to_owned(), location.longitude().to_owned()));
        labels.push(("asn".to_owned(), location.asn().to_owned()));
        labels.push(("subnet".to_owned(), self.identity.subnet.clone()));
        labels.push((
            "entrypoint".to_owned(),
            self.identity.entrypoint.to_string(),
        ));
        labels.push(("direction".to_owned(), direction.to_owned()));
        if let Some(result) = result {
            labels.push(("result".to_owned(), result.to_owned()));
        }
        labels
    }

    pub(crate) fn prometheus_samples(&self) -> Vec<PrometheusSample> {
        let mut samples = Vec::with_capacity(10);
        for (direction, counters) in [
            (UDP_LINK_UPLINK, &self.uplink),
            (UDP_LINK_DOWNLINK, &self.downlink),
        ] {
            for (result, value) in [
                ("good", counters.good),
                ("late", counters.late),
                ("lost", counters.lost),
                ("resync", counters.resync),
            ] {
                samples.push(PrometheusSample::new(
                    "shitspeak_client_udp_packets_total",
                    self.labels(direction, Some(result)),
                    value as f64,
                ));
            }
            samples.push(PrometheusSample::new(
                "shitspeak_client_udp_packet_loss_ratio",
                self.labels(direction, None),
                counters.loss_ratio(),
            ));
        }
        samples
    }
}

/// Mask `ip` to the aggregation prefix used by the `subnet` label.
fn client_subnet(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            let mut network = [0u8; 4];
            network[..3].copy_from_slice(&octets[..3]);
            format!(
                "{}/{}",
                std::net::Ipv4Addr::from(network),
                SUBNET_PREFIX_LEN_V4
            )
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            let mut network = [0u16; 8];
            network[..3].copy_from_slice(&segments[..3]);
            format!(
                "{}/{}",
                std::net::Ipv6Addr::from(network),
                SUBNET_PREFIX_LEN_V6
            )
        }
    }
}

/// Build the series for `client`, or `None` when it has no UDP link.
///
/// Callers pass only locally owned clients: a projected remote client carries
/// no crypt state, and its owning node already exports the same link. The
/// caller also passes the already-flattened `location`, because it needs the
/// same GeoIP answer for its client-count buckets and formatting it twice per
/// scrape per client is pure waste.
pub(crate) fn client_udp_link_series(
    client: &Client,
    node_id: u16,
    location: ClientLocation,
) -> Option<UdpLinkSeries> {
    let crypt = client.crypt_state();
    let state = crypt.as_ref()?;
    let (good, late, lost, resync) = state.local_packet_stats();
    let (remote_good, remote_late, remote_lost, remote_resync) = state.remote_packet_stats();
    let identity = UdpLinkIdentity::new(
        node_id,
        client.server_id(),
        u32::from(client.get_session_id()),
        location,
        client_subnet(client.get_real_ip_address()),
        client.get_local_address(),
    );
    Some(UdpLinkSeries::new(
        identity,
        UdpLinkCounters::new(good, late, lost, resync),
        UdpLinkCounters::new(remote_good, remote_late, remote_lost, remote_resync),
    ))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{ClientLocation, UdpLinkCounters, UdpLinkIdentity, UdpLinkSeries, client_subnet};

    fn test_location() -> ClientLocation {
        ClientLocation::unknown()
    }

    /// Stand-in GeoIP answer: Frankfurt, AS3320.
    fn test_geo(city: Option<&str>) -> Option<super::ClientGeo> {
        let location = shitspeak_core::geo::NodeGeo::new(
            50.1109,
            8.6821,
            city.map(str::to_owned),
            Some("HE".to_owned()),
            Some("DE".to_owned()),
            "test",
        )?;
        super::ClientGeo::new(Some(3320), Some("DE".to_owned()), Some(location))
    }

    fn test_identity() -> UdpLinkIdentity {
        UdpLinkIdentity::new(
            12,
            "default".to_owned(),
            4711,
            ClientLocation::from_geo(test_geo(Some("Frankfurt am Main")).as_ref()),
            "198.51.100.0/24".to_owned(),
            "0.0.0.0:64738".parse().unwrap(),
        )
    }

    fn test_series() -> UdpLinkSeries {
        UdpLinkSeries::new(
            test_identity(),
            UdpLinkCounters::new(90, 3, 7, 1),
            UdpLinkCounters::new(50, 2, 5, 0),
        )
    }

    fn sample_value(series: &UdpLinkSeries, name: &str, direction: &str, result: &str) -> f64 {
        series
            .prometheus_samples()
            .into_iter()
            .find(|sample| {
                sample.name() == name
                    && sample
                        .labels()
                        .iter()
                        .any(|(key, value)| key == "direction" && value == direction)
                    && (result.is_empty()
                        || sample
                            .labels()
                            .iter()
                            .any(|(key, value)| key == "result" && value == result))
            })
            .expect("sample present")
            .value()
    }

    #[test]
    fn both_directions_render_independent_counters() {
        let series = test_series();

        assert_eq!(
            sample_value(
                &series,
                "shitspeak_client_udp_packets_total",
                "uplink",
                "lost"
            ),
            7.0
        );
        assert_eq!(
            sample_value(
                &series,
                "shitspeak_client_udp_packets_total",
                "downlink",
                "lost"
            ),
            5.0
        );
        assert_eq!(
            sample_value(
                &series,
                "shitspeak_client_udp_packets_total",
                "uplink",
                "late"
            ),
            3.0
        );
        assert_eq!(
            sample_value(
                &series,
                "shitspeak_client_udp_packets_total",
                "downlink",
                "resync"
            ),
            0.0
        );
        assert_eq!(
            sample_value(
                &series,
                "shitspeak_client_udp_packet_loss_ratio",
                "uplink",
                ""
            ),
            0.07
        );
        assert_eq!(
            sample_value(
                &series,
                "shitspeak_client_udp_packet_loss_ratio",
                "downlink",
                ""
            ),
            5.0 / 57.0
        );
    }

    #[test]
    fn loss_ratio_covers_every_packet_the_sender_emitted() {
        let counters = UdpLinkCounters::new(60, 40, 0, 0);

        assert_eq!(counters.loss_ratio(), 0.0);
        assert_eq!(counters.sent(), 100);
    }

    #[test]
    fn a_silent_link_reports_zero_instead_of_dividing_by_zero() {
        let series = UdpLinkSeries::new(
            UdpLinkIdentity::new(
                1,
                "default".to_owned(),
                9,
                ClientLocation::unknown(),
                "127.0.0.0/24".to_owned(),
                "0.0.0.0:1".parse().unwrap(),
            ),
            UdpLinkCounters::default(),
            UdpLinkCounters::default(),
        );

        assert_eq!(
            sample_value(
                &series,
                "shitspeak_client_udp_packet_loss_ratio",
                "downlink",
                ""
            ),
            0.0
        );
    }

    #[test]
    fn series_carry_identity_region_city_coordinates_asn_subnet_and_entrypoint() {
        let series = test_series();
        let labels = series.labels("uplink", Some("good"));

        assert!(labels.contains(&("node".to_owned(), "12".to_owned())));
        assert!(labels.contains(&("server_id".to_owned(), "default".to_owned())));
        assert!(labels.contains(&("session".to_owned(), "4711".to_owned())));
        assert!(labels.contains(&("region".to_owned(), "DE".to_owned())));
        assert!(labels.contains(&("city".to_owned(), "Frankfurt am Main".to_owned())));
        assert!(labels.contains(&("lat".to_owned(), "50.1109".to_owned())));
        assert!(labels.contains(&("lon".to_owned(), "8.6821".to_owned())));
        assert!(labels.contains(&("asn".to_owned(), "3320".to_owned())));
        assert!(labels.contains(&("subnet".to_owned(), "198.51.100.0/24".to_owned())));
        assert!(labels.contains(&("entrypoint".to_owned(), "0.0.0.0:64738".to_owned())));
    }

    #[test]
    fn missing_geo_falls_back_to_unknown_with_empty_coordinates() {
        let location = test_location();

        assert_eq!(location.region(), "unknown");
        assert_eq!(location.city(), "unknown");
        assert_eq!(location.asn(), "unknown");
        assert_eq!(location.latitude(), "");
        assert_eq!(location.longitude(), "");
    }

    #[test]
    fn subnet_masks_host_bits_so_one_customer_keeps_one_series() {
        let first: IpAddr = "198.51.100.7".parse().unwrap();
        let second: IpAddr = "198.51.100.200".parse().unwrap();

        assert_eq!(client_subnet(first), "198.51.100.0/24");
        assert_eq!(client_subnet(second), "198.51.100.0/24");
    }

    #[test]
    fn subnet_masks_ipv6_to_a_provider_allocation() {
        let ip: IpAddr = "2001:db8:abcd:12::7".parse().unwrap();

        assert_eq!(client_subnet(ip), "2001:db8:abcd::/48");
    }
}
