use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use crate::config::GeoIpConfig;
use parking_lot::Mutex;
pub use shitspeak_core::{NodeGeo, valid_coordinates};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpGeoMetadata {
    asn: Option<u32>,
    country_code: Option<String>,
    country_name: Option<String>,
    source: String,
}

impl IpGeoMetadata {
    pub fn new(
        asn: Option<u32>,
        country_code: Option<String>,
        country_name: Option<String>,
        source: impl Into<String>,
    ) -> Option<Self> {
        let country_code = normalize_country_code(country_code);
        let country_name = empty_to_none(country_name);
        (asn.is_some() || country_code.is_some()).then(|| Self {
            asn,
            country_code,
            country_name,
            source: source.into(),
        })
    }

    pub fn asn(&self) -> Option<u32> {
        self.asn
    }

    pub fn country_code(&self) -> Option<&str> {
        self.country_code.as_deref()
    }

    pub fn country_name(&self) -> Option<&str> {
        self.country_name.as_deref()
    }

    pub fn source(&self) -> &str {
        &self.source
    }
}

#[derive(Clone)]
pub struct GeoIpResolver {
    config: GeoIpConfig,
    cache: Arc<Mutex<HashMap<IpAddr, CacheEntry>>>,
}

#[derive(Clone)]
struct CacheEntry {
    expires_at: Instant,
    metadata: Option<IpGeoMetadata>,
}

impl GeoIpResolver {
    pub fn new(config: GeoIpConfig) -> Self {
        Self {
            config,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn disabled() -> Self {
        Self::new(GeoIpConfig::default().disabled())
    }

    pub async fn lookup_ip_metadata(&self, ip: IpAddr) -> Option<IpGeoMetadata> {
        if !self.config.enabled() || !is_public_geoip_candidate(&ip) {
            return None;
        }

        let now = Instant::now();
        if let Some(entry) = self.cache.lock().get(&ip).cloned()
            && entry.expires_at > now
        {
            return entry.metadata;
        }

        let metadata = self.lookup_ip_metadata_uncached(ip).await;
        self.cache_metadata(ip, metadata.clone());
        metadata
    }

    pub async fn lookup_node_geo(&self, ips: &[IpAddr]) -> Option<NodeGeo> {
        if !self.config.enabled() {
            return None;
        }
        let ips = ips
            .iter()
            .filter(|ip| is_public_geoip_candidate(ip))
            .copied()
            .collect::<Vec<_>>();
        if ips.is_empty() {
            return None;
        }

        self.config
            .maxmind_database_path()
            .and_then(|path| lookup_city_database(path, &ips))
    }

    async fn lookup_ip_metadata_uncached(&self, ip: IpAddr) -> Option<IpGeoMetadata> {
        self.config
            .maxmind_database_path()
            .and_then(|path| lookup_ip_metadata_database(path, ip))
    }

    fn cache_metadata(&self, ip: IpAddr, metadata: Option<IpGeoMetadata>) {
        let capacity = self.config.cache_capacity();
        if capacity == 0 {
            return;
        }
        let mut cache = self.cache.lock();
        if cache.len() >= capacity
            && !cache.contains_key(&ip)
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(ip, _)| *ip)
        {
            cache.remove(&oldest);
        }
        cache.insert(
            ip,
            CacheEntry {
                expires_at: Instant::now() + self.config.cache_ttl(),
                metadata,
            },
        );
    }
}

pub fn lookup_city_database(path: &Path, ips: &[IpAddr]) -> Option<NodeGeo> {
    let reader = match maxminddb::Reader::open_readfile(path) {
        Ok(reader) => reader,
        Err(error) => {
            tracing::debug!(path = %path.display(), %error, "GeoIP database unavailable");
            return None;
        }
    };

    for ip in ips {
        let result = match reader.lookup(*ip) {
            Ok(result) => result,
            Err(error) => {
                tracing::debug!(%ip, %error, "GeoIP lookup failed");
                continue;
            }
        };
        let city = match result.decode::<maxminddb::geoip2::City>() {
            Ok(Some(city)) => city,
            Ok(None) => continue,
            Err(error) => {
                tracing::debug!(%ip, %error, "GeoIP city decode failed");
                continue;
            }
        };
        let Some(latitude) = city.location.latitude else {
            continue;
        };
        let Some(longitude) = city.location.longitude else {
            continue;
        };
        let region = city
            .subdivisions
            .first()
            .and_then(|subdivision| subdivision.iso_code)
            .map(str::to_owned);
        if let Some(geo) = NodeGeo::new(
            latitude,
            longitude,
            city.city.names.english.map(str::to_owned),
            region,
            city.country.iso_code.map(str::to_owned),
            format!("geoip:{}", path.display()),
        ) {
            return Some(geo);
        }
    }

    None
}

pub fn lookup_ip_metadata_database(path: &Path, ip: IpAddr) -> Option<IpGeoMetadata> {
    let reader = match maxminddb::Reader::open_readfile(path) {
        Ok(reader) => reader,
        Err(error) => {
            tracing::debug!(path = %path.display(), %error, "GeoIP database unavailable");
            return None;
        }
    };

    let asn = reader
        .lookup(ip)
        .ok()
        .and_then(|result| result.decode::<maxminddb::geoip2::Asn>().ok().flatten())
        .and_then(|record| record.autonomous_system_number);

    let country = reader
        .lookup(ip)
        .ok()
        .and_then(|result| result.decode::<maxminddb::geoip2::Country>().ok().flatten())
        .and_then(|record| {
            record
                .country
                .iso_code
                .map(str::to_owned)
                .or(record.registered_country.iso_code.map(str::to_owned))
        })
        .or_else(|| {
            reader
                .lookup(ip)
                .ok()
                .and_then(|result| result.decode::<maxminddb::geoip2::City>().ok().flatten())
                .and_then(|record| record.country.iso_code.map(str::to_owned))
        });

    IpGeoMetadata::new(asn, country, None, format!("maxmind:{}", path.display()))
}

pub fn is_public_geoip_candidate(ip: &IpAddr) -> bool {
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

fn normalize_country_code(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (trimmed.len() == 2 && trimmed.chars().all(|ch| ch.is_ascii_alphabetic()))
            .then(|| trimmed.to_ascii_uppercase())
    })
}

fn empty_to_none(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_coordinate_ranges() {
        assert!(valid_coordinates(32.7, -96.8));
        assert!(!valid_coordinates(91.0, 0.0));
        assert!(!valid_coordinates(0.0, -181.0));
        assert!(!valid_coordinates(f64::NAN, 0.0));
    }

    #[test]
    fn node_geo_rejects_invalid_coordinates() {
        assert!(NodeGeo::new(100.0, 0.0, None, None, None, "manual").is_none());
        assert!(NodeGeo::new(45.0, 90.0, None, None, None, "manual").is_some());
    }

    #[test]
    fn public_candidate_filter_excludes_private_and_documentation_ips() {
        assert!(!is_public_geoip_candidate(&"127.0.0.1".parse().unwrap()));
        assert!(!is_public_geoip_candidate(&"10.0.0.1".parse().unwrap()));
        assert!(!is_public_geoip_candidate(&"192.0.2.1".parse().unwrap()));
        assert!(is_public_geoip_candidate(&"8.8.8.8".parse().unwrap()));
    }
}
