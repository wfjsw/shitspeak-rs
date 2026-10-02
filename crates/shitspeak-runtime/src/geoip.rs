use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwapOption;
use parking_lot::Mutex;
pub use shitspeak_core::{NodeGeo, valid_coordinates};
use shitspeak_runtime_config::GeoIpConfig;

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

/// How often the reload thread checks the database files for a change. A
/// rewrite is adopted once its size and modification time have held steady
/// for one interval, so an update takes effect within about two intervals.
const DATABASE_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Resolves IP metadata from MaxMind databases held in memory.
///
/// Lookups never touch the filesystem: they read databases already loaded
/// into memory. A dedicated thread loads them and polls the files for
/// changes, adopting a rewrite only once it has stopped changing. The bytes
/// are read into memory rather than mapped, because the files may be
/// rewritten in place, which would tear a mapping under live lookups.
#[derive(Clone)]
pub struct GeoIpResolver {
    inner: Arc<ResolverInner>,
}

struct ResolverInner {
    config: GeoIpConfig,
    city: DatabaseSlot,
    asn: DatabaseSlot,
    cache: Mutex<HashMap<IpAddr, CacheEntry>>,
}

#[derive(Clone)]
struct CacheEntry {
    expires_at: Instant,
    metadata: Option<IpGeoMetadata>,
}

impl GeoIpResolver {
    /// Build a resolver whose databases load on its background thread.
    /// Lookups that run before the first load settles see no database, and
    /// their results are not cached.
    pub fn new(config: GeoIpConfig) -> Self {
        Self::start(config, Some(DATABASE_POLL_INTERVAL))
    }

    /// Build a resolver and wait, on the blocking pool, for the first load of
    /// its databases, so lookups see them from the start.
    pub async fn load(config: GeoIpConfig) -> Self {
        let resolver = Self::start(config, None);
        let inner = resolver.inner.clone();
        if let Err(error) = tokio::task::spawn_blocking(move || inner.refresh()).await {
            tracing::warn!(%error, "GeoIP database load task failed");
        }
        resolver.spawn_reloader(DATABASE_POLL_INTERVAL);
        resolver
    }

    pub fn disabled() -> Self {
        Self::start(GeoIpConfig::default().disabled(), None)
    }

    fn start(config: GeoIpConfig, poll_interval: Option<Duration>) -> Self {
        let resolver = Self {
            inner: Arc::new(ResolverInner {
                city: DatabaseSlot::new(config.maxmind_city_database_path()),
                asn: DatabaseSlot::new(config.maxmind_asn_database_path()),
                config,
                cache: Mutex::new(HashMap::new()),
            }),
        };
        if let Some(interval) = poll_interval {
            resolver.spawn_reloader(interval);
        }
        resolver
    }

    /// Load and then poll the databases on a dedicated thread, which exits
    /// once the resolver is dropped (a config reload replaces it).
    fn spawn_reloader(&self, interval: Duration) {
        if self.inner.city.path.is_none() && self.inner.asn.path.is_none() {
            return;
        }
        let resolver = Arc::downgrade(&self.inner);
        let spawned = std::thread::Builder::new()
            .name("geoip-reload".to_owned())
            .spawn(move || {
                loop {
                    {
                        let Some(inner) = resolver.upgrade() else {
                            return;
                        };
                        inner.refresh();
                    }
                    std::thread::sleep(interval);
                }
            });
        if let Err(error) = spawned {
            tracing::warn!(%error, "failed to start the GeoIP reload thread");
        }
    }

    pub async fn lookup_ip_metadata(&self, ip: IpAddr) -> Option<IpGeoMetadata> {
        let inner = &self.inner;
        if !inner.config.enabled() || !is_public_geoip_candidate(&ip) {
            return None;
        }

        let now = Instant::now();
        if let Some(entry) = inner.cache.lock().get(&ip).cloned()
            && entry.expires_at > now
        {
            return entry.metadata;
        }

        let metadata = inner.lookup_ip_metadata_loaded(ip);
        // Before the first load settles, a miss only means "not loaded yet";
        // caching it would hide the database for a whole TTL.
        if inner.city.settled() && inner.asn.settled() {
            inner.cache_metadata(ip, metadata.clone());
        }
        metadata
    }

    pub async fn lookup_node_geo(&self, ips: &[IpAddr]) -> Option<NodeGeo> {
        if !self.inner.config.enabled() {
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

        let city = &self.inner.city;
        let path = city.path.as_deref()?;
        let reader = city.reader()?;
        lookup_city(&reader, path, &ips)
    }

    /// Check the database files now, as the reload thread does each poll.
    #[cfg(test)]
    fn refresh_now(&self) {
        self.inner.refresh();
    }
}

impl ResolverInner {
    fn refresh(&self) {
        let city = self.city.refresh();
        let asn = self.asn.refresh();
        if city || asn {
            // Cached results came from the databases just replaced.
            self.cache.lock().clear();
        }
    }

    fn lookup_ip_metadata_loaded(&self, ip: IpAddr) -> Option<IpGeoMetadata> {
        let asn = self.asn.reader().and_then(|reader| lookup_asn(&reader, ip));
        let country = self
            .city
            .reader()
            .and_then(|reader| lookup_country(&reader, ip));

        let source = match (self.city.path.as_deref(), self.asn.path.as_deref()) {
            (Some(city), Some(asn)) => {
                format!("maxmind:city={},asn={}", city.display(), asn.display())
            }
            (Some(city), None) => format!("maxmind:city={}", city.display()),
            (None, Some(asn)) => format!("maxmind:asn={}", asn.display()),
            (None, None) => return None,
        };
        IpGeoMetadata::new(asn, country, None, source)
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

/// One MaxMind database file and the copy of it serving lookups.
struct DatabaseSlot {
    path: Option<PathBuf>,
    loaded: ArcSwapOption<maxminddb::Reader<Vec<u8>>>,
    /// Whether a load has been attempted, whatever its outcome.
    settled: AtomicBool,
    state: Mutex<SlotState>,
}

#[derive(Default)]
struct SlotState {
    /// The file version serving lookups.
    loaded: Option<FileFingerprint>,
    /// A changed version seen at the last poll, adopted if it is unchanged
    /// at the next.
    candidate: Option<FileFingerprint>,
    /// A version that failed to parse; not retried until the file changes.
    rejected: Option<FileFingerprint>,
}

/// Size and modification time: enough to notice a rewrite, in place or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileFingerprint {
    len: u64,
    modified: Option<SystemTime>,
}

impl FileFingerprint {
    fn read(path: &Path) -> Option<Self> {
        let metadata = std::fs::metadata(path).ok()?;
        Some(Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

impl DatabaseSlot {
    fn new(path: Option<PathBuf>) -> Self {
        Self {
            settled: AtomicBool::new(path.is_none()),
            path,
            loaded: ArcSwapOption::empty(),
            state: Mutex::new(SlotState::default()),
        }
    }

    fn reader(&self) -> Option<Arc<maxminddb::Reader<Vec<u8>>>> {
        self.loaded.load_full()
    }

    fn settled(&self) -> bool {
        self.settled.load(Ordering::Acquire)
    }

    /// Load the file if it changed since the copy serving lookups. Returns
    /// whether a new copy replaced it. Blocking: runs off the async workers.
    fn refresh(&self) -> bool {
        let Some(path) = self.path.as_deref() else {
            return false;
        };
        let replaced = {
            let mut state = self.state.lock();
            self.refresh_locked(path, &mut state)
        };
        self.settled.store(true, Ordering::Release);
        replaced
    }

    fn refresh_locked(&self, path: &Path, state: &mut SlotState) -> bool {
        let Some(seen) = FileFingerprint::read(path) else {
            // Missing or unreadable: keep serving what is loaded. A file
            // replaced by rename can be briefly absent.
            state.candidate = None;
            return false;
        };
        if state.loaded == Some(seen) || state.rejected == Some(seen) {
            state.candidate = None;
            return false;
        }
        // A database already serving lookups is replaced only by a version
        // that held steady across a poll: the file may be rewritten in place,
        // and a half-written copy must never replace a good one.
        if state.loaded.is_some() && state.candidate != Some(seen) {
            state.candidate = Some(seen);
            return false;
        }
        state.candidate = None;
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::debug!(path = %path.display(), %error, "GeoIP database unavailable");
                return false;
            }
        };
        if FileFingerprint::read(path) != Some(seen) {
            // Changed while being read; try again at the next poll.
            return false;
        }
        match maxminddb::Reader::from_source(bytes) {
            Ok(reader) => {
                self.loaded.store(Some(Arc::new(reader)));
                state.loaded = Some(seen);
                state.rejected = None;
                tracing::info!(path = %path.display(), "GeoIP database loaded");
                true
            }
            Err(error) => {
                state.rejected = Some(seen);
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "GeoIP database rejected; keeping the previous copy"
                );
                false
            }
        }
    }
}

fn lookup_city(
    reader: &maxminddb::Reader<Vec<u8>>,
    path: &Path,
    ips: &[IpAddr],
) -> Option<NodeGeo> {
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

fn lookup_asn(reader: &maxminddb::Reader<Vec<u8>>, ip: IpAddr) -> Option<u32> {
    reader
        .lookup(ip)
        .ok()
        .and_then(|result| result.decode::<maxminddb::geoip2::Asn>().ok().flatten())
        .and_then(|record| record.autonomous_system_number)
}

fn lookup_country(reader: &maxminddb::Reader<Vec<u8>>, ip: IpAddr) -> Option<String> {
    reader
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
        })
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

    /// A minimal MaxMind DB: an IPv4 tree whose single node sends every
    /// address to one data record.
    fn mmdb(record: &[u8]) -> Vec<u8> {
        fn string(value: &str) -> Vec<u8> {
            let mut out = vec![(2 << 5) | value.len() as u8];
            out.extend_from_slice(value.as_bytes());
            out
        }
        fn uint16(value: u16) -> Vec<u8> {
            let mut out = vec![(5 << 5) | 2];
            out.extend_from_slice(&value.to_be_bytes());
            out
        }
        let mut out = vec![0, 0, 17, 0, 0, 17];
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(record);
        out.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
        out.push((7 << 5) | 9);
        out.extend(string("binary_format_major_version"));
        out.extend(uint16(2));
        out.extend(string("binary_format_minor_version"));
        out.extend(uint16(0));
        out.extend(string("build_epoch"));
        out.extend_from_slice(&[8, 2, 0, 0, 0, 0, 0, 0, 0, 1]);
        out.extend(string("database_type"));
        out.extend(string("Test"));
        out.extend(string("description"));
        out.push(7 << 5);
        out.extend(string("ip_version"));
        out.extend(uint16(4));
        out.extend(string("languages"));
        out.extend_from_slice(&[0, 4]);
        out.extend(string("node_count"));
        out.extend_from_slice(&[(6 << 5) | 4, 0, 0, 0, 1]);
        out.extend(string("record_size"));
        out.extend(uint16(24));
        out
    }

    fn asn_database(asn: u32) -> Vec<u8> {
        let mut record = vec![(7 << 5) | 1, (2 << 5) | 24];
        record.extend_from_slice(b"autonomous_system_number");
        record.push((6 << 5) | 4);
        record.extend_from_slice(&asn.to_be_bytes());
        mmdb(&record)
    }

    fn city_database(country: &str) -> Vec<u8> {
        let mut record = vec![(7 << 5) | 1, (2 << 5) | 7];
        record.extend_from_slice(b"country");
        record.extend_from_slice(&[(7 << 5) | 1, (2 << 5) | 8]);
        record.extend_from_slice(b"iso_code");
        record.push((2 << 5) | country.len() as u8);
        record.extend_from_slice(country.as_bytes());
        mmdb(&record)
    }

    fn config_for(dir: &Path, cache_capacity: usize) -> GeoIpConfig {
        serde_json::from_value(serde_json::json!({
            "maxmind_database_path": dir,
            "cache_capacity": cache_capacity,
        }))
        .unwrap()
    }

    fn write_databases(dir: &Path, asn: u32, country: &str) {
        std::fs::write(dir.join("GeoLite2-ASN.mmdb"), asn_database(asn)).unwrap();
        std::fs::write(dir.join("GeoLite2-City.mmdb"), city_database(country)).unwrap();
    }

    fn public_ip() -> IpAddr {
        "8.8.8.8".parse().unwrap()
    }

    async fn wait_for_metadata(resolver: &GeoIpResolver) -> IpGeoMetadata {
        for _ in 0..200 {
            if let Some(metadata) = resolver.lookup_ip_metadata(public_ip()).await {
                return metadata;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("GeoIP databases never loaded");
    }

    /// A lookup reads only the databases already in memory: once loaded,
    /// removing the files changes nothing until a reload. Reading the files
    /// per lookup put tens of MB of synchronous I/O on the voice runtime for
    /// every result-cache miss.
    #[tokio::test]
    async fn lookups_are_served_from_databases_already_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        write_databases(dir.path(), 15169, "US");
        let resolver = GeoIpResolver::new(config_for(dir.path(), 0));
        let metadata = wait_for_metadata(&resolver).await;
        assert_eq!(metadata.asn(), Some(15169));
        assert_eq!(metadata.country_code(), Some("US"));

        std::fs::remove_file(dir.path().join("GeoLite2-ASN.mmdb")).unwrap();
        std::fs::remove_file(dir.path().join("GeoLite2-City.mmdb")).unwrap();
        let metadata = resolver
            .lookup_ip_metadata(public_ip())
            .await
            .expect("lookup must not depend on the files after loading");
        assert_eq!(metadata.asn(), Some(15169));
        assert_eq!(metadata.country_code(), Some("US"));
    }

    async fn asn_now(resolver: &GeoIpResolver) -> Option<u32> {
        resolver
            .lookup_ip_metadata(public_ip())
            .await
            .and_then(|metadata| metadata.asn())
    }

    /// Rewrite a file in place (same inode, truncated and rewritten) with an
    /// explicit modification time, so the change is visible even on file
    /// systems with coarse timestamps.
    fn rewrite_in_place(path: &Path, bytes: &[u8], modified: SystemTime) {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.set_modified(modified).unwrap();
    }

    #[tokio::test]
    async fn load_waits_for_the_databases_before_returning() {
        let dir = tempfile::tempdir().unwrap();
        write_databases(dir.path(), 15169, "US");
        let resolver = GeoIpResolver::load(config_for(dir.path(), 16)).await;
        assert_eq!(asn_now(&resolver).await, Some(15169));
    }

    /// An in-place rewrite replaces the database once its size and
    /// modification time held steady across a poll, and the result cache
    /// built from the old copy is discarded.
    #[tokio::test]
    async fn an_in_place_rewrite_is_adopted_once_it_holds_steady() {
        let dir = tempfile::tempdir().unwrap();
        write_databases(dir.path(), 15169, "US");
        let resolver = GeoIpResolver::start(config_for(dir.path(), 16), None);
        resolver.refresh_now();
        assert_eq!(asn_now(&resolver).await, Some(15169));

        let asn_path = dir.path().join("GeoLite2-ASN.mmdb");
        let later = SystemTime::now() + Duration::from_secs(60);
        rewrite_in_place(&asn_path, &asn_database(13335), later);
        // First sighting of the new version: it may still be being written.
        resolver.refresh_now();
        assert_eq!(asn_now(&resolver).await, Some(15169));
        // Unchanged at the next poll: adopted, and the cached result dropped.
        resolver.refresh_now();
        assert_eq!(asn_now(&resolver).await, Some(13335));
    }

    /// A half-written or corrupt file never replaces a good database; the
    /// next complete version still does.
    #[tokio::test]
    async fn a_torn_rewrite_keeps_serving_the_previous_database() {
        let dir = tempfile::tempdir().unwrap();
        write_databases(dir.path(), 15169, "US");
        let resolver = GeoIpResolver::start(config_for(dir.path(), 0), None);
        resolver.refresh_now();
        assert_eq!(asn_now(&resolver).await, Some(15169));

        let asn_path = dir.path().join("GeoLite2-ASN.mmdb");
        let torn = asn_database(13335);
        let base = SystemTime::now() + Duration::from_secs(60);
        rewrite_in_place(&asn_path, &torn[..torn.len() / 2], base);
        resolver.refresh_now();
        resolver.refresh_now();
        assert_eq!(asn_now(&resolver).await, Some(15169));

        rewrite_in_place(&asn_path, &torn, base + Duration::from_secs(1));
        resolver.refresh_now();
        resolver.refresh_now();
        assert_eq!(asn_now(&resolver).await, Some(13335));
    }

    /// A lookup before the first load settles misses, and that miss must not
    /// be cached for the whole TTL.
    #[tokio::test]
    async fn a_miss_before_the_first_load_is_not_cached() {
        let dir = tempfile::tempdir().unwrap();
        write_databases(dir.path(), 15169, "US");
        let resolver = GeoIpResolver::start(config_for(dir.path(), 16), None);
        assert_eq!(asn_now(&resolver).await, None);
        resolver.refresh_now();
        assert_eq!(asn_now(&resolver).await, Some(15169));
    }

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
