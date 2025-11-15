use std::net::IpAddr;

#[derive(Debug)]
pub struct Config {
    ip_address: IpAddr,
    country_code: String,
    country: String,
    continent_code: String,
    latitude: f64,
    longitude: f64,
    asn: i32,
    organization: String,
    timezone: i8,
}
