use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct NodeGeo {
    latitude: f64,
    longitude: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    source: String,
}

impl NodeGeo {
    pub fn new(
        latitude: f64,
        longitude: f64,
        city: Option<String>,
        region: Option<String>,
        country: Option<String>,
        source: impl Into<String>,
    ) -> Option<Self> {
        valid_coordinates(latitude, longitude).then(|| Self {
            latitude,
            longitude,
            city: empty_to_none(city),
            region: empty_to_none(region),
            country: empty_to_none(country),
            source: source.into(),
        })
    }

    pub fn latitude(&self) -> f64 {
        self.latitude
    }

    pub fn longitude(&self) -> f64 {
        self.longitude
    }

    pub fn city(&self) -> Option<&str> {
        self.city.as_deref()
    }

    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    pub fn country(&self) -> Option<&str> {
        self.country.as_deref()
    }

    pub fn source(&self) -> &str {
        &self.source
    }
}

pub fn valid_coordinates(latitude: f64, longitude: f64) -> bool {
    latitude.is_finite()
        && longitude.is_finite()
        && (-90.0..=90.0).contains(&latitude)
        && (-180.0..=180.0).contains(&longitude)
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
}
