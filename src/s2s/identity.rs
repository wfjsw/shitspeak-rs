use x509_parser::prelude::parse_x509_certificate;

pub fn extract_node_id_from_cert(
    certificate_der: &[u8],
    extension_oid: &str,
) -> Result<Option<u16>, String> {
    let (_, cert) = parse_x509_certificate(certificate_der)
        .map_err(|e| format!("x509 parse error: {e}"))?;

    let extensions = cert.tbs_certificate.extensions();
    let maybe_extension = extensions
        .iter()
        .find(|ext| ext.oid.to_id_string() == extension_oid);

    let Some(extension) = maybe_extension else {
        return Ok(None);
    };

    parse_node_id_extension(extension.value)
        .ok_or_else(|| "unsupported node-id extension payload format".to_owned())
        .map(Some)
}

fn parse_node_id_extension(value: &[u8]) -> Option<u16> {
    parse_der_integer_u16(value).or_else(|| match value {
        [single] => Some(*single as u16),
        [high, low] => Some(u16::from_be_bytes([*high, *low])),
        _ => None,
    })
}

fn parse_der_integer_u16(value: &[u8]) -> Option<u16> {
    if value.len() < 3 || value[0] != 0x02 {
        return None;
    }

    let length = value[1] as usize;
    if value.len() != 2 + length || length == 0 || length > 3 {
        return None;
    }

    let mut number: u32 = 0;
    for byte in &value[2..] {
        number = (number << 8) | u32::from(*byte);
    }

    u16::try_from(number).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_integer_encoding_is_supported() {
        assert_eq!(parse_node_id_extension(&[0x02, 0x01, 0x2a]), Some(42));
        assert_eq!(parse_node_id_extension(&[0x02, 0x02, 0x01, 0x00]), Some(256));
    }

    #[test]
    fn raw_byte_fallback_encodings_are_supported() {
        assert_eq!(parse_node_id_extension(&[0x7f]), Some(127));
        assert_eq!(parse_node_id_extension(&[0x01, 0x00]), Some(256));
    }

    #[test]
    fn invalid_encoding_returns_none() {
        assert_eq!(parse_node_id_extension(&[0x02, 0x04, 0, 0, 0, 1]), None);
        assert_eq!(parse_der_integer_u16(&[0x01, 0x01, 0x01]), None);
    }
}
