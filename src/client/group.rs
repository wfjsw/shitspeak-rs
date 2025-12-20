use std::{net::IpAddr, str::FromStr};

use cidr::{AnyIpCidr};

enum IPMaskType<'a> {
    FullMatch(IpAddr),
    CIDR(AnyIpCidr),
    ASN(u32),
    CountryCode(&'a str),
}

enum TokenMatchType<'a> {
    All(&'a str),
    ChannelPassword(&'a str),
    UserAccessToken(&'a str),
}

enum MatchType<'a> {
    None,
    All,
    Authenticated,
    HasVerifiedCertificateChain,
    CertificateHash(Vec<u8>),
    InChannel(u32),
    OutOfChannel(u32),
    ClientGroup(&'a str),
    Token(TokenMatchType<'a>),
    IPMask(IPMaskType<'a>),
}

pub struct ClientMembershipQuery<'a> {
    groups: &'a [&'a str],
    authenticated: bool,
    access_tokens: &'a [&'a str],
    cert_hash: Option<&'a [u8]>,
    has_verified_cert_chain: bool,
    ip_address: Option<IpAddr>,
    asn: Option<u32>,
    country_code: Option<&'a str>,
}

pub fn is_member_in_group(
    group: &str,
    current_channel_id: u32,
    target_channel_id: Option<u32>,
    join_passwords: &[&str],
    client: &ClientMembershipQuery,
) -> bool {
    let (match_type, invert, use_target_channel) = evaluate_group_string_match_type(group);
    let channel_id = match use_target_channel {
        true => match target_channel_id {
            Some(id) => id,
            None => current_channel_id,
        },
        false => current_channel_id,
    };

    let in_group = match match_type {
        None => false,
        Some(MatchType::All) => true,
        Some(MatchType::None) => false,
        Some(MatchType::Authenticated) => client.authenticated,
        Some(MatchType::HasVerifiedCertificateChain) => client.has_verified_cert_chain,
        Some(MatchType::CertificateHash(expected_hash)) => {
            match client.cert_hash {
                Some(actual_hash) => actual_hash == expected_hash.as_slice(),
                None => false,
            }
        },
        Some(MatchType::InChannel(expected_channel_id)) => channel_id == expected_channel_id,
        Some(MatchType::OutOfChannel(expected_channel_id)) => channel_id != expected_channel_id,
        Some(MatchType::ClientGroup(expected_group)) => {
            client.groups.iter().any(|&g| g.trim().eq_ignore_ascii_case(expected_group.trim()))
        }
        Some(MatchType::Token(token_match_type)) => match token_match_type {
            TokenMatchType::All(token) => {
                join_passwords.iter().any(|&p| p.trim().eq_ignore_ascii_case(token.trim()))
                    || client.access_tokens.iter().any(|&t| t == token)
            }
            TokenMatchType::ChannelPassword(token) => {
                join_passwords.iter().any(|&p| p.trim().eq_ignore_ascii_case(token.trim()))
            }
            TokenMatchType::UserAccessToken(token) => {
                client.access_tokens.iter().any(|&t| t == token)
            }
        },
        Some(MatchType::IPMask(ip_mask_type)) => match ip_mask_type {
            IPMaskType::FullMatch(ip) => {
                match client.ip_address {
                    Some(client_ip) => client_ip == ip,
                    None => false,
                }
            }
            IPMaskType::CIDR(cidr) => {
                match client.ip_address {
                    Some(client_ip) => cidr.contains(&client_ip),
                    None => false,
                }
            }
            IPMaskType::ASN(asn) => {
                match client.asn {
                    Some(client_asn) => client_asn == asn,
                    None => false,
                }
            }
            IPMaskType::CountryCode(country_code) => {
                match client.country_code {
                    Some(client_cc) => client_cc.eq_ignore_ascii_case(country_code),
                    None => false,
                }
            }
        },

    };

    if invert {
        !in_group
    } else {
        in_group
    }
}

fn evaluate_group_string_match_type<'a>(group: &'a str) -> (Option<MatchType<'a>>, bool, bool) {
    let mut invert = false;
    let mut use_target_channel = false;
    let mut group_name_slice = group;
    let match_type = loop {
        match group_name_slice.chars().next() {
            // Invert the match
            Some('!') => {
                invert = true;
                group_name_slice = &group_name_slice[1..];
            }

            // Use target channel for evaluation
            Some('~') => {
                group_name_slice = &group_name_slice[1..];
                use_target_channel = true;
            }

            // Tokens (aka. channel passwords)
            Some('#') => {
                group_name_slice = &group_name_slice[1..];
                match group_name_slice.chars().next() {
                    Some('@') => {
                        // User access token only
                        break Some(MatchType::Token(TokenMatchType::UserAccessToken(
                            &group_name_slice[1..],
                        )));
                    }

                    Some('$') => {
                        // Channel password only
                        break Some(MatchType::Token(TokenMatchType::ChannelPassword(
                            &group_name_slice[1..],
                        )));
                    }

                    None => {
                        // Empty token; invalid
                        break None;
                    }

                    _ => {
                        // Not a specialized token type request
                        break Some(MatchType::Token(TokenMatchType::All(&group_name_slice)));
                    }
                }
            }

            // Client certificate hash
            Some('$') => {
                // Client certificate hash
                let expected_certificate_hash = hex::decode(&group_name_slice[1..]);

                break match expected_certificate_hash {
                    Ok(hash) => Some(MatchType::CertificateHash(hash)),
                    Err(_) => None,
                };
            }

            // IP Database Mask
            Some('%') => {
                group_name_slice = &group_name_slice[1..];
                match group_name_slice.chars().next() {
                    // Country code
                    Some('#') => {
                        break Some(MatchType::IPMask(IPMaskType::CountryCode(
                            &group_name_slice[1..],
                        )));
                    }

                    // ASN
                    Some('@') => match group_name_slice[1..].parse::<u32>() {
                        Ok(asn) => break Some(MatchType::IPMask(IPMaskType::ASN(asn))),
                        Err(_) => break None,
                    },

                    // CIDR
                    Some('!') => {
                        let cidr_str = &group_name_slice[1..];
                        match AnyIpCidr::from_str(cidr_str) {
                            Ok(cidr) => break Some(MatchType::IPMask(IPMaskType::CIDR(cidr))),
                            Err(_) => break None,
                        }
                    }

                    // Full match
                    None => match group_name_slice[1..].parse::<IpAddr>() {
                        Ok(ip) => break Some(MatchType::IPMask(IPMaskType::FullMatch(ip))),
                        Err(_) => break None,
                    },

                    _ => break None,
                }
            }

            _ => break Some(MatchType::ClientGroup(group_name_slice)),
        }
    };
    (match_type, invert, use_target_channel)
}
