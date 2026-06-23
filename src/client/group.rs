use std::{net::IpAddr, str::FromStr};

use bytes::Bytes;

use cidr::AnyIpCidr;

#[derive(Clone, Copy)]
pub struct ChannelHierarchy<'a> {
    current_channel_id: u32,
    ancestors: &'a [u32],
}

impl<'a> ChannelHierarchy<'a> {
    pub fn new(current_channel_id: u32, ancestors: &'a [u32]) -> Self {
        Self {
            current_channel_id,
            ancestors,
        }
    }

    fn root_to_current(&self) -> Vec<u32> {
        let mut hierarchy: Vec<u32> = self.ancestors.iter().rev().copied().collect();
        hierarchy.push(self.current_channel_id);
        hierarchy
    }
}

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
    CertificateHash(Bytes),
    InChannel,
    OutOfChannel,
    Subtree(SubtreeMatch),
    ClientGroup(&'a str),
    Token(TokenMatchType<'a>),
    IPMask(IPMaskType<'a>),
}

struct SubtreeMatch {
    channel_offset: i32,
    min_descendant_level: i32,
    max_descendant_level: i32,
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
    home_channel: ChannelHierarchy<'a>,
}

impl<'a> ClientMembershipQuery<'a> {
    pub fn new(
        groups: &'a [&'a str],
        authenticated: bool,
        access_tokens: &'a [&'a str],
        cert_hash: Option<&'a [u8]>,
        has_verified_cert_chain: bool,
        ip_address: Option<IpAddr>,
    ) -> Self {
        Self {
            groups,
            authenticated,
            access_tokens,
            cert_hash,
            has_verified_cert_chain,
            ip_address,
            asn: None,
            country_code: None,
            home_channel: ChannelHierarchy::new(0, &[]),
        }
    }

    pub fn with_ip_metadata(mut self, asn: Option<u32>, country_code: Option<&'a str>) -> Self {
        self.asn = asn;
        self.country_code = country_code;
        self
    }

    pub fn with_home_channel(mut self, home_channel: ChannelHierarchy<'a>) -> Self {
        self.home_channel = home_channel;
        self
    }

    pub fn authenticated(&self) -> bool {
        self.authenticated
    }
}

pub fn is_member_in_group(
    group: &str,
    evaluation_channel: ChannelHierarchy<'_>,
    acl_channel: Option<ChannelHierarchy<'_>>,
    join_passwords: &[&str],
    client: &ClientMembershipQuery,
) -> bool {
    let home_channel = client.home_channel;
    let (match_type, invert, use_target_channel) = evaluate_group_string_match_type(group);
    let context_channel = match use_target_channel {
        true => acl_channel.unwrap_or(evaluation_channel),
        false => evaluation_channel,
    };

    let in_group = match match_type {
        None => false,
        Some(MatchType::All) => true,
        Some(MatchType::None) => false,
        Some(MatchType::Authenticated) => client.authenticated,
        Some(MatchType::HasVerifiedCertificateChain) => client.has_verified_cert_chain,
        Some(MatchType::CertificateHash(expected_hash)) => match client.cert_hash {
            Some(actual_hash) => actual_hash == expected_hash.as_ref(),
            None => false,
        },
        Some(MatchType::InChannel) => {
            home_channel.current_channel_id == context_channel.current_channel_id
        }
        Some(MatchType::OutOfChannel) => {
            home_channel.current_channel_id != context_channel.current_channel_id
        }
        Some(MatchType::Subtree(subtree)) => {
            matches_subtree(home_channel, evaluation_channel, context_channel, &subtree)
        }
        Some(MatchType::ClientGroup(expected_group)) => client
            .groups
            .iter()
            .any(|&g| g.trim().eq_ignore_ascii_case(expected_group.trim())),
        Some(MatchType::Token(token_match_type)) => match token_match_type {
            TokenMatchType::All(token) => {
                join_passwords
                    .iter()
                    .any(|&p| p.trim().eq_ignore_ascii_case(token.trim()))
                    || client.access_tokens.iter().any(|&t| t == token)
            }
            TokenMatchType::ChannelPassword(token) => join_passwords
                .iter()
                .any(|&p| p.trim().eq_ignore_ascii_case(token.trim())),
            TokenMatchType::UserAccessToken(token) => {
                client.access_tokens.iter().any(|&t| t == token)
            }
        },
        Some(MatchType::IPMask(ip_mask_type)) => match ip_mask_type {
            IPMaskType::FullMatch(ip) => match client.ip_address {
                Some(client_ip) => client_ip == ip,
                None => false,
            },
            IPMaskType::CIDR(cidr) => match client.ip_address {
                Some(client_ip) => cidr.contains(&client_ip),
                None => false,
            },
            IPMaskType::ASN(asn) => match client.asn {
                Some(client_asn) => client_asn == asn,
                None => false,
            },
            IPMaskType::CountryCode(country_code) => match client.country_code {
                Some(client_cc) => client_cc.eq_ignore_ascii_case(country_code),
                None => false,
            },
        },
    };

    if invert { !in_group } else { in_group }
}

fn evaluate_group_string_match_type(group: &str) -> (Option<MatchType<'_>>, bool, bool) {
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
                    Ok(hash) => Some(MatchType::CertificateHash(Bytes::from(hash))),
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

            _ => {
                // Built-in group names that are not prefix-delimited.
                let m = match group_name_slice {
                    "all" => Some(MatchType::All),
                    "none" => Some(MatchType::None),
                    "auth" => Some(MatchType::Authenticated),
                    "strong" => Some(MatchType::HasVerifiedCertificateChain),
                    "in" => Some(MatchType::InChannel),
                    "out" => Some(MatchType::OutOfChannel),
                    "sub" => Some(MatchType::Subtree(SubtreeMatch::default())),
                    name if name.starts_with("sub,") => parse_subtree_match(name)
                        .map(MatchType::Subtree)
                        .or_else(|| Some(MatchType::ClientGroup(name))),
                    name => Some(MatchType::ClientGroup(name)),
                };
                break m;
            }
        }
    };
    (match_type, invert, use_target_channel)
}

impl Default for SubtreeMatch {
    fn default() -> Self {
        Self {
            channel_offset: 0,
            min_descendant_level: 1,
            max_descendant_level: 1000,
        }
    }
}

fn parse_subtree_match(group_name: &str) -> Option<SubtreeMatch> {
    let args = group_name.strip_prefix("sub,")?;
    let mut parsed = SubtreeMatch::default();

    for (index, arg) in args.split(',').take(3).enumerate() {
        if arg.is_empty() {
            continue;
        }
        let value = arg.parse::<i32>().unwrap_or(0);
        match index {
            0 => parsed.channel_offset = value,
            1 => parsed.min_descendant_level = value,
            2 => parsed.max_descendant_level = value,
            _ => {}
        }
    }

    Some(parsed)
}

fn matches_subtree(
    home_channel: ChannelHierarchy<'_>,
    evaluation_channel: ChannelHierarchy<'_>,
    context_channel: ChannelHierarchy<'_>,
    subtree: &SubtreeMatch,
) -> bool {
    let home_hierarchy = home_channel.root_to_current();
    let evaluation_hierarchy = evaluation_channel.root_to_current();

    let Some(context_index) = evaluation_hierarchy
        .iter()
        .position(|id| *id == context_channel.current_channel_id)
    else {
        return false;
    };

    let mut required_index = context_index as i32 + subtree.channel_offset;
    if required_index >= evaluation_hierarchy.len() as i32 {
        return false;
    }
    if required_index < 0 {
        required_index = 0;
    }
    let required_index = required_index as usize;
    let required_channel = evaluation_hierarchy[required_index];

    if !home_hierarchy.contains(&required_channel) {
        return false;
    }

    let total_depth = home_hierarchy.len() as i32 - 1;
    let min_depth = required_index as i32 + subtree.min_descendant_level;
    let max_depth = required_index as i32 + subtree.max_descendant_level;

    total_depth >= min_depth && total_depth <= max_depth
}

#[cfg(test)]
mod tests {
    use super::*;

    fn membership<'a>(home_channel: ChannelHierarchy<'a>) -> ClientMembershipQuery<'a> {
        ClientMembershipQuery::new(&[], true, &[], None, false, None)
            .with_home_channel(home_channel)
    }

    #[test]
    fn sub_matches_descendants_of_current_context_by_default() {
        let home_ancestors = [1, 0];
        let evaluation_ancestors = [0];
        let home = ChannelHierarchy::new(2, &home_ancestors);
        let evaluation = ChannelHierarchy::new(1, &evaluation_ancestors);
        let client = membership(home);

        assert!(is_member_in_group("sub", evaluation, None, &[], &client));
        assert!(!is_member_in_group("sub", home, None, &[], &client));
        assert!(is_member_in_group("sub,0,0", home, None, &[], &client));
        assert!(!is_member_in_group(
            "sub,0,2",
            evaluation,
            None,
            &[],
            &client
        ));
    }

    #[test]
    fn sub_with_target_context_matches_mumble_depth_arguments() {
        let home_ancestors = [3, 1, 0];
        let acl_ancestors = [1, 0];
        let home = ChannelHierarchy::new(4, &home_ancestors);
        let acl = ChannelHierarchy::new(2, &acl_ancestors);
        let client = membership(home);

        assert!(is_member_in_group(
            "~sub,-1,0",
            acl,
            Some(acl),
            &[],
            &client
        ));
        assert!(is_member_in_group(
            "~sub,-1,1,2",
            acl,
            Some(acl),
            &[],
            &client
        ));
        assert!(!is_member_in_group(
            "~sub,-1,0,0",
            acl,
            Some(acl),
            &[],
            &client
        ));
        assert!(!is_member_in_group("~sub,1", acl, Some(acl), &[], &client));
    }

    #[test]
    fn inverted_sub_negates_the_match() {
        let home_ancestors = [1, 0];
        let evaluation_ancestors = [0];
        let home = ChannelHierarchy::new(2, &home_ancestors);
        let evaluation = ChannelHierarchy::new(1, &evaluation_ancestors);
        let client = membership(home);

        assert!(!is_member_in_group("!sub", evaluation, None, &[], &client));
        assert!(is_member_in_group("!sub", home, None, &[], &client));
    }
}
