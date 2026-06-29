use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tracing::debug;

pub(crate) fn discover_interface_ips(allowlist: &[String]) -> Vec<IpAddr> {
    if allowlist.is_empty() {
        return Vec::new();
    }

    match discover_interface_ips_inner(Some(allowlist)) {
        Ok(ips) => ips,
        Err(e) => {
            debug!(error=%e, "local interface IP discovery failed");
            Vec::new()
        }
    }
}

pub(crate) fn has_usable_ipv6_address() -> bool {
    match discover_interface_ips_inner(None) {
        Ok(ips) => ips.into_iter().any(|ip| ip.is_ipv6()),
        Err(e) => {
            debug!(error=%e, "local IPv6 interface discovery failed");
            false
        }
    }
}

#[cfg(unix)]
fn discover_interface_ips_inner(allowlist: Option<&[String]>) -> std::io::Result<Vec<IpAddr>> {
    use std::ffi::CStr;
    use std::ptr;

    struct IfAddrs(*mut libc::ifaddrs);

    impl Drop for IfAddrs {
        fn drop(&mut self) {
            unsafe {
                libc::freeifaddrs(self.0);
            }
        }
    }

    let mut ifaddrs = ptr::null_mut();
    let rc = unsafe { libc::getifaddrs(&mut ifaddrs) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let ifaddrs = IfAddrs(ifaddrs);

    let mut out = Vec::new();
    let mut current = ifaddrs.0;
    while !current.is_null() {
        let iface = unsafe { &*current };
        if !iface.ifa_addr.is_null() && (iface.ifa_flags & libc::IFF_UP as libc::c_uint) != 0 {
            let name = unsafe { CStr::from_ptr(iface.ifa_name) }.to_string_lossy();
            if interface_allowed(&name, allowlist) {
                if let Some(ip) = sockaddr_to_ip(iface.ifa_addr) {
                    push_advertisable_ip(&mut out, ip);
                }
            }
        }
        current = unsafe { (*current).ifa_next };
    }

    Ok(out)
}

#[cfg(unix)]
fn sockaddr_to_ip(sockaddr: *const libc::sockaddr) -> Option<IpAddr> {
    match unsafe { (*sockaddr).sa_family as i32 } {
        libc::AF_INET => {
            let addr = unsafe { *(sockaddr as *const libc::sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                addr.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            let addr = unsafe { *(sockaddr as *const libc::sockaddr_in6) };
            Some(IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

#[cfg(windows)]
fn discover_interface_ips_inner(allowlist: Option<&[String]>) -> std::io::Result<Vec<IpAddr>> {
    use std::io;
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    const INITIAL_ADAPTER_BUFFER_LEN: u32 = 15 * 1024;

    let mut buf_len = INITIAL_ADAPTER_BUFFER_LEN;
    let mut buffer = Vec::<IP_ADAPTER_ADDRESSES_LH>::new();
    loop {
        let buffer_len =
            (buf_len as usize).div_ceil(std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>());
        buffer.resize_with(buffer_len, IP_ADAPTER_ADDRESSES_LH::default);
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST,
                ptr::null(),
                buffer.as_mut_ptr(),
                &mut buf_len,
            )
        };
        match rc {
            ERROR_SUCCESS => break,
            ERROR_BUFFER_OVERFLOW => continue,
            code => return Err(io::Error::from_raw_os_error(code as i32)),
        }
    }

    let mut out = Vec::new();
    let mut adapter = buffer.as_mut_ptr();
    while !adapter.is_null() {
        let adapter_ref = unsafe { &*adapter };
        if adapter_ref.OperStatus == IfOperStatusUp
            && windows_adapter_allowed(adapter_ref, allowlist)
        {
            let mut unicast = adapter_ref.FirstUnicastAddress;
            while !unicast.is_null() {
                let addr = unsafe { &(*unicast).Address };
                if let Some(ip) = windows_socket_address_to_ip(addr.lpSockaddr) {
                    push_advertisable_ip(&mut out, ip);
                }
                unicast = unsafe { (*unicast).Next };
            }
        }
        adapter = adapter_ref.Next;
    }

    Ok(out)
}

#[cfg(windows)]
fn windows_adapter_allowed(
    adapter: &windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH,
    allowlist: Option<&[String]>,
) -> bool {
    let Some(allowlist) = allowlist else {
        return true;
    };
    let adapter_name = (!adapter.AdapterName.is_null()).then(|| unsafe {
        std::ffi::CStr::from_ptr(adapter.AdapterName.cast())
            .to_string_lossy()
            .into_owned()
    });
    let friendly_name = wide_ptr_to_string(adapter.FriendlyName);
    let description = wide_ptr_to_string(adapter.Description);

    [
        adapter_name.as_deref(),
        friendly_name.as_deref(),
        description.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|name| interface_name_allowed(name, allowlist))
}

#[cfg(windows)]
fn wide_ptr_to_string(ptr: windows_sys::core::PWSTR) -> Option<String> {
    if ptr.is_null() {
        return None;
    }

    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    Some(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(ptr, len)
    }))
}

#[cfg(windows)]
fn windows_socket_address_to_ip(
    sockaddr: *mut windows_sys::Win32::Networking::WinSock::SOCKADDR,
) -> Option<IpAddr> {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};

    if sockaddr.is_null() {
        return None;
    }

    match unsafe { (*sockaddr).sa_family } {
        AF_INET => {
            let addr = unsafe { &*(sockaddr as *const SOCKADDR_IN) };
            let octets = unsafe { addr.sin_addr.S_un.S_un_b };
            Some(IpAddr::V4(Ipv4Addr::new(
                octets.s_b1,
                octets.s_b2,
                octets.s_b3,
                octets.s_b4,
            )))
        }
        AF_INET6 => {
            let addr = unsafe { &*(sockaddr as *const SOCKADDR_IN6) };
            let octets = unsafe { addr.sin6_addr.u.Byte };
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

#[cfg(not(any(unix, windows)))]
fn discover_interface_ips_inner(_allowlist: Option<&[String]>) -> std::io::Result<Vec<IpAddr>> {
    Ok(Vec::new())
}

#[cfg(unix)]
fn interface_allowed(name: &str, allowlist: Option<&[String]>) -> bool {
    match allowlist {
        Some(allowlist) => interface_name_allowed(name, allowlist),
        None => true,
    }
}

fn interface_name_allowed(name: &str, allowlist: &[String]) -> bool {
    let name = name.trim();
    let lower_name = name.to_ascii_lowercase();
    allowlist
        .iter()
        .map(|allowed| allowed.trim())
        .filter(|allowed| !allowed.is_empty())
        .any(|allowed| {
            name.eq_ignore_ascii_case(allowed) || lower_name.contains(&allowed.to_ascii_lowercase())
        })
}

fn push_advertisable_ip(out: &mut Vec<IpAddr>, ip: IpAddr) {
    if is_advertisable_interface_ip(ip) && !out.contains(&ip) {
        out.push(ip);
    }
}

fn is_advertisable_interface_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !is_ipv6_unicast_link_local(ip)
        }
    }
}

fn is_ipv6_unicast_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_name_allowlist_is_case_insensitive() {
        let allowlist = vec!["Tailscale".to_string()];

        assert!(interface_name_allowed("tailscale", &allowlist));
        assert!(interface_name_allowed("tailscale0", &allowlist));
        assert!(interface_name_allowed("Tailscale Tunnel", &allowlist));
        assert!(!interface_name_allowed("eth0", &allowlist));
    }

    #[test]
    fn interface_ip_filter_allows_private_and_tailscale_addresses() {
        assert!(is_advertisable_interface_ip("100.64.0.1".parse().unwrap()));
        assert!(is_advertisable_interface_ip("10.0.0.1".parse().unwrap()));
        assert!(is_advertisable_interface_ip("fd00::1".parse().unwrap()));
        assert!(is_advertisable_interface_ip(
            "2001:4860:4860::8888".parse().unwrap()
        ));
    }

    #[test]
    fn interface_ip_filter_rejects_non_dialable_addresses() {
        assert!(!is_advertisable_interface_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_advertisable_interface_ip(
            "169.254.1.1".parse().unwrap()
        ));
        assert!(!is_advertisable_interface_ip("fe80::1".parse().unwrap()));
        assert!(!is_advertisable_interface_ip("ff02::1".parse().unwrap()));
    }
}
