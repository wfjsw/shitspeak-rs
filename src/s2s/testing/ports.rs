//! Free-port and loopback-address helpers for tests.

use std::net::SocketAddr;

/// Build a 127.0.0.1:`port` `SocketAddr`.
pub fn loopback(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// Bind ephemeral, drop, and return the port. Used by tests that need a
/// known TCP port before the listener is up.
///
/// Note: there's an inherent race window between this returning and the
/// real listener binding. Tests that spin up multiple managers in parallel
/// should serialize allocation under a mutex.
pub async fn pick_free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// Same as `pick_free_port` but for UDP.
pub async fn pick_free_udp_port() -> u16 {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let p = s.local_addr().unwrap().port();
    drop(s);
    p
}
