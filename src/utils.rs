//! Generic async utilities.

/// Helper for `tokio::select!` with an `Option<Receiver>`.
/// Returns `None` if the receiver is `None` (not subscribed yet),
/// otherwise awaits the next message.
///
/// Useful for conditional branches in `tokio::select!` where you may not
/// have a receiver to wait on yet.
pub async fn recv_optional<T: Clone>(
    rx: Option<&mut tokio::sync::broadcast::Receiver<T>>,
) -> Option<Result<T, tokio::sync::broadcast::error::RecvError>> {
    match rx {
        Some(rx) => Some(rx.recv().await),
        None => std::future::pending().await,
    }
}

pub async fn recv_mpsc_optional<T>(rx: Option<&mut tokio::sync::mpsc::Receiver<T>>) -> Option<T> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}
