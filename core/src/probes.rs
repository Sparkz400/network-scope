use crate::scan::PortState;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

pub async fn connect(ip: IpAddr, port: u16, timeout: Duration) -> PortState {
    let attempt = async {
        let address = SocketAddr::new(ip, port);
        let socket = match address {
            SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
            SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
        };
        #[cfg(windows)]
        no_syn_retransmissions(&socket, timeout);
        socket.connect(address).await
    };
    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(_)) => PortState::Open,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => PortState::Closed,
        // The OS may give up at the same moment as the timer (see `no_syn_retransmissions`).
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::TimedOut => PortState::Unanswered,
        Ok(Err(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ) =>
        {
            PortState::Reset
        }
        Err(_) => PortState::Unanswered,
        Ok(Err(e)) => PortState::Error(e.to_string()),
    }
}

/// Windows answers a SYN that gets a RST by sending the SYN again (twice, 0.5 s and 1 s
/// later) and reports "connection refused" only after about 2 s, which is the default probe
/// timeout: closed ports then look unanswered. Turning off SYN retransmissions for the probe
/// socket (`SIO_TCP_INITIAL_RTO` with `TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS`, Windows 10+)
/// makes a RST end the connect at once. Silent (filtered) ports still wait for the timeout,
/// because the initial RTO is set to the probe timeout; a lost SYN is covered by `--retries`.
/// Best effort: if the ioctl fails (older Windows), the probe behaves as before.
#[cfg(windows)]
fn no_syn_retransmissions(socket: &tokio::net::TcpSocket, timeout: Duration) {
    use std::{ffi::c_void, os::windows::io::AsRawSocket};

    #[repr(C)]
    struct InitialRto {
        rtt: u16,
        max_syn_retransmissions: u8,
    }
    const SIO_TCP_INITIAL_RTO: u32 = 0x9800_0011;
    const TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS: u8 = 0xFE;

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn WSAIoctl(
            socket: usize,
            control_code: u32,
            in_buffer: *const c_void,
            in_length: u32,
            out_buffer: *mut c_void,
            out_length: u32,
            bytes_returned: *mut u32,
            overlapped: *mut c_void,
            completion: *mut c_void,
        ) -> i32;
    }

    let parameters = InitialRto {
        // 0xFFFF means "unspecified"; stay below it.
        rtt: u16::try_from(timeout.as_millis())
            .unwrap_or(u16::MAX - 1)
            .clamp(1, u16::MAX - 1),
        max_syn_retransmissions: TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS,
    };
    let mut returned = 0u32;
    // SAFETY: a valid socket handle, an input buffer of the stated size that outlives the
    // synchronous call (no OVERLAPPED), no output buffer.
    unsafe {
        WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_TCP_INITIAL_RTO,
            (&raw const parameters).cast(),
            size_of::<InitialRto>() as u32,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
    }
}

/// A loopback port that refuses connections, for tests, with the socket that keeps it that way
/// (hold it until the test has connected). The socket is bound and never listens: Linux and
/// Windows answer a SYN to it with a reset, and no listener of a test running at the same time
/// can be given the port, which happened to ports that were bound and released again.
/// Elsewhere the port is released as before (`None`): macOS drops such a SYN instead of
/// refusing it (seen in CI, 2026-11-25), so there a port that is bound and released is the
/// only refused one, and another test may still be given it.
#[cfg(test)]
pub(crate) fn refused_port() -> (u16, Option<socket2::Socket>) {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    socket
        .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
        .unwrap();
    let port = socket.local_addr().unwrap().as_socket().unwrap().port();
    (
        port,
        cfg!(any(windows, target_os = "linux")).then_some(socket),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_and_closed_loopback_ports_are_classified() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap().port();
        let localhost: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            connect(localhost, open, Duration::from_secs(2)).await,
            PortState::Open
        );
        let (closed, _reserved) = refused_port();
        assert_eq!(
            connect(localhost, closed, Duration::from_secs(3)).await,
            PortState::Closed
        );
    }

    /// The regression this guards against: on Windows a refused connect used to take about
    /// 2 s (SYN retransmissions after the RST), so with the default 2 s timeout every closed
    /// port was reported as unanswered.
    #[tokio::test]
    async fn a_refused_port_is_closed_well_within_the_default_timeout() {
        let (port, _reserved) = refused_port();
        let started = std::time::Instant::now();
        let state = connect("127.0.0.1".parse().unwrap(), port, Duration::from_secs(2)).await;
        assert_eq!(state, PortState::Closed);
        assert!(
            started.elapsed() < Duration::from_millis(1000),
            "refused after {:?}",
            started.elapsed()
        );
    }
}
