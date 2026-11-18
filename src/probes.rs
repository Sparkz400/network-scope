use crate::scan::PortState;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

pub async fn connect(ip: IpAddr, port: u16, timeout: Duration) -> PortState {
    match tokio::time::timeout(
        timeout,
        tokio::net::TcpStream::connect(SocketAddr::new(ip, port)),
    )
    .await
    {
        Ok(Ok(_)) => PortState::Open,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => PortState::Closed,
        Err(_) => PortState::Unanswered,
        Ok(Err(e)) => PortState::Error(e.to_string()),
    }
}
