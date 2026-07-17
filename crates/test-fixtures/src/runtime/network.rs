use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::thread;
use std::time::Duration;

use super::FixtureError;
use super::config::{NetworkAddress, NetworkConfig};

pub(crate) fn run(config: NetworkConfig) -> Result<(), FixtureError> {
    let address = ip_address(config.address);
    let tcp_listener =
        TcpListener::bind(SocketAddr::new(address, 0)).map_err(|_| FixtureError::Runtime)?;
    let udp_socket =
        UdpSocket::bind(SocketAddr::new(address, 0)).map_err(|_| FixtureError::Runtime)?;
    let tcp_port = tcp_listener
        .local_addr()
        .map_err(|_| FixtureError::Runtime)?
        .port();
    let udp_port = udp_socket
        .local_addr()
        .map_err(|_| FixtureError::Runtime)?
        .port();
    if tcp_port == 0 || udp_port == 0 {
        return Err(FixtureError::Runtime);
    }

    let mut output = std::io::stdout().lock();
    writeln!(
        output,
        "MAGICTOOLS_TEST_FIXTURE_NETWORK_READY address={} tcp_port={tcp_port} udp_port={udp_port}",
        address_name(config.address)
    )
    .map_err(|_| FixtureError::Runtime)?;
    output.flush().map_err(|_| FixtureError::Runtime)?;
    drop(output);

    thread::sleep(Duration::from_millis(config.hold_ms));
    drop((tcp_listener, udp_socket));
    Ok(())
}

fn ip_address(address: NetworkAddress) -> IpAddr {
    match address {
        NetworkAddress::Ipv4Loopback => IpAddr::V4(Ipv4Addr::LOCALHOST),
        NetworkAddress::Ipv4Unspecified => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        NetworkAddress::Ipv6Loopback => IpAddr::V6(Ipv6Addr::LOCALHOST),
        NetworkAddress::Ipv6Unspecified => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

fn address_name(address: NetworkAddress) -> &'static str {
    match address {
        NetworkAddress::Ipv4Loopback => "127.0.0.1",
        NetworkAddress::Ipv4Unspecified => "0.0.0.0",
        NetworkAddress::Ipv6Loopback => "::1",
        NetworkAddress::Ipv6Unspecified => "::",
    }
}
