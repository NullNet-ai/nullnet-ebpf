use tun::{Configuration};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::io::Read;
use std::sync::Arc;
use tokio::net::UdpSocket;
use crate::tap::receive::receive;
use crate::tap::send::send;

pub(crate) async fn setup_tap(name: &str, ip: IpAddr, peer: IpAddr) {
    let name = name.to_string();
    let mut config = Configuration::default();
    config
        .layer(tun::Layer::L2)
        .mtu(42500)
        .tun_name(name)
        .address(ip)
        .netmask(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)))
        .up();
    // create the asynchronous TUN device, and split it into reader & writer halves
    let device = tun::create_as_async(&config).expect("Failed to create TUN device");
    let (read_half, write_half) = tokio::io::split(device);

    let socket_addr = SocketAddr::new(ip, 9999);
    let socket = Arc::new(UdpSocket::bind(socket_addr).await.unwrap());
    let socket_2 = socket.clone();

    let peer_socket_addr = SocketAddr::new(peer, 9999);

    // handle incoming traffic
    tokio::spawn(async move {
        Box::pin(receive(write_half, &socket)).await;
    });

    // handle outgoing traffic
    tokio::spawn(async move {
        Box::pin(send(read_half, &socket_2, peer_socket_addr)).await;
    });
}