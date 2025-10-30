use tun::{Configuration};
use std::net::{IpAddr, Ipv4Addr};
use std::io::Read;

pub(crate) fn setup_tap(name: &str, ip: IpAddr, ) {
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

    // handle incoming traffic
    tokio::spawn(async move {
        Box::pin(receive(write_half, &socket_1, &tun_ip)).await;
    });

    // handle outgoing traffic
    tokio::spawn(async move {
        Box::pin(send(read_half, &socket_2, peers_2)).await;
    });
}