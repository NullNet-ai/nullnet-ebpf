use tun::{Configuration};
use std::net::{IpAddr, Ipv4Addr};

pub(crate) fn setup_tun(name: &str, ip: IpAddr) {
    let mut config = Configuration::default();
    config
        .mtu(42500)
        .tun_name(name)
        .address(ip)
        .netmask(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)))
        .up();
    let _ = tun::create(&config).unwrap();
}