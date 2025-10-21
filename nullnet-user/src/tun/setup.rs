use tun2::{Configuration};
use std::net::{IpAddr, Ipv4Addr};

pub(crate) fn setup_tun(name: &str, ip: IpAddr) {
    // configure TUN device
    let mut config = Configuration::default();
    config.name(name.to_string());
    config.mtu(42500).address(ip).netmask(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))).up();
}