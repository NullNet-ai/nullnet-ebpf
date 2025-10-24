use tun::{Configuration};
use std::net::{IpAddr, Ipv4Addr};
use std::io::Read;

pub(crate) fn setup_tun(name: &str, ip: IpAddr) {
    std::thread::spawn(move || {
        let mut config = Configuration::default();
        config
            .mtu(42500)
            .tun_name(name)
            .address(ip)
            .netmask(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)))
            .up();
        let tun = tun::create(&config).unwrap();

        let mut buf = [0; 4096];
        loop {
            let _ = tun.read(&mut buf)?;
        }
    });
}