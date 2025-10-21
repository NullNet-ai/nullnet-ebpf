mod ebpf;
mod tun;

use ebpf::load::load_ebpf;
use tun::setup::setup_tun;
use nullnet_common::{TUN1_IPADDR, TUN1_NAME, TUN2_IPADDR, TUN2_NAME};
use std::net::{IpAddr, Ipv4Addr};

fn main() {
    // kill the main thread as soon as a secondary thread panics
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        orig_hook(panic_info);
        std::process::exit(1);
    }));

    setup_tun(TUN1_NAME, IpAddr::V4(Ipv4Addr::from_bits(TUN1_IPADDR)));
    setup_tun(TUN2_NAME, IpAddr::V4(Ipv4Addr::from_bits(TUN2_IPADDR)));

    load_ebpf();

    // Keep the main thread alive
    loop {
        std::thread::park();
    }
}
