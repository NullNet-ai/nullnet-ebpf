mod ebpf;
mod tap;

use ebpf::load::load_ebpf;
use tap::setup::setup_tap;
use nullnet_common::{TUN0_IPADDR, TUN0_NAME};
use std::net::{IpAddr, Ipv4Addr};

#[tokio::main]
async fn main() {
    env_logger::init();

    // kill the main thread as soon as a secondary thread panics
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        orig_hook(panic_info);
        std::process::exit(1);
    }));

    setup_tap(TUN0_NAME, IpAddr::V4(Ipv4Addr::from_bits(TUN0_IPADDR))).await;

    load_ebpf();

    // Keep the main thread alive
    loop {
        std::thread::park();
    }
}
