mod ebpf;
mod tap;
mod cli;

use ebpf::load::load_ebpf;
use tap::setup::setup_tap;
use nullnet_common::{TUN0_IPADDR, TUN0_NAME};
use std::net::{IpAddr, Ipv4Addr};
use cli::Args;
use std::str::FromStr;
use clap::Parser;

#[tokio::main]
async fn main() {
    env_logger::init();

    // read CLI arguments
    let Args {
        bind,
        // peer,
    } = Args::parse();

    // kill the main thread as soon as a secondary thread panics
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        orig_hook(panic_info);
        std::process::exit(1);
    }));

    setup_tap(TUN0_NAME, IpAddr::from_str(&bind).unwrap()).await;

    load_ebpf();

    // Keep the main thread alive
    loop {
        std::thread::park();
    }
}
