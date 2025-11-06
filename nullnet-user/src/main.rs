mod ebpf;
mod cli;

use ebpf::load::load_ebpf;
use cli::Args;
use clap::Parser;

#[tokio::main]
async fn main() {
    env_logger::init();

    // read CLI arguments
    let Args {
        tun_name,
        eth_name,
    } = Args::parse();

    // kill the main thread as soon as a secondary thread panics
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        orig_hook(panic_info);
        std::process::exit(1);
    }));

    load_ebpf(&tun_name, &eth_name);

    // Keep the main thread alive
    loop {
        std::thread::park();
    }
}
