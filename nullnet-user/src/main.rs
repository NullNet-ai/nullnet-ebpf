mod ebpf;
mod env;
mod triggers;

use ebpf::load::load_ebpf;
use env::ETH_NAME;

fn main() {
    env_logger::init();

    // kill the main thread as soon as a secondary thread panics
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        orig_hook(panic_info);
        std::process::exit(1);
    }));

    load_ebpf(&ETH_NAME);

    // Keep the main thread alive
    loop {
        std::thread::park();
    }
}
