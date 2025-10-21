mod ebpf;

use ebpf::load::load_ebpf;

fn main() {
    // kill the main thread as soon as a secondary thread panics
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        orig_hook(panic_info);
        std::process::exit(1);
    }));

    // setup_tun();

    load_ebpf();

    // Keep the main thread alive
    loop {
        std::thread::park();
    }
}
