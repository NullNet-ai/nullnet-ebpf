mod ebpf;

use std::sync::Arc;
use ebpf::load::load_ebpf;

fn main() {
    load_ebpf();

    // Keep the main thread alive
    loop {
        std::thread::park();
    }
}
