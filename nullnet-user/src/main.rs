mod ebpf;

use std::sync::Arc;
use ebpf::ingress::load_ingress;

fn main() {
    start();

    // Keep the main thread alive
    loop {
        std::thread::park();
    }
}

pub fn start(
    // notification_sender: kanal::Sender<Event>,
) {
    let iface = "interface_name";

    load_ingress(
        iface,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
    );

    // load_egress(
    //     iface,
    //     notification_sender,
    //     data_sender,
    //     self.filter_chans.egress.receiver.clone(),
    //     self.firewall_chans.egress.receiver.clone(),
    //     self.traffic_direction.terminate_egress.clone(),
    // );
}
