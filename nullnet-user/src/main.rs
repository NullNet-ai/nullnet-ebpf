use std::sync::Arc;

fn main() {

}

pub fn start(
    notification_sender: kanal::Sender<Event>,
) -> AppResult<()> {
    let iface = "interface_name";

    load_ingress(
        iface.clone(),
        Arc::new(AtomicBool::new(false)),
    );

    // load_egress(
    //     iface,
    //     notification_sender,
    //     data_sender,
    //     self.filter_chans.egress.receiver.clone(),
    //     self.firewall_chans.egress.receiver.clone(),
    //     self.traffic_direction.terminate_egress.clone(),
    // );

    Ok(())
}
