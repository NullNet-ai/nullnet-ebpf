fn main() {

}

pub fn start(
    notification_sender: kanal::Sender<Event>,
    data_sender: kanal::Sender<([u8; RawData::LEN], TrafficDirection)>,
) -> AppResult<()> {
    let iface = "interface_name";

    self.apply();

    load_ingress(
        iface.clone(),
        notification_sender.clone(),
        data_sender.clone(),
        self.filter_chans.ingress.receiver.clone(),
        self.firewall_chans.ingress.receiver.clone(),
        self.traffic_direction.terminate_ingress.clone(),
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
