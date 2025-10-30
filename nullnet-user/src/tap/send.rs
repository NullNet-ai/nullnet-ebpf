use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, ReadHalf};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tun::AsyncDevice;

use crate::forward::frame::Frame;
use crate::peers::peer::{PeerKey, PeerVal};

/// Handles outgoing network packets (receives packets from the TAP interface and sends them to the socket),
/// ensuring the firewall rules are correctly observed.
pub async fn send(
    device: ReadHalf<AsyncDevice>,
    tap_ip: &IpAddr,
) {
    let mut frame = Frame::new();
    let socket_addr = SocketAddr::new(tap_ip, 9999);
    let socket = UdpSocket::bind(forward_socket_addr).await.unwrap();
    loop {
        // wait until there is a packet outgoing from kernel
        frame.size = device
            .read(&mut frame.frame)
            .await
            .unwrap_or(0);

        if frame.size > 0 {
            // send the packet to the socket
            let pkt_data = frame.pkt_data();
            let Some(dst_socket) = get_dst_socket(pkt_data, &peers).await else {
                continue;
            };
            socket.send_to(pkt_data, dst_socket).await.unwrap_or(0);
        }
    }
}

async fn get_dst_socket(
    pkt_data: &[u8],
    peers: &Arc<RwLock<HashMap<PeerKey, PeerVal>>>,
) -> Option<SocketAddr> {
    if pkt_data.len() < 20 {
        None
    } else {
        let dest_ip_slice: [u8; 4] = pkt_data[16..20].try_into().unwrap();
        let dest_ip = IpAddr::from(dest_ip_slice);
        SocketAddr::new(dest_ip, 9999)
    }
}
