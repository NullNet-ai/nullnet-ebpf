use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, ReadHalf};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tun::AsyncDevice;

use crate::tap::frame::Frame;

/// Handles outgoing network packets (receives packets from the TAP interface and sends them to the socket),
/// ensuring the firewall rules are correctly observed.
pub async fn send(
    mut device: ReadHalf<AsyncDevice>,
    socket: &Arc<UdpSocket>,
) {
    let mut frame = Frame::new();
    loop {
        // wait until there is a packet outgoing from kernel
        frame.size = device
            .read(&mut frame.frame)
            .await
            .unwrap_or(0);

        if frame.size > 0 {
            // send the packet to the socket
            let pkt_data = frame.pkt_data();
            let Some(dst_socket) = get_dst_socket(pkt_data).await else {
                continue;
            };
            println!("Sending packet to {}", dst_socket);
            socket.send_to(pkt_data, dst_socket).await.unwrap_or(0);
        }
    }
}

async fn get_dst_socket(
    pkt_data: &[u8],
) -> Option<SocketAddr> {
    if pkt_data.len() < 20 {
        None
    } else {
        let dest_ip_slice: [u8; 4] = pkt_data[16..20].try_into().unwrap();
        let dest_ip = IpAddr::from(dest_ip_slice);
        Some(SocketAddr::new(dest_ip, 9999))
    }
}
