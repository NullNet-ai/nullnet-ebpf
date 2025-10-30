use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tun::AsyncDevice;

use crate::tap::frame::Frame;

/// Handles incoming network packets (receives packets from the socket and sends them to the TUN interface),
/// ensuring the firewall rules are correctly observed.
pub async fn receive(
    device: WriteHalf<AsyncDevice>,
    tap_ip: IpAddr,
) {
    let mut frame = Frame::new();
    let mut _remote_socket;
    let socket_addr = SocketAddr::new(*tap_ip, 9999);
    let socket = UdpSocket::bind(socket_addr).await.unwrap();
    loop {
        // wait until there is an incoming packet on the socket (packets on the socket are raw IP)
        (frame.size, _remote_socket) = socket
            .recv_from(&mut frame.frame)
            .await
            .unwrap_or_else(|_| (0, SocketAddr::from_str("0.0.0.0:0").unwrap()));

        if frame.size > 0 {
            let pkt_data = frame.pkt_data();
            // write packet to the kernel
            device.lock().await.write_all(pkt_data).await.unwrap_or(());
        }
    }
}
