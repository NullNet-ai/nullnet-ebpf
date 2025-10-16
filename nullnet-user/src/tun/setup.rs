pub(crate) fn setup_tun(tun_ip: IpAddr, netmask: IpAddr, num_tasks:usize) {
    // configure TUN device
    let mut config = Configuration::default();
    // set_tun_name(&tun_ip, &netmask, &mut config);
    config.mtu(42500).address(tun_ip).netmask(netmask).up();

    // create the asynchronous TUN device, and split it into reader & writer halves
    let device = tun2::create_as_async(&config).expect("failed to create TUN device");
    let (read_half, write_half) = tokio::io::split(device);
    let reader_shared = Arc::new(Mutex::new(read_half));
    let writer_shared = Arc::new(Mutex::new(write_half));

    // spawn a number of asynchronous tasks to handle incoming and outgoing network traffic
    for _ in 0..num_tasks / 2 {
        let writer = writer_shared.clone();
        let reader = reader_shared.clone();
        let socket_1 = forward_socket.clone();
        let socket_2 = socket_1.clone();
        let peers_2 = peers.clone();

        // handle incoming traffic
        tokio::spawn(async move {
            Box::pin(receive(&writer, &socket_1, &tun_ip)).await;
        });

        // handle outgoing traffic
        tokio::spawn(async move {
            Box::pin(send(&reader, &socket_2, peers_2)).await;
        });
    }
}