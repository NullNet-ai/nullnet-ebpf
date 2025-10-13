use std::{
    net::IpAddr,
    os::fd::AsRawFd,
    sync::{Arc, atomic::AtomicBool},
    thread,
    time::Duration,
};

use aya::{
    EbpfLoader, include_bytes_aligned,
    maps::{Array, HashMap},
    programs::{SchedClassifier, TcAttachType, tc},
};
use log::error;
use nullnet_common::{MAX_RULES_PORT, RawData, protocols::Protocol};

use mio::{Events, Interest, Poll, Token, unix::SourceFd};

use super::{
    EbpfTrafficDirection, RingBuffer,
    // firewall::{update_ipv4_blocklist, update_ipv6_blocklist},
};

pub fn load_ingress(
    terminate: Arc<AtomicBool>,
) {
    let Ok(ifaces) = pcap::Device::list() else { return; };
    let ifaces_names: Vec<String> = ifaces.iter().map(|d| d.name.to_owned()).collect();

    for direction in [TcAttachType::Ingress, TcAttachType::Egress] {
        for iface_name in ifaces_names {
            thread::spawn({
                move || {
                    let rlim = libc::rlimit {
                        rlim_cur: libc::RLIM_INFINITY,
                        rlim_max: libc::RLIM_INFINITY,
                    };

                    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

                    let mut bpf = match EbpfLoader::new()
                        .load(include_bytes_aligned!(env!("NULLNET_BIN_PATH")))
                    {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Failed to load the ingress eBPF bytecode. {}", e);
                            return;;
                        }
                    };

                    let _ = tc::qdisc_add_clsact(&iface_name);

                    let program: &mut SchedClassifier =
                        bpf.program_mut("nullnet").unwrap().try_into().unwrap();

                    if let Err(e) = program.load() {
                        error!("Failed to load the ingress eBPF program to the kernel. {e}",);
                        return;;
                    };

                    if let Err(e) = program.attach(&iface_name, direction) {
                        error!("Failed to attach the ingress eBPF program to the interface. {e}",);
                        return;;
                    };

                    let mut poll = Poll::new().unwrap();
                    let mut events = Events::with_capacity(128);

                    // packets reader
                    let mut ring_buf = RingBuffer::new(&mut bpf);

                    poll.registry()
                        .register(
                            &mut SourceFd(&ring_buf.buffer.as_raw_fd()),
                            Token(0),
                            Interest::READABLE,
                        )
                        .unwrap();

                    loop {
                        poll.poll(&mut events, Some(Duration::from_millis(100)))
                            .unwrap();
                        // if terminate.load(std::sync::atomic::Ordering::Relaxed) {
                        //     break;
                        // }
                        for event in &events {
                            // if terminate.load(std::sync::atomic::Ordering::Relaxed) {
                            //     break;
                            // }
                            if event.token() == Token(0) && event.is_readable() {
                                // if terminate.load(std::sync::atomic::Ordering::Relaxed) {
                                //     break;
                                // }
                                while let Some(item) = ring_buf.next() {
                                    // if terminate.load(std::sync::atomic::Ordering::Relaxed) {
                                    //     break;
                                    // }
                                    // let data: [u8; RawData::LEN] = item.to_owned().try_into().unwrap();
                                    // data_sender.send((data, TrafficDirection::Ingress)).ok();
                                }
                            }
                        }
                    }

                    let _ = poll
                        .registry()
                        .deregister(&mut SourceFd(&ring_buf.buffer.as_raw_fd()));
                }
            });
        }
    }
}
