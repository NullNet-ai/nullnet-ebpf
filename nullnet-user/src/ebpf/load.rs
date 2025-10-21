use std::{
    os::fd::AsRawFd,
    thread,
    time::Duration,
};

use aya::{
    EbpfLoader, include_bytes_aligned,
    programs::{SchedClassifier, TcAttachType, tc},
};
use log::error;

use nullnet_common::{TUN1_NAME, TUN0_NAME};

use mio::{Events, Interest, Poll, Token, unix::SourceFd};

use super::{RingBuffer};

pub fn load_ebpf() {
    let Ok(ifaces) = pcap::Device::list() else { return; };
    let ifaces_names: Vec<String> = ifaces.iter().map(|d| d.name.to_owned()).collect();

    // attach nullnet_drop to all interfaces except our TUN interfaces
    // for iface_name in ifaces_names {
    //     if iface_name == TUN1_NAME || iface_name == TUN0_NAME {
    //         continue;
    //     }
    //     for direction in [TcAttachType::Ingress, TcAttachType::Egress] {
    //         let iface_name = iface_name.clone();
    //         thread::spawn({
    //             move || {
    //                 let rlim = libc::rlimit {
    //                     rlim_cur: libc::RLIM_INFINITY,
    //                     rlim_max: libc::RLIM_INFINITY,
    //                 };
    //
    //                 unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    //
    //                 let mut bpf = match EbpfLoader::new()
    //                     .load(include_bytes_aligned!(env!("NULLNET_BIN_PATH")))
    //                 {
    //                     Ok(v) => v,
    //                     Err(e) => {
    //                         error!("Failed to load the eBPF bytecode. {}", e);
    //                         return;
    //                     }
    //                 };
    //
    //                 let _ = tc::qdisc_add_clsact(&iface_name);
    //
    //                 let program: &mut SchedClassifier =
    //                     bpf.program_mut("nullnet_drop").unwrap().try_into().unwrap();
    //
    //                 if let Err(e) = program.load() {
    //                     error!("Failed to load the eBPF program to the kernel. {e}",);
    //                     return;
    //                 };
    //
    //                 if let Err(e) = program.attach(&iface_name, direction) {
    //                     error!("Failed to attach the eBPF program to the interface. {e}",);
    //                     return;
    //                 };
    //
    //                 let mut poll = Poll::new().unwrap();
    //                 let mut events = Events::with_capacity(128);
    //
    //                 // packets reader
    //                 let mut ring_buf = RingBuffer::new(&mut bpf);
    //
    //                 poll.registry()
    //                     .register(
    //                         &mut SourceFd(&ring_buf.buffer.as_raw_fd()),
    //                         Token(0),
    //                         Interest::READABLE,
    //                     )
    //                     .unwrap();
    //
    //                 loop {
    //                     poll.poll(&mut events, Some(Duration::from_millis(100))).unwrap();
    //                     for event in &events {
    //                         if event.token() == Token(0) && event.is_readable() {
    //                             while let Some(_item) = ring_buf.next() {
    //                                 // let data: [u8; RawData::LEN] = item.to_owned().try_into().unwrap();
    //                                 // data_sender.send((data, TrafficDirection::Ingress)).ok();
    //                             }
    //                         }
    //                     }
    //                 }
    //
    //                 // let _ = poll
    //                 //     .registry()
    //                 //     .deregister(&mut SourceFd(&ring_buf.buffer.as_raw_fd()));
    //             }
    //         });
    //     }
    // }

    // attach nullnet_redirect_ingress to TUN1 ingress
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
                            error!("Failed to load the eBPF bytecode. {}", e);
                            return;
                        }
                    };

                    let _ = tc::qdisc_add_clsact(TUN1_NAME);

                    let program: &mut SchedClassifier =
                        bpf.program_mut("nullnet_redirect_ingress").unwrap().try_into().unwrap();

                    if let Err(e) = program.load() {
                        error!("Failed to load the eBPF program to the kernel. {e}",);
                        return;
                    };

                    if let Err(e) = program.attach(TUN1_NAME, TcAttachType::Ingress) {
                        error!("Failed to attach the eBPF program to the interface. {e}",);
                        return;
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
                        poll.poll(&mut events, Some(Duration::from_millis(100))).unwrap();
                        for event in &events {
                            if event.token() == Token(0) && event.is_readable() {
                                while let Some(_item) = ring_buf.next() {
                                    // let data: [u8; RawData::LEN] = item.to_owned().try_into().unwrap();
                                    // data_sender.send((data, TrafficDirection::Ingress)).ok();
                                }
                            }
                        }
                    }

                    // let _ = poll
                    //     .registry()
                    //     .deregister(&mut SourceFd(&ring_buf.buffer.as_raw_fd()));
                }
            });
}
