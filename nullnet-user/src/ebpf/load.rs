use std::{
    thread,
};

use aya::{
    EbpfLoader, include_bytes_aligned,
    programs::{SchedClassifier, TcAttachType, tc},
};
use log::{error, debug};

pub fn load_ebpf(tun_name: &str, eth_name: &str) {
    let Ok(ifaces) = pcap::Device::list() else { return; };
    let ifaces_names: Vec<String> = ifaces.iter().map(|d| d.name.to_owned()).collect();

    // attach nullnet_drop to all interfaces except for our ethernet and tun
    for iface_name in ifaces_names {
        if iface_name == eth_name || iface_name == tun_name {
            continue;
        }
        for direction in [TcAttachType::Ingress, TcAttachType::Egress] {
            let iface_name = iface_name.clone();
            thread::spawn({
                move || {
                    debug!("Attaching nullnet_drop to {iface_name} for {direction:?} direction");

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

                    let _ = tc::qdisc_add_clsact(&iface_name);

                    let program: &mut SchedClassifier =
                        bpf.program_mut("nullnet_drop").unwrap().try_into().unwrap();

                    if let Err(e) = program.load() {
                        error!("Failed to load the eBPF program to the kernel. {e}",);
                        return;
                    };

                    if let Err(e) = program.attach(&iface_name, direction) {
                        error!("Failed to attach the eBPF program to the interface '{iface_name}'. {e}",);
                        return;
                    };

                    loop {
                        std::thread::park();
                    }
                }
            });
        }
    }

    // attach nullnet_filter_ports to the ethernet interface
    for direction in [TcAttachType::Ingress, TcAttachType::Egress] {
        let eth_name = eth_name.to_string();
    thread::spawn({
        move || {
            debug!("Attaching nullnet_filter_ports to {eth_name} for {direction:?} direction");

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

            let _ = tc::qdisc_add_clsact(&eth_name);

            let program: &mut SchedClassifier =
                bpf.program_mut("nullnet_filter_ports").unwrap().try_into().unwrap();

            if let Err(e) = program.load() {
                error!("Failed to load the eBPF program to the kernel. {e}",);
                return;
            };

            if let Err(e) = program.attach(&eth_name, direction) {
                error!("Failed to attach the eBPF program to the interface '{eth_name}'. {e}",);
                return;
            };

            loop {
                std::thread::park();
            }
        }
    });
    }
}
