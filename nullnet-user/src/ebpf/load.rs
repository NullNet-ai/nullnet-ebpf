use std::collections::HashMap;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::Duration;

use aya::{
    EbpfLoader, include_bytes_aligned,
    maps::{HashMap as AyaHashMap, RingBuf},
    programs::{SchedClassifier, TcAttachType, tc},
};
use log::{debug, error, warn};

use crate::triggers;

const TRIGGER_ADDR: &str = "127.0.0.1:8888";
const TRIGGER_TIMEOUT: Duration = Duration::from_secs(2);
const EVENTS_POLL_INTERVAL: Duration = Duration::from_millis(50);

pub fn load_ebpf(eth_name: &str) {
    let port_to_services = triggers::load();

    for direction in [TcAttachType::Ingress, TcAttachType::Egress] {
        let eth_name = eth_name.to_string();
        let port_to_services = port_to_services.clone();
        thread::spawn(move || {
            debug!("Attaching nullnet_filter_ports to {eth_name} for {direction:?} direction");

            let rlim = libc::rlimit {
                rlim_cur: libc::RLIM_INFINITY,
                rlim_max: libc::RLIM_INFINITY,
            };

            unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

            let mut loader = EbpfLoader::new();
            if direction == TcAttachType::Egress {
                loader.set_global("IS_EGRESS", &1u8, true);
            }
            let mut bpf = match loader.load(include_bytes_aligned!(env!("NULLNET_BIN_PATH"))) {
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
                error!("Failed to load the eBPF program to the kernel. {e}");
                return;
            }

            if let Err(e) = program.attach(&eth_name, direction) {
                error!("Failed to attach the eBPF program to the interface '{eth_name}'. {e}");
                return;
            }

            if direction == TcAttachType::Egress {
                run_observer(&mut bpf, port_to_services);
            } else {
                loop {
                    thread::park();
                }
            }
        });
    }
}

fn run_observer(bpf: &mut aya::Ebpf, port_to_services: HashMap<u16, Vec<String>>) {
    {
        let mut watch_ports: AyaHashMap<_, u16, u8> = match bpf
            .map_mut("WATCH_PORTS")
            .unwrap()
            .try_into()
        {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to access WATCH_PORTS map: {e}");
                return;
            }
        };
        for &port in port_to_services.keys() {
            if let Err(e) = watch_ports.insert(port, 0u8, 0) {
                warn!("Failed to insert watch port {port}: {e}");
            }
        }
    }

    let mut events: RingBuf<_> = match bpf.take_map("EVENTS").unwrap().try_into() {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to access EVENTS ring buffer: {e}");
            return;
        }
    };

    loop {
        while let Some(item) = events.next() {
            let bytes: &[u8] = &item;
            if bytes.len() < 2 {
                continue;
            }
            let port = u16::from_ne_bytes([bytes[0], bytes[1]]);
            if let Some(services) = port_to_services.get(&port) {
                for service_name in services {
                    fire_trigger(service_name);
                }
            }
        }
        thread::sleep(EVENTS_POLL_INTERVAL);
    }
}

fn fire_trigger(service_name: &str) {
    let addr: SocketAddr = TRIGGER_ADDR.parse().unwrap();
    let mut stream = match TcpStream::connect_timeout(&addr, TRIGGER_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to connect to client trigger endpoint for '{service_name}': {e}");
            return;
        }
    };
    let _ = stream.set_write_timeout(Some(TRIGGER_TIMEOUT));
    let req = format!(
        "GET /trigger/{service_name} HTTP/1.0\r\n\
         Host: 127.0.0.1\r\n\
         Connection: close\r\n\
         \r\n"
    );
    if let Err(e) = stream.write_all(req.as_bytes()) {
        warn!("Failed to send trigger for '{service_name}': {e}");
    } else {
        debug!("Triggered '{service_name}'");
    }
}
