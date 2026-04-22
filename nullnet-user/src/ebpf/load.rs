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

use crate::triggers;

const TRIGGER_ADDR: &str = "127.0.0.1:8888";
const TRIGGER_TIMEOUT: Duration = Duration::from_secs(2);
const EVENTS_POLL_INTERVAL: Duration = Duration::from_millis(50);

pub fn load_ebpf(eth_name: &str) {
    let port_to_services = triggers::load();
    println!(
        "[load_ebpf] eth={eth_name} triggers={} ports={:?}",
        port_to_services.len(),
        port_to_services.keys().collect::<Vec<_>>()
    );

    for direction in [TcAttachType::Ingress, TcAttachType::Egress] {
        let eth_name = eth_name.to_string();
        let port_to_services = port_to_services.clone();
        thread::spawn(move || {
            println!("[{direction:?}] thread started; attaching to {eth_name}");

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
                    eprintln!("[{direction:?}] failed to load eBPF bytecode: {e}");
                    return;
                }
            };
            println!("[{direction:?}] eBPF bytecode loaded");

            match tc::qdisc_add_clsact(&eth_name) {
                Ok(()) => println!("[{direction:?}] clsact qdisc added on {eth_name}"),
                Err(e) => println!("[{direction:?}] clsact qdisc add returned: {e} (ok if already present)"),
            }

            let program: &mut SchedClassifier =
                bpf.program_mut("nullnet_filter_ports").unwrap().try_into().unwrap();

            if let Err(e) = program.load() {
                eprintln!("[{direction:?}] failed to load program into kernel: {e}");
                return;
            }
            println!("[{direction:?}] program loaded into kernel");

            if let Err(e) = program.attach(&eth_name, direction) {
                eprintln!("[{direction:?}] failed to attach to '{eth_name}': {e}");
                return;
            }
            println!("[{direction:?}] program attached to {eth_name}");

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
                eprintln!("[observer] failed to access WATCH_PORTS map: {e}");
                return;
            }
        };
        for &port in port_to_services.keys() {
            match watch_ports.insert(port, 0u8, 0) {
                Ok(()) => println!("[observer] watching port {port}"),
                Err(e) => eprintln!("[observer] failed to insert watch port {port}: {e}"),
            }
        }
    }

    let mut events: RingBuf<_> = match bpf.take_map("EVENTS").unwrap().try_into() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[observer] failed to access EVENTS ring buffer: {e}");
            return;
        }
    };
    println!("[observer] polling EVENTS ring buffer");

    loop {
        while let Some(item) = events.next() {
            let bytes: &[u8] = &item;
            println!("[observer] event ({} bytes): {bytes:?}", bytes.len());
            if bytes.len() < 2 {
                continue;
            }
            let port = u16::from_ne_bytes([bytes[0], bytes[1]]);
            println!("[observer] decoded port={port}");
            if let Some(services) = port_to_services.get(&port) {
                for service_name in services {
                    fire_trigger(service_name);
                }
            } else {
                println!("[observer] no services mapped to port {port}");
            }
        }
        thread::sleep(EVENTS_POLL_INTERVAL);
    }
}

fn fire_trigger(service_name: &str) {
    println!("[trigger] firing for '{service_name}'");
    let addr: SocketAddr = TRIGGER_ADDR.parse().unwrap();
    let mut stream = match TcpStream::connect_timeout(&addr, TRIGGER_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[trigger] connect to {TRIGGER_ADDR} failed for '{service_name}': {e}");
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
        eprintln!("[trigger] write failed for '{service_name}': {e}");
    } else {
        println!("[trigger] sent for '{service_name}'");
    }
}
