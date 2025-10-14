#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::bpf_get_current_pid_tgid,
    macros::{classifier, map},
    maps::{Array, HashMap, RingBuf},
    programs::TcContext,
};
use core::mem;
use network_types::{
    arp::ArpHdr,
    eth::{EthHdr, EtherType},
    icmp::{Icmp, IcmpHdr, IcmpV6Hdr},
    ip::{IpHdr, IpProto, Ipv4Hdr, Ipv6Hdr},
    sctp::SctpHdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};
use nullnet_common::{MAX_FIREWALL_RULES, ProtoHdr, RawData, RawFrame, RawPacket};

#[map]
static DATA: RingBuf = RingBuf::with_byte_size(4096 * RawFrame::LEN as u32, 0);

#[unsafe(no_mangle)]
static PID_HELPER_AVAILABILITY: u8 = 0;

#[unsafe(no_mangle)]
static TRAFFIC_DIRECTION: i32 = 0;

#[classifier]
pub fn nullnet(ctx: TcContext) -> i32 {
    match process(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

#[inline]
fn submit(data: RawData) {
    if let Some(mut buf) = DATA.reserve::<RawData>(0) {
        unsafe { (*buf.as_mut_ptr()) = data };
        buf.submit(0);
    }
}

#[inline]
fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline]
fn is_ingress() -> bool {
    let traffic_direction = unsafe { core::ptr::read_volatile(&TRAFFIC_DIRECTION) };
    traffic_direction == -1
}

#[inline]
fn process(ctx: TcContext) -> Result<i32, ()> {
    // just drop every packet for now
    return Ok(TC_ACT_SHOT);

    // let eth_header: *const EthHdr = ptr_at(&ctx, 0)?;
    //
    // let pid = if is_ingress() {
    //     None
    // } else {
    //     let is_pid_helper_available = unsafe { core::ptr::read_volatile(&PID_HELPER_AVAILABILITY) };
    //
    //     if is_pid_helper_available == 1 {
    //         Some((bpf_get_current_pid_tgid() >> 32) as u32)
    //     } else {
    //         None
    //     }
    // };
    //
    // let ether_type = EtherType::try_from(unsafe { (*eth_header).ether_type }).map_err(|_| ())?;
    //
    // match ether_type {
    //     EtherType::Ipv4 => {
    //         let ipv4_header: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    //
    //         let addr = unsafe {
    //             if is_ingress() {
    //                 u32::from_be_bytes((*ipv4_header).src_addr)
    //             } else {
    //                 u32::from_be_bytes((*ipv4_header).dst_addr)
    //             }
    //         };
    //
    //         match unsafe { (*ipv4_header).proto } {
    //             IpProto::Tcp => {
    //                 let tcp_header: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    //
    //                 let port = if is_ingress() {
    //                     u16::from_be_bytes(unsafe { (*tcp_header).source })
    //                 } else {
    //                     u16::from_be_bytes(unsafe { (*tcp_header).dest })
    //                 };
    //
    //                 unsafe {
    //                     submit(RawData {
    //                         frame: RawFrame {
    //                             header: *eth_header,
    //                             payload: RawPacket::Ip(
    //                                 IpHdr::V4(*ipv4_header),
    //                                 ProtoHdr::Tcp(*tcp_header),
    //                             ),
    //                         },
    //                         pid,
    //                     });
    //                 }
    //             }
    //             IpProto::Udp => {
    //                 let udp_header: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    //
    //                 let port = if is_ingress() {
    //                     u16::from_be_bytes(unsafe { (*udp_header).src })
    //                 } else {
    //                     u16::from_be_bytes(unsafe { (*udp_header).dst })
    //                 };
    //
    //                 unsafe {
    //                     submit(RawData {
    //                         frame: RawFrame {
    //                             header: *eth_header,
    //                             payload: RawPacket::Ip(
    //                                 IpHdr::V4(*ipv4_header),
    //                                 ProtoHdr::Udp(*udp_header),
    //                             ),
    //                         },
    //                         pid,
    //                     });
    //                 }
    //             }
    //             IpProto::Sctp => {
    //                 let sctp_header: *const SctpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    //
    //                 let port = if is_ingress() {
    //                     u16::from_be_bytes(unsafe { (*sctp_header).src })
    //                 } else {
    //                     u16::from_be_bytes(unsafe { (*sctp_header).dst })
    //                 };
    //
    //                 unsafe {
    //                     submit(RawData {
    //                         frame: RawFrame {
    //                             header: *eth_header,
    //                             payload: RawPacket::Ip(
    //                                 IpHdr::V4(*ipv4_header),
    //                                 ProtoHdr::Sctp(*sctp_header),
    //                             ),
    //                         },
    //                         pid,
    //                     });
    //                 }
    //             }
    //             IpProto::Icmp => {
    //                 let icmp_header: *const IcmpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    //
    //                 unsafe {
    //                     submit(RawData {
    //                         frame: RawFrame {
    //                             header: *eth_header,
    //                             payload: RawPacket::Ip(
    //                                 IpHdr::V4(*ipv4_header),
    //                                 ProtoHdr::Icmp(Icmp::V4(*icmp_header)),
    //                             ),
    //                         },
    //                         pid,
    //                     });
    //                 }
    //             }
    //             _ => {}
    //         }
    //     }
    //     EtherType::Ipv6 => {
    //         let ipv6_header: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    //
    //         let addr = unsafe {
    //             if is_ingress() {
    //                 (*ipv6_header).src_addr().to_bits()
    //             } else {
    //                 (*ipv6_header).dst_addr().to_bits()
    //             }
    //         };
    //
    //         match unsafe { (*ipv6_header).next_hdr } {
    //             IpProto::Tcp => {
    //                 let tcp_header: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
    //
    //                 let port = unsafe {
    //                     if is_ingress() {
    //                         u16::from_be_bytes((*tcp_header).source)
    //                     } else {
    //                         u16::from_be_bytes((*tcp_header).dest)
    //                     }
    //                 };
    //
    //                 unsafe {
    //                     submit(RawData {
    //                         frame: RawFrame {
    //                             header: *eth_header,
    //                             payload: RawPacket::Ip(
    //                                 IpHdr::V6(*ipv6_header),
    //                                 ProtoHdr::Tcp(*tcp_header),
    //                             ),
    //                         },
    //                         pid,
    //                     });
    //                 }
    //             }
    //             IpProto::Udp => {
    //                 let udp_header: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
    //
    //                 let port = unsafe {
    //                     if is_ingress() {
    //                         u16::from_be_bytes((*udp_header).src)
    //                     } else {
    //                         u16::from_be_bytes((*udp_header).dst)
    //                     }
    //                 };
    //
    //                 unsafe {
    //                     submit(RawData {
    //                         frame: RawFrame {
    //                             header: *eth_header,
    //                             payload: RawPacket::Ip(
    //                                 IpHdr::V6(*ipv6_header),
    //                                 ProtoHdr::Udp(*udp_header),
    //                             ),
    //                         },
    //                         pid,
    //                     });
    //                 }
    //             }
    //             IpProto::Sctp => {
    //                 let sctp_header: *const SctpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    //
    //                 let port = if is_ingress() {
    //                     u16::from_be_bytes(unsafe { (*sctp_header).src })
    //                 } else {
    //                     u16::from_be_bytes(unsafe { (*sctp_header).dst })
    //                 };
    //
    //                 unsafe {
    //                     submit(RawData {
    //                         frame: RawFrame {
    //                             header: *eth_header,
    //                             payload: RawPacket::Ip(
    //                                 IpHdr::V6(*ipv6_header),
    //                                 ProtoHdr::Sctp(*sctp_header),
    //                             ),
    //                         },
    //                         pid,
    //                     });
    //                 }
    //             }
    //             IpProto::Ipv6Icmp => {
    //                 let icmp_header: *const IcmpV6Hdr = ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
    //
    //                 unsafe {
    //                     submit(RawData {
    //                         frame: RawFrame {
    //                             header: *eth_header,
    //                             payload: RawPacket::Ip(
    //                                 IpHdr::V6(*ipv6_header),
    //                                 ProtoHdr::Icmp(Icmp::V6(*icmp_header)),
    //                             ),
    //                         },
    //                         pid,
    //                     });
    //                 }
    //             }
    //             _ => {}
    //         }
    //     }
    //     EtherType::Arp => {
    //         let arp_header: *const ArpHdr = ptr_at(&ctx, EthHdr::LEN)?;
    //
    //         unsafe {
    //             submit(RawData {
    //                 frame: RawFrame {
    //                     header: *eth_header,
    //                     payload: RawPacket::Arp(*arp_header),
    //                 },
    //                 pid,
    //             });
    //         }
    //     }
    //     _ => {}
    // };
    //
    // Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
