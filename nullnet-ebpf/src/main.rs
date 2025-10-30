#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT, TC_ACT_OK, BPF_F_INGRESS},
    macros::{classifier, map},
    maps::{RingBuf},
    programs::TcContext,
    helpers::{bpf_redirect, bpf_l3_csum_replace, bpf_l4_csum_replace},
};
use core::mem;
use nullnet_common::{RawData, RawFrame, TUN0_IPADDR, TUN0_NAME};

#[map]
static DATA: RingBuf = RingBuf::with_byte_size(4096 * RawFrame::LEN as u32, 0);

#[unsafe(no_mangle)]
static PID_HELPER_AVAILABILITY: u8 = 0;

#[unsafe(no_mangle)]
static TRAFFIC_DIRECTION: i32 = 0;

#[unsafe(no_mangle)]
static TUN0_IFINDEX: u32 = 0;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8  = 17;

#[repr(C)]
struct Ipv4Hdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[repr(C)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    doff_res_flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

#[repr(C)]
struct UdpHdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

#[classifier]
pub fn nullnet_drop(ctx: TcContext) -> i32 {
    TC_ACT_SHOT
}

#[classifier]
pub fn nullnet_redirect_ingress(ctx: TcContext) -> i32 {
    match redirect_ingress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

// #[classifier]
// pub fn nullnet_redirect_egress(ctx: TcContext) -> i32 {
//     match redirect_egress(ctx) {
//         Ok(ret) => ret,
//         Err(_) => TC_ACT_PIPE,
//     }
// }

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
fn get_tun0_ifindex() -> u32 {
    unsafe { core::ptr::read_volatile(&TUN0_IFINDEX) }
}

#[inline]
fn redirect_ingress(ctx: TcContext) -> Result<i32, ()> {
    let data = ctx.data() as usize;
    let data_end = ctx.data_end() as usize;

    // Minimal size check for IPv4 header
    if data + mem::size_of::<Ipv4Hdr>() > data_end {
        return Ok(TC_ACT_OK);
    }

    trace!(&ctx, "A");

    let iph = (data as *mut Ipv4Hdr) as *mut Ipv4Hdr;

    unsafe {
        // version check
        if (*iph).version_ihl >> 4 != 4 {
            return Ok(TC_ACT_OK);
        }

        trace!(&ctx, "B");

        let ihl = ((*iph).version_ihl & 0x0f) as usize;
        let ip_hdr_len = ihl * 4;
        let l4_offset = data + ip_hdr_len;

        let old_daddr = (*iph).daddr;
        let new_daddr = TUN0_IPADDR;

        // overwrite destination IP
        (*iph).daddr = new_daddr;

        // fix IPv4 header checksum:
        // helper signature: bpf_l3_csum_replace(skb, offset, from, to, size)
        // offset for IPv4 checksum adjustment is 10 (checksum field bytes offset within header)
        let _ = bpf_l3_csum_replace(ctx.skb.skb, 10, old_daddr as u64, new_daddr as u64, 4);

        trace!(&ctx, "C");

        // If TCP/UDP, update pseudo-header checksum
        match (*iph).protocol {
            IPPROTO_TCP => {
                if l4_offset + mem::size_of::<TcpHdr>() <= data_end {
                    // let tcph = (l4_offset as *mut TcpHdr) as *mut TcpHdr;
                    let _ = bpf_l4_csum_replace(ctx.skb.skb, 0, old_daddr as u64, new_daddr as u64, 4);
                    // Note: offset=0 used here; many kernels ignore offset for l4 helper and operate on the pseudo header.
                    // Some kernels require a correct offset for the checksum field; if so, adjust accordingly.
                }
            }
            IPPROTO_UDP => {
                if l4_offset + mem::size_of::<UdpHdr>() <= data_end {
                    // let udph = (l4_offset as *mut UdpHdr) as *mut UdpHdr;
                    let _ = bpf_l4_csum_replace(ctx.skb.skb, 0, old_daddr as u64, new_daddr as u64, 4);
                }
            }
            _ => {}
        }

        trace!(&ctx, "D");

        // redirect
        Ok(bpf_redirect(get_tun0_ifindex(), BPF_F_INGRESS.into()) as i32)
    }
}

// #[inline]
// fn redirect_egress(ctx: TcContext) -> Result<i32, ()> {
//     let data = ctx.data() as *mut u8;
//     let data_end = ctx.data_end() as *mut u8;
//
//     if data.add(core::mem::size_of::<iphdr>()) > data_end {
//         return Ok(TC_ACT_OK);
//     }
//
//     let iph = &mut *(data as *mut iphdr);
//
//     if iph.version() != 4 {
//         return Ok(TC_ACT_OK);
//     }
//
//     // change source IP
//     let old_src = iph.saddr;
//     iph.saddr = TUN1_IPADDR;
//
//     // fix IPv4 header checksum
//     let _ = bpf_l3_csum_replace(ctx.skb as *mut _, 10, old_src, iph.saddr, 4);
//
//     // fix L4 checksum
//     let _ = bpf_l4_csum_replace(ctx.skb as *mut _, 0, old_src, iph.saddr, 4);
//
//     // redirect
//     Ok(bpf_redirect(TUN1_IFINDEX, 0) as i32)
// }

// #[inline]
// fn process(_ctx: TcContext) -> Result<i32, ()> {
    // let eth_header: *const EthHdr = ptr_at(&ctx, 0)?;
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
// }

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
