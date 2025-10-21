#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT, TC_ACT_OK, BPF_F_INGRESS, iphdr},
    macros::{classifier, map},
    maps::{RingBuf},
    programs::TcContext,
    helpers::{bpf_redirect, bpf_l3_csum_replace, bpf_l4_csum_replace},
};
use core::mem;
use nullnet_common::{RawData, RawFrame};

#[map]
static DATA: RingBuf = RingBuf::with_byte_size(4096 * RawFrame::LEN as u32, 0);

#[unsafe(no_mangle)]
static PID_HELPER_AVAILABILITY: u8 = 0;

#[unsafe(no_mangle)]
static TRAFFIC_DIRECTION: i32 = 0;

static TUN1_IPADDR: u32 = u32::from_be_bytes([10, 0, 0, 1]);
static TUN2_IPADDR: u32 = u32::from_be_bytes([10, 0, 1, 1]);

static TUN1_IFINDEX: u32 = 5;
static TUN2_IFINDEX: u32 = 6;

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

#[classifier]
pub fn nullnet_redirect_egress(ctx: TcContext) -> i32 {
    match redirect_egress(ctx) {
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
fn redirect_ingress(ctx: TcContext) -> Result<i32, ()> {
    let data = ctx.data() as *mut u8;
    let data_end = ctx.data_end() as *mut u8;

    if data.add(core::mem::size_of::<iphdr>()) > data_end {
        return Ok(TC_ACT_OK);
    }

    let iph = &mut *(data as *mut iphdr);

    if iph.version() != 4 {
        return Ok(TC_ACT_OK);
    }

    // change dest IP
    let old_dst = iph.daddr;
    iph.daddr = TUN2_IPADDR;

    // fix IPv4 header checksum
    let _ = bpf_l3_csum_replace(ctx.skb as *mut _, 10, old_dst, iph.daddr, 4);

    // fix L4 checksum
    let _ = bpf_l4_csum_replace(ctx.skb as *mut _, 0, old_dst, iph.daddr, 4);

    // redirect
    Ok(bpf_redirect(TUN2_IFINDEX, 0) as i32)
}

#[inline]
fn redirect_egress(ctx: TcContext) -> Result<i32, ()> {
    let data = ctx.data() as *mut u8;
    let data_end = ctx.data_end() as *mut u8;

    if data.add(core::mem::size_of::<iphdr>()) > data_end {
        return OK(TC_ACT_OK);
    }

    let iph = &mut *(data as *mut iphdr);

    if iph.version() != 4 {
        return OK(TC_ACT_OK);
    }

    // change source IP
    let old_src = iph.saddr;
    iph.saddr = TUN1_IPADDR;

    // fix IPv4 header checksum
    let _ = bpf_l3_csum_replace(ctx.skb as *mut _, 10, old_src, iph.saddr, 4);

    // fix L4 checksum
    let _ = bpf_l4_csum_replace(ctx.skb as *mut _, 0, old_src, iph.saddr, 4);

    // redirect
    Ok(bpf_redirect(TUN1_IFINDEX, 0) as i32)
}

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
