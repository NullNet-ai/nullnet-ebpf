#![no_std]
#![feature(trivial_bounds)]

use core::mem;

use network_types::{
    arp::ArpHdr, eth::EthHdr, icmp::Icmp, ip::IpHdr, sctp::SctpHdr, tcp::TcpHdr, udp::UdpHdr,
};

pub static TUN0_IPADDR: u32 = u32::from_be_bytes([10, 0, 0, 1]);
pub static TUN1_IPADDR: u32 = u32::from_be_bytes([10, 0, 1, 1]);

pub static TUN0_NAME: &'static str = "tun0";
pub static ETHINTF_NAME: &'static str = "ens18";

#[derive(Clone)]
#[repr(C)]
pub struct RawData {
    pub frame: RawFrame,
    pub pid: Option<u32>,
}

impl RawData {
    pub const LEN: usize = mem::size_of::<RawData>();
}

impl From<[u8; RawData::LEN]> for RawData {
    fn from(value: [u8; RawData::LEN]) -> Self {
        unsafe { core::mem::transmute::<[u8; RawData::LEN], Self>(value) }
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct RawFrame {
    pub header: EthHdr,
    pub payload: RawPacket,
}

impl RawFrame {
    pub const LEN: usize = mem::size_of::<RawFrame>();
}

#[repr(C)]
pub enum RawPacket {
    Ip(IpHdr, ProtoHdr),
    Arp(ArpHdr),
}

impl Clone for RawPacket {
    fn clone(&self) -> Self {
        match self {
            Self::Ip(ip_hdr, proto_hdr) => match ip_hdr {
                IpHdr::V4(ipv4_hdr) => Self::Ip(IpHdr::V4(*ipv4_hdr), *proto_hdr),
                IpHdr::V6(ipv6_hdr) => Self::Ip(IpHdr::V6(*ipv6_hdr), *proto_hdr),
            },
            Self::Arp(arp_hdr) => Self::Arp(*arp_hdr),
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub enum ProtoHdr {
    Tcp(TcpHdr),
    Udp(UdpHdr),
    Sctp(SctpHdr),
    Icmp(Icmp),
}
