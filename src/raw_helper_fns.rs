use std::net::IpAddr;

use pktparse::{
    ethernet::{EthernetFrame, MacAddress},
    ipv4::IPv4Header,
    ipv6::IPv6Header,
    tcp::TcpHeader,
    udp::UdpHeader,
};

use crate::structs::{
    self,
    ether::Ether,
    ipv4::IPv4,
    ipv6::IPv6,
    raw::Raw,
    tcp::{self, TCP},
    udp::UDP,
};

pub fn collect_ip_address_from_ether(ips: &mut Vec<IpAddr>, ether: &Ether) {
    use structs::arp::ARP;
    match ether {
        Ether::Arp(arp) => match arp {
            ARP::Request(arp_packet) => {
                ips.push(IpAddr::V4(arp_packet.dest_addr));
                ips.push(IpAddr::V4(arp_packet.src_addr));
            }
            ARP::Reply(arp_packet) => {
                ips.push(IpAddr::V4(arp_packet.dest_addr));
                ips.push(IpAddr::V4(arp_packet.src_addr));
            }
        },
        Ether::IPv4(header, _) => {
            ips.push(IpAddr::V4(header.source_addr));
            ips.push(IpAddr::V4(header.dest_addr));
        }
        Ether::IPv6(header, _) => {
            ips.push(IpAddr::V6(header.source_addr));
            ips.push(IpAddr::V6(header.dest_addr));
        }
        Ether::Cjdns(cjdns_eth_pkt) => {}
        Ether::Unknown(_) => {}
    }
}

pub fn collect_ip_address_from_message(ips: &mut Vec<IpAddr>, message: &Raw) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = vec![];
    match message {
        Raw::Ether(_, ether) => collect_ip_address_from_ether(&mut ips, &ether),
        Raw::Tun(tun) => collect_ip_address_from_ether(&mut ips, &tun),
        Raw::Sll(sll) => collect_ip_address_from_ether(&mut ips, &sll),
        Raw::Unknown(_) => {}
    };
    ips
}

pub fn print_udp(prefix: &str, udp: &UDP) {
    match &udp {
        structs::udp::UDP::DHCP(dhcp) => match dhcp {
            structs::dhcp::DHCP::ACK(payload) => {
                println!("{}:udp:dhcp:ACK {:?}", prefix, payload)
            }
            structs::dhcp::DHCP::DECLINE(payload) => {
                println!("{}:udp:dhcp:DECLINE {:?}", prefix, payload)
            }
            structs::dhcp::DHCP::DISCOVER(payload) => {
                println!("{}:udp:dhcp:DISCOVER {:?}", prefix, payload)
            }
            structs::dhcp::DHCP::INFORM(payload) => {
                println!("{}:udp:dhcp:INFORM {:?}", prefix, payload)
            }
            structs::dhcp::DHCP::NAK(payload) => {
                println!("{}:udp:dhcp:NAK {:?}", prefix, payload)
            }
            structs::dhcp::DHCP::OFFER(payload) => {
                println!("{}:udp:dhcp:OFFER {:?}", prefix, payload)
            }
            structs::dhcp::DHCP::RELEASE(payload) => {
                println!("{}:udp:dhcp:RELEASE {:?}", prefix, payload)
            }
            structs::dhcp::DHCP::REQUEST(payload) => {
                println!("{}:udp:dhcp:REQUEST {:?}", prefix, payload)
            }
            structs::dhcp::DHCP::UNKNOWN(payload) => {
                println!("{}:udp:dhcp:UNKNOWN {:?}", prefix, payload)
            }
        },
        structs::udp::UDP::DNS(dns) => match dns {
            structs::dns::DNS::Request(r) => {
                println!("{}:udp:dns:Request {:?}", prefix, r)
            }
            structs::dns::DNS::Response(r) => {
                println!("{}:udp:dns:Response {:?}", prefix, r)
            }
        },
        structs::udp::UDP::SSDP(ssdp) => match ssdp {
            structs::ssdp::SSDP::Discover(discover) => {
                println!("{}:udp:Discover {:?}", prefix, discover)
            }
            structs::ssdp::SSDP::Notify(notify) => {
                println!("{}:udp:Notify {:?}", prefix, notify)
            }
            structs::ssdp::SSDP::BTSearch(btsearch) => {
                println!("{}:udp:BTSearch {:?}", prefix, btsearch)
            }
        },
        structs::udp::UDP::Dropbox(dropbox) => {
            println!("{}:udp:Dropbox {:?}", prefix, dropbox)
        }
        structs::udp::UDP::Text(text) => {
            println!("{}:udp:text {:?}", prefix, {
                if text.len() < 100 {
                    format!("payload:{:?}", text)
                } else {
                    format!("too_long:len:{:?}", text.len())
                }
            });
        }
        structs::udp::UDP::Binary(binary) => {
            println!("{}:udp:binary {:?}", prefix, binary.len());
        }
    }
}

pub fn print_tcp(prefix: &str, tcp: &TCP) {
    match &tcp {
        structs::tcp::TCP::TLS(tls) => {
            println!("{}:tcp:tls {:?}", prefix, tls);
        }
        structs::tcp::TCP::HTTP(http) => {
            println!("{}:tcp:http {:?}", prefix, http);
        }
        structs::tcp::TCP::Text(text) => {
            println!("{}:tcp:text {:?}", prefix, {
                if text.len() < 100 {
                    format!("payload:{:?}", text)
                } else {
                    format!("too_long:len:{:?}", text.len())
                }
            });
        }
        structs::tcp::TCP::Binary(binary) => {
            println!("{}:tcp:binary {:?}", prefix, binary.len());
        }
        structs::tcp::TCP::Empty => {}
    }
}

pub fn print_ether(ether: &Ether) {
    match ether {
        Ether::Arp(arp) => match arp {
            structs::arp::ARP::Request(req) => {
                println!("arp::req {:?}", req)
            }
            structs::arp::ARP::Reply(reply) => {
                println!("arp::reply {:?}", reply)
            }
        },
        Ether::IPv4(_, ip) => match ip {
            structs::ipv4::IPv4::TCP(tcp_header, tcp) => {
                println!("tcp_header: {:?}", tcp_header);
                print_tcp("ipv4".into(), tcp)
            }
            structs::ipv4::IPv4::UDP(udp_header, udp) => {
                println!("udp_header: {:?}", udp_header);
                print_udp("ipv4", udp)
            }
            structs::ipv4::IPv4::ICMP(icmp_header, icmp) => {
                println!("icmp_header: {:?}", icmp_header);
                println!("ipv4:icmp: {:?}", icmp);
            }
            structs::ipv4::IPv4::Unknown(_) => {}
        },
        Ether::IPv6(_, ip) => match ip {
            structs::ipv6::IPv6::TCP(tcp_header, tcp) => {
                println!("tcp_header: {:?}", tcp_header);
                print_tcp("ipv6".into(), tcp);
            }
            structs::ipv6::IPv6::UDP(udp_header, udp) => {
                println!("udp_header: {:?}", udp_header);
                print_udp("ipv4", udp);
            }
            structs::ipv6::IPv6::Unknown(_) => {}
        },
        Ether::Cjdns(cjdns) => println!("cjdns {:?}", cjdns),
        Ether::Unknown(_) => {}
    }
}

pub fn print_raw(raw: &Raw) {
    match raw {
        Raw::Ether(ether_frame, ether) => print_ether(ether),
        Raw::Tun(ether) => print_ether(ether),
        Raw::Sll(ether) => print_ether(ether),
        Raw::Unknown(_) => {}
    }
}

pub fn extract_for_ether(raw: &Raw) -> Option<(Option<&EthernetFrame>, &Ether)> {
    match raw {
        Raw::Ether(ether_frame, ether) => Some((Some(ether_frame), ether)),
        Raw::Tun(ether) | Raw::Sll(ether) => Some((None, ether)),
        _ => None,
    }
}

pub fn extract_for_tcp(ether: &Ether) -> Option<(&TcpHeader, &TCP)> {
    match ether {
        Ether::IPv4(_, payload) => match payload {
            IPv4::TCP(tcp_header, tcp) => Some((tcp_header, tcp)),
            _ => None,
        },
        Ether::IPv6(_, payload) => match payload {
            IPv6::TCP(tcp_header, tcp) => Some((tcp_header, tcp)),
            _ => None,
        },
        _ => None,
    }
}

pub fn extract_for_udp(ether: &Ether) -> Option<(&UdpHeader, &UDP)> {
    match ether {
        Ether::IPv4(_, payload) => match payload {
            IPv4::UDP(udp_header, udp) => Some((udp_header, udp)),
            _ => None,
        },
        Ether::IPv6(_, payload) => match payload {
            IPv6::UDP(udp_header, udp) => Some((udp_header, udp)),
            _ => None,
        },
        _ => None,
    }
}

pub fn extract_for_mac_address(ether_frame: &EthernetFrame) -> Option<(MacAddress, MacAddress)> {
    Some((ether_frame.source_mac, ether_frame.dest_mac))
}

pub fn extract_for_ip_address(ether: &Ether) -> Option<(IpAddr, IpAddr)> {
    match ether {
        Ether::IPv4(header, _) => Some((header.source_addr.into(), header.dest_addr.into())),
        Ether::IPv6(header, _) => Some((header.source_addr.into(), header.dest_addr.into())),
        _ => None,
    }
}

pub fn extract_for_port(ether: &Ether) -> Option<(u16, u16)> {
    if let Some((udp_header, udp)) = extract_for_udp(ether) {
        return Some((udp_header.source_port, udp_header.dest_port));
    }
    if let Some((tcp_header, tcp)) = extract_for_tcp(ether) {
        return Some((tcp_header.source_port, tcp_header.dest_port));
    }
    None
}
