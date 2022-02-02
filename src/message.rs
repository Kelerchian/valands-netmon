use crate::raw_helper_fns::{
    extract_for_ether, extract_for_ip_address, extract_for_mac_address, extract_for_port,
};
use crate::structs::{self, ether::Ether, raw::Raw, tcp::TCP, udp::UDP};
use pktparse::{ethernet::MacAddress, tcp::TcpHeader, udp::UdpHeader};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
};

#[derive(Default, Clone, Debug)]
pub struct CompositeAddress {
    pub mac: Option<MacAddress>,
    pub ip: Option<IpAddr>,
    pub port: Option<u16>,
    pub socket_address: Option<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Direction {
    Download,
    Upload,
    Loop,
    None,
}

impl Direction {
    pub fn determine(
        local_macs: &Vec<MacAddress>,
        local_ips: &HashSet<IpAddr>,
        source_address: &CompositeAddress,
        destination_address: &CompositeAddress,
    ) -> Self {
        // TODO: make mac_address hashable
        let source_is_local: bool = {
            match (&source_address.ip, &source_address.mac) {
                (Some(ip), _) => local_ips.contains(ip),
                (_, (Some(mac))) => local_macs.iter().any(|local_mac| local_mac == mac),
                _ => false,
            }
        };

        let destination_is_local: bool = {
            match (&destination_address.ip, &destination_address.mac) {
                (Some(ip), _) => local_ips.contains(ip),
                (_, Some(mac)) => local_macs.iter().any(|local_mac| local_mac == mac),
                _ => false,
            }
        };

        if source_is_local && destination_is_local {
            return Direction::Loop;
        }
        if source_is_local {
            return Direction::Upload;
        }
        if destination_is_local {
            return Direction::Download;
        }

        Direction::None
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum MessageTableRecordTags {
    Ether,
    Tun,
    Sll,
    Arp,
    IPv4(u16),
    IPv6(u16),
    Cjdns,
    TCP { dest_port: u16, source_port: u16 },
    UDP { dest_port: u16, source_port: u16 },
    ICMP,
    TLS,
    HTTP { uri: String, host: Option<String> },
    Text,
    Binary,
    DHCP,
    DNS,
    SSDP,
    Dropbox,
}

impl MessageTableRecordTags {
    pub fn append_set_from_binary(set: &mut HashSet<MessageTableRecordTags>, _binary: &Vec<u8>) {
        set.insert(MessageTableRecordTags::Binary);
    }

    pub fn append_set_from_text(set: &mut HashSet<MessageTableRecordTags>, _text: &String) {
        set.insert(MessageTableRecordTags::Text);
    }

    pub fn append_set_from_tcp(
        set: &mut HashSet<MessageTableRecordTags>,
        tcp_header: &TcpHeader,
        tcp: &TCP,
    ) {
        let source_port = tcp_header.source_port;
        let dest_port = tcp_header.dest_port;
        set.insert(MessageTableRecordTags::TCP {
            dest_port,
            source_port,
        });
        match tcp {
            TCP::TLS(_) => {
                set.insert(MessageTableRecordTags::TLS);
            }
            TCP::HTTP(req) => {
                set.insert(MessageTableRecordTags::HTTP { uri: req.uri.clone(), host: req.host.clone() });
            }
            TCP::Text(text) => {
                MessageTableRecordTags::append_set_from_text(set, text);
            }
            TCP::Binary(binary) => {
                MessageTableRecordTags::append_set_from_binary(set, binary);
            }
            TCP::Empty => {}
        }
    }

    pub fn append_set_from_udp(
        set: &mut HashSet<MessageTableRecordTags>,
        udp_header: &UdpHeader,
        udp: &UDP,
    ) {
        let source_port = udp_header.source_port;
        let dest_port = udp_header.dest_port;
        set.insert(MessageTableRecordTags::UDP {
            source_port,
            dest_port,
        });
        match udp {
            UDP::DHCP(_) => {
                set.insert(MessageTableRecordTags::DHCP);
            }
            UDP::DNS(_) => {
                set.insert(MessageTableRecordTags::DNS);
            }
            UDP::SSDP(_) => {
                set.insert(MessageTableRecordTags::SSDP);
            }
            UDP::Dropbox(_) => {
                set.insert(MessageTableRecordTags::Dropbox);
            }
            UDP::Text(text) => {
                MessageTableRecordTags::append_set_from_text(set, text);
            }
            UDP::Binary(binary) => {
                MessageTableRecordTags::append_set_from_binary(set, binary);
            }
        }
    }

    pub fn append_set_from_ether(set: &mut HashSet<MessageTableRecordTags>, ether: &Ether) {
        set.insert(MessageTableRecordTags::Ether);
        match ether {
            Ether::Arp(arp) => {
                set.insert(MessageTableRecordTags::Arp);
            }
            Ether::IPv4(header, ipv4) => {
                set.insert(MessageTableRecordTags::IPv4(header.length));
                match ipv4 {
                    structs::ipv4::IPv4::TCP(tcp_header, tcp) => {
                        MessageTableRecordTags::append_set_from_tcp(set, tcp_header, tcp);
                    }
                    structs::ipv4::IPv4::UDP(udp_header, udp) => {
                        MessageTableRecordTags::append_set_from_udp(set, udp_header, udp)
                    }
                    structs::ipv4::IPv4::ICMP(_, _) => {
                        set.insert(MessageTableRecordTags::ICMP);
                    }
                    structs::ipv4::IPv4::Unknown(_) => {}
                }
            }
            Ether::IPv6(header, ipv6) => {
                set.insert(MessageTableRecordTags::IPv6(header.length));
                match ipv6 {
                    structs::ipv6::IPv6::TCP(tcp_header, tcp) => {
                        MessageTableRecordTags::append_set_from_tcp(set, tcp_header, tcp);
                    }
                    structs::ipv6::IPv6::UDP(udp_header, udp) => {
                        MessageTableRecordTags::append_set_from_udp(set, udp_header, udp)
                    }
                    structs::ipv6::IPv6::Unknown(_) => {}
                }
            }
            Ether::Cjdns(_) => {
                set.insert(MessageTableRecordTags::Cjdns);
            }
            Ether::Unknown(_) => {}
        };
    }
    pub fn append_set_from_raw(set: &mut HashSet<MessageTableRecordTags>, raw: &Raw) {
        match raw {
            Raw::Ether(_, ether) => MessageTableRecordTags::append_set_from_ether(set, ether),
            Raw::Tun(ether) => MessageTableRecordTags::append_set_from_ether(set, ether),
            Raw::Sll(ether) => MessageTableRecordTags::append_set_from_ether(set, ether),
            Raw::Unknown(_) => {}
        };
    }
    pub fn create_set_from_raw(raw: &Raw) -> HashSet<MessageTableRecordTags> {
        let mut set: HashSet<MessageTableRecordTags> = Default::default();
        MessageTableRecordTags::append_set_from_raw(&mut set, raw);
        set
    }
}

#[derive(Clone)]
pub struct MessageRecord {
    pub source: CompositeAddress,
    pub dest: CompositeAddress,
    pub direction: Direction,
    pub tags: HashSet<MessageTableRecordTags>,
}

impl MessageRecord {
    pub fn from_raw<'a>(
        local_macs: &Vec<MacAddress>,
        local_ips: &HashSet<IpAddr>,
        raw: &Raw,
    ) -> MessageRecord {
        let ether = extract_for_ether(&raw);

        let addresses_from_raw = match &ether {
            Some((ether_frame, ether)) => Some((
                if let Some(ether_frame) = ether_frame {
                    extract_for_mac_address(ether_frame)
                } else {
                    None
                },
                extract_for_ip_address(ether),
                extract_for_port(ether),
            )),
            None => None,
        };

        let (source, dest): (CompositeAddress, CompositeAddress) = match addresses_from_raw {
            Some((mac_addresses, ip_addresses, ports)) => (
                CompositeAddress {
                    mac: match mac_addresses {
                        Some((source, _)) => Some(source),
                        None => None,
                    },
                    ip: match ip_addresses {
                        Some((source, _)) => Some(source),
                        None => None,
                    },
                    port: match ports {
                        Some((source, _)) => Some(source),
                        None => None,
                    },
                    socket_address: match (ip_addresses, ports) {
                        (Some((source_ip, _)), Some((source_port, _))) => {
                            Some(SocketAddr::new(source_ip, source_port))
                        }
                        _ => None,
                    },
                },
                CompositeAddress {
                    mac: match mac_addresses {
                        Some((_, dest)) => Some(dest),
                        None => None,
                    },
                    ip: match ip_addresses {
                        Some((_, dest)) => Some(dest),
                        None => None,
                    },
                    port: match ports {
                        Some((_, dest)) => Some(dest),
                        None => None,
                    },
                    socket_address: match (ip_addresses, ports) {
                        (Some((_, dest_ip)), Some((_, dest_port))) => {
                            Some(SocketAddr::new(dest_ip, dest_port))
                        }
                        _ => None,
                    },
                },
            ),
            None => (Default::default(), Default::default()),
        };

        let direction = Direction::determine(local_macs, local_ips, &source, &dest);

        MessageRecord {
            source,
            dest,
            direction,
            tags: MessageTableRecordTags::create_set_from_raw(raw),
        }
    }
}
