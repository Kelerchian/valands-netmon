pub mod centrifuge;
pub mod dns_resolver_actor;
pub mod nom_http;
pub mod raw_helper_fns;
pub mod sniffer_actor;
pub mod structs;
use dns_resolver_actor::DNSResolverActor;
use pktparse::ethernet::MacAddress;
use pnet::{
    datalink::{self, NetworkInterface},
    ipnetwork::IpNetwork,
};
use raw_helper_fns::{collect_ip_address_from_message, extract_for_ether, print_raw};
use sniffer_actor::SnifferActor;
use std::{
    collections::{HashSet, VecDeque},
    net::IpAddr,
    sync::{mpsc, Arc, RwLock},
    time::{self, Duration},
    vec,
};
use structs::{ether::Ether, raw::Raw, tcp::TCP, udp::UDP};

use crate::raw_helper_fns::{extract_for_ip_address, extract_for_mac_address, extract_for_port};

#[derive(Debug)]
pub enum Direction {
    Download,
    Upload,
    Loop,
    None,
}

impl Direction {
    pub fn determine(
        ips: &HashSet<IpNetwork>,
        source_ip: &IpAddr,
        destination_ip: &IpAddr,
    ) -> Self {
        let source_is_local = ips.iter().any(|ip_network| ip_network.ip() == *source_ip);
        let destination_is_local = ips
            .iter()
            .any(|ip_network| ip_network.ip() == *destination_ip);

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

#[derive(Debug)]
pub struct Message {
    raw: Raw,
}

fn generate_local_ips_set_from_interfaces(
    network_interfaces: &Vec<NetworkInterface>,
) -> HashSet<IpNetwork> {
    let ips_vec = network_interfaces.iter().fold(
        vec![],
        |mut vec: Vec<IpNetwork>, interface: &NetworkInterface| {
            let mut ips = interface.ips.clone();
            vec.append(&mut ips);
            vec
        },
    );
    HashSet::from_iter(ips_vec)
}

#[derive(PartialEq, Eq, Hash)]
pub enum MessageTableRecordTags {
    Ether,
    Tun,
    Sll,
    Arp,
    IPv4,
    IPv6,
    Cjdns,
    TCP,
    UDP,
    ICMP,
    TLS,
    HTTP,
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

    pub fn append_set_from_tcp(set: &mut HashSet<MessageTableRecordTags>, tcp: &TCP) {
        set.insert(MessageTableRecordTags::TCP);
        match tcp {
            TCP::TLS(_) => {
                set.insert(MessageTableRecordTags::TLS);
            }
            TCP::HTTP(_) => {
                set.insert(MessageTableRecordTags::HTTP);
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

    pub fn append_set_from_udp(set: &mut HashSet<MessageTableRecordTags>, udp: &UDP) {
        set.insert(MessageTableRecordTags::UDP);
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
            Ether::IPv4(_, ipv4) => {
                set.insert(MessageTableRecordTags::IPv4);
                match ipv4 {
                    structs::ipv4::IPv4::TCP(_, tcp) => {
                        MessageTableRecordTags::append_set_from_tcp(set, tcp);
                    }
                    structs::ipv4::IPv4::UDP(_, udp) => {
                        MessageTableRecordTags::append_set_from_udp(set, udp)
                    }
                    structs::ipv4::IPv4::ICMP(_, _) => {
                        set.insert(MessageTableRecordTags::ICMP);
                    }
                    structs::ipv4::IPv4::Unknown(_) => {}
                }
            }
            Ether::IPv6(_, ipv6) => {
                set.insert(MessageTableRecordTags::IPv6);
                match ipv6 {
                    structs::ipv6::IPv6::TCP(_, tcp) => {
                        MessageTableRecordTags::append_set_from_tcp(set, tcp);
                    }
                    structs::ipv6::IPv6::UDP(_, udp) => {
                        MessageTableRecordTags::append_set_from_udp(set, udp)
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

#[derive(Default)]
struct Address {
    mac: Option<MacAddress>,
    ip: Option<IpAddr>,
    port: Option<u16>,
}

struct MessageRecord {
    source: Address,
    dest: Address,
    direction: Direction,
    tags: HashSet<MessageTableRecordTags>,
}

impl MessageRecord {
    pub fn from_raw<'a>(local_ips: &HashSet<IpNetwork>, raw: &Raw) -> MessageRecord {
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

        let (source, dest): (Address, Address) = match addresses_from_raw {
            Some((mac_addresses, ip_addresses, ports)) => (
                Address {
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
                },
                Address {
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
                },
            ),
            None => (Default::default(), Default::default()),
        };

        let direction = match (&source.ip, &dest.ip) {
            (Some(source_ip), Some(destination_ip)) => {
                Direction::determine(local_ips, source_ip, destination_ip)
            }
            _ => Direction::None,
        };

        MessageRecord {
            source,
            dest,
            direction,
            tags: MessageTableRecordTags::create_set_from_raw(raw),
        }
    }
}

struct MessageBuckets {
    /**
     * Used to stash message record in a period of time
     */
    pub bucket: Arc<RwLock<(time::Instant, Vec<MessageRecord>)>>,

    /**
     * (Tuple of Age and Records)
     */
    pub historical_buckets: Arc<RwLock<VecDeque<(time::Instant, Vec<MessageRecord>)>>>,
}

impl MessageBuckets {
    pub fn new() -> MessageBuckets {
        MessageBuckets {
            bucket: Arc::new(RwLock::new((time::Instant::now(), Default::default()))),
            historical_buckets: Default::default(),
        }
    }

    pub fn rotate(&self) -> Result<(), ()> {
        let historical_buckets_rwlock = &*self.historical_buckets;
        match historical_buckets_rwlock.write() {
            Err(_x) => Err(()),
            Ok(mut historical_buckets) => match self.bucket.write() {
                Err(_x) => Err(()),
                Ok(mut current_bucket) => {
                    let old_bucket = {
                        std::mem::replace::<(time::Instant, Vec<MessageRecord>)>(
                            &mut current_bucket,
                            (time::Instant::now(), Default::default()),
                        )
                    };

                    historical_buckets.push_front(old_bucket);

                    Ok(())
                }
            },
        }
    }

    pub fn clean_older_than(&self, oldest_allowed_age: &time::Instant) -> Result<(), ()> {
        let historical_buckets_rwlock = &*self.historical_buckets;
        match historical_buckets_rwlock.write() {
            Err(_) => Err(()),
            Ok(mut historical_buckets) => {
                historical_buckets.retain(|(time, _)| time > oldest_allowed_age);
                Ok(())
            }
        }
    }
}

struct MessageTableRegulator {
    local_ips: HashSet<IpNetwork>,
    rotation_duration: Duration,
    expiry_duration: Duration,
    pub downstream_buckets: Arc<MessageBuckets>,
    pub upstream_buckets: Arc<MessageBuckets>,
}

impl MessageTableRegulator {
    pub fn new(
        rotation_duration: Duration,
        expiry_duration: Duration,
        local_ips: HashSet<IpNetwork>,
    ) -> MessageTableRegulator {
        MessageTableRegulator {
            local_ips,
            rotation_duration,
            expiry_duration,
            downstream_buckets: Arc::new(MessageBuckets::new()),
            upstream_buckets: Arc::new(MessageBuckets::new()),
        }
    }

    pub fn register(&self, raw: &Raw) {
        let message = MessageRecord::from_raw(&self.local_ips, raw);
    }

    fn rotate(&self) -> Result<(), ()> {
        let res_upstream = self.upstream_buckets.rotate();
        let res_downstream = self.downstream_buckets.rotate();
        if res_upstream.is_err() || res_downstream.is_err() {
            Err(())
        } else {
            Ok(())
        }
    }

    fn clean(&self) -> Result<(), ()> {
        let expiry_time = time::Instant::now() - self.expiry_duration;
        let res_upstream = self.upstream_buckets.clean_older_than(&expiry_time);
        let res_downstream = self.downstream_buckets.clean_older_than(&expiry_time);
        if res_upstream.is_err() || res_downstream.is_err() {
            Err(())
        } else {
            Ok(())
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (message_sender, message_receiver) = mpsc::channel::<Raw>();
    let network_interfaces = datalink::interfaces();

    let local_ips_set = generate_local_ips_set_from_interfaces(&network_interfaces);

    let sniffer_actor = SnifferActor::new(&network_interfaces, &message_sender);
    let message_table_regulator = Arc::new(MessageTableRegulator::new(
        Duration::from_millis(100),
        Duration::from_millis(5000),
        local_ips_set.clone(),
    ));
    let dns_resolver: DNSResolverActor = Default::default();
    let dns_resolver_store = Arc::clone(&dns_resolver.store);
    let message_hub_thread = {
        std::thread::Builder::new()
            .name(String::from("message_hub"))
            .spawn(move || loop {
                let message_table_regulator = Arc::clone(&message_table_regulator);
                let message_res = message_receiver.recv_timeout(Duration::from_millis(10));
                if let Ok(message) = message_res {
                    // Process IP Adresses
                    {
                        let detected_ips = collect_ip_address_from_message(&mut vec![], &message);
                        let unregistered_ips: Vec<&IpAddr> = {
                            let dns_resolver_store_read_handle =
                                &dns_resolver_store.read().unwrap();
                            detected_ips
                                .iter()
                                .filter(|ip_address| {
                                    !dns_resolver_store_read_handle.is_registered(ip_address)
                                })
                                .collect()
                        };

                        message_table_regulator.register(&message);

                        if unregistered_ips.len() > 0 {
                            println!("unregistered_ips {:?}", unregistered_ips);
                            let dns_resolver_store_write_handle =
                                &mut dns_resolver_store.write().unwrap();
                            unregistered_ips.iter().for_each(|ip| {
                                dns_resolver_store_write_handle.register_default_if_empty(ip)
                            });
                        }
                    }

                    // Process HTTP
                    {
                        print_raw(&message);
                    }
                }
                std::thread::park_timeout(Duration::from_millis(10));
            })
            .unwrap()
    };

    dns_resolver.join().unwrap();
    sniffer_actor.join().unwrap();
    message_hub_thread.join().unwrap();

    Ok(())
}
