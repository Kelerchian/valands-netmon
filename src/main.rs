pub mod centrifuge;
pub mod compatibility;
pub mod dns_resolver_actor;
pub mod nom_http;
pub mod raw_helper_fns;
pub mod sniffer_actor;
pub mod structs;
use dns_resolver_actor::DNSResolverActor;
use pktparse::ethernet::MacAddress;
use pnet::datalink::{self, NetworkInterface};
use raw_helper_fns::{collect_ip_address_from_message, extract_for_ether, print_raw};
use sniffer_actor::SnifferActor;
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    sync::{mpsc, Arc, RwLock},
    time::{self, Duration},
    vec,
};
use structs::{ether::Ether, raw::Raw, tcp::TCP, udp::UDP};

use crate::raw_helper_fns::{extract_for_ip_address, extract_for_mac_address, extract_for_port};

#[derive(Default, Clone)]
pub struct CompositeAddress {
    mac: Option<MacAddress>,
    ip: Option<IpAddr>,
    port: Option<u16>,
}

#[derive(Debug, Clone)]
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
                (_, (Some(mac))) => local_macs.iter().any(|local_mac| local_mac == mac),
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

#[derive(Debug)]
pub struct Message {
    raw: Raw,
}

fn generate_local_ips_set_from_interfaces(
    network_interfaces: &Vec<NetworkInterface>,
) -> HashSet<IpAddr> {
    HashSet::from_iter(network_interfaces.iter().fold(
        vec![],
        |mut vec: Vec<IpAddr>, interface: &NetworkInterface| {
            let mut ips = interface
                .ips
                .iter()
                .map(|ip_network| -> IpAddr { ip_network.ip() })
                .collect();
            vec.append(&mut ips);
            vec
        },
    ))
}

fn generate_local_macs_set_from_interfaces(
    network_interfaces: &Vec<NetworkInterface>,
) -> Vec<MacAddress> {
    network_interfaces.iter().fold(
        vec![],
        |mut vec: Vec<MacAddress>, interface: &NetworkInterface| {
            if let Some(mac) = interface.mac {
                vec.push(compatibility::mac_addr_to_mac_address(&mac));
            }
            vec
        },
    )
}

#[derive(PartialEq, Eq, Hash, Clone)]
pub enum MessageTableRecordTags {
    Ether,
    Tun,
    Sll,
    Arp,
    IPv4(u16),
    IPv6(u16),
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
            Ether::IPv4(header, ipv4) => {
                set.insert(MessageTableRecordTags::IPv4(header.length));
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
            Ether::IPv6(header, ipv6) => {
                set.insert(MessageTableRecordTags::IPv6(header.length));
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

#[derive(Clone)]
struct MessageRecord {
    source: CompositeAddress,
    dest: CompositeAddress,
    direction: Direction,
    tags: HashSet<MessageTableRecordTags>,
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

    pub fn register(&self, message_record: MessageRecord) -> Result<(), ()> {
        let bucket_rwlock = &*self.bucket;
        match bucket_rwlock.write() {
            Ok(mut current_bucket) => {
                current_bucket.1.push(message_record);
                Ok(())
            }
            Err(err) => Err(()),
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
    local_ips: HashSet<IpAddr>,
    local_macs: Vec<MacAddress>,
    local_network_interfaces: Vec<NetworkInterface>,
    rotation_duration: Duration,
    expiry_duration: Duration,
    pub downstream_buckets: Arc<MessageBuckets>,
    pub upstream_buckets: Arc<MessageBuckets>,
}

impl MessageTableRegulator {
    pub fn new(
        rotation_duration: Duration,
        expiry_duration: Duration,
        local_network_interfaces: Vec<NetworkInterface>,
    ) -> MessageTableRegulator {
        let local_macs = generate_local_macs_set_from_interfaces(&local_network_interfaces);

        let mut regulator = MessageTableRegulator {
            local_ips: generate_local_ips_set_from_interfaces(&local_network_interfaces),
            local_macs,
            local_network_interfaces,
            rotation_duration,
            expiry_duration,
            downstream_buckets: Arc::new(MessageBuckets::new()),
            upstream_buckets: Arc::new(MessageBuckets::new()),
        };

        regulator
    }

    pub fn create_runner(
        self_arc: &Arc<MessageTableRegulator>,
    ) -> (std::thread::JoinHandle<()>, std::thread::JoinHandle<()>) {
        let rotation_duration = self_arc.rotation_duration;
        let expiry_duration = self_arc.expiry_duration;
        let rotator_clone = Arc::clone(self_arc);
        let expiror_clone = Arc::clone(self_arc);

        let rotator_thread_handle = std::thread::Builder::new()
            .name("MessageBucketRotator".into())
            .spawn(move || loop {
                rotator_clone.rotate().unwrap();
                std::thread::sleep(rotation_duration);
            })
            .unwrap();
        let expiror_thread_handle = std::thread::Builder::new()
            .name("MessageBucketExpiror".into())
            .spawn(move || loop {
                expiror_clone.expire().unwrap();
                std::thread::sleep(expiry_duration);
            })
            .unwrap();

        (rotator_thread_handle, expiror_thread_handle)
    }

    pub fn register(&self, raw: &Raw) -> Result<(), ()> {
        let message_record = MessageRecord::from_raw(&self.local_macs, &self.local_ips, raw);
        match &message_record.direction {
            &Direction::Download => {
                let bucket = &(*self.downstream_buckets);
                bucket.register(message_record)
            }
            &Direction::Upload => {
                let bucket = &(*self.upstream_buckets);
                bucket.register(message_record)
            }
            _ => Ok(()),
        }
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

    fn expire(&self) -> Result<(), ()> {
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
    let local_network_interfaces = datalink::interfaces();

    let sniffer_actor = SnifferActor::new(&local_network_interfaces, &message_sender);
    let message_table_regulator = Arc::new(MessageTableRegulator::new(
        Duration::from_millis(100),
        Duration::from_millis(5000),
        local_network_interfaces.clone(),
    ));
    let dns_resolver: DNSResolverActor = Default::default();
    let message_hub_thread = {
        let dns_resolver_store = Arc::clone(&dns_resolver.store);
        let message_table_regulator = Arc::clone(&message_table_regulator);
        std::thread::Builder::new()
            .name(String::from("message_hub"))
            .spawn(move || loop {
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

                        if unregistered_ips.len() > 0 {
                            // println!("unregistered_ips {:?}", unregistered_ips);
                            let dns_resolver_store_write_handle =
                                &mut dns_resolver_store.write().unwrap();
                            unregistered_ips.iter().for_each(|ip| {
                                dns_resolver_store_write_handle.register_default_if_empty(ip)
                            });
                        }
                    }

                    message_table_regulator.register(&message).unwrap();

                    // Process HTTP
                    // {
                    //     print_raw(&message);
                    // }
                }
                std::thread::park_timeout(Duration::from_millis(10));
            })
            .unwrap()
    };

    let (rotator, expiror) = MessageTableRegulator::create_runner(&message_table_regulator);
    let dns_resolver_store = Arc::clone(&dns_resolver.store);

    loop {
        for _ in [1..10] {
            println!("");
        }
        let downstream_data = {
            let downstream_read = &message_table_regulator
                .downstream_buckets
                .historical_buckets
                .read()
                .unwrap();
            downstream_read.iter().fold::<Vec<Vec<MessageRecord>>, _>(
                vec![],
                |mut accumulator, item| {
                    let vec_ref = item.1.clone();
                    accumulator.push(vec_ref);
                    accumulator
                },
            )
        };

        let mut ip_payload_map = downstream_data.iter().fold(
            HashMap::<&IpAddr, u16>::new(),
            |mut ip_payload_map, vec| {
                vec.iter().for_each(|item| match &item.source.ip {
                    Some(ip) => {
                        ip_payload_map.insert(ip, {
                            let mut sum: u16 = match ip_payload_map.get(ip) {
                                Some(val) => *val,
                                None => 0_u16.into(),
                            };
                            sum += item.tags.iter().fold(0, |sum, tag| match tag {
                                MessageTableRecordTags::IPv4(header_length) => *header_length,
                                MessageTableRecordTags::IPv6(header_length) => *header_length,
                                _ => 0,
                            });
                            sum
                        });
                    }
                    None => {}
                });
                ip_payload_map
            },
        );

        let mut ip_payload_vec: Vec<_> = ip_payload_map.into_iter().collect();
        ip_payload_vec.sort_by(|(ip_a, size_a), (ip_b, size_b)| match true {
            _ if size_a < size_b => Ordering::Greater,
            _ if size_a > size_b => Ordering::Less,
            _ => match true {
                _ if ip_a < ip_b => Ordering::Greater,
                _ if ip_a > ip_b => Ordering::Less,
                _ => Ordering::Equal,
            },
        });

        let dns_resolver_store = dns_resolver_store.read().unwrap();

        ip_payload_vec.iter().for_each(|(ip, size)| {
            let default: &String = &String::from("unknown");
            let name: &String = match dns_resolver_store.get(ip) {
                Some(name) => name,
                None => default,
            };
            println!("{} ({}): {}", ip, name, size);
        });

        std::thread::sleep(Duration::from_millis(1000));
    }

    rotator.join().unwrap();
    expiror.join().unwrap();
    dns_resolver.join().unwrap();
    sniffer_actor.join().unwrap();
    message_hub_thread.join().unwrap();

    Ok(())
}
