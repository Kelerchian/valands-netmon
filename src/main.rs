pub mod actors;
pub mod centrifuge;
pub mod compatibility;
pub mod message;
pub mod nom_http;
pub mod raw_helper_fns;
pub mod structs;
pub mod ui;

use actors::{dns_resolver_actor::DNSResolverActor, sniffer_actor::SnifferActor, message_table_regulator::MessageTableRegulator};
use message::MessageRecord;
use pktparse::ethernet::MacAddress;
use pnet::datalink::{self, NetworkInterface};
use raw_helper_fns::collect_ip_address_from_message;
use std::{
    collections::{HashSet, VecDeque},
    sync::{mpsc, Arc, RwLock},
    time::{self, Duration},
    vec, net::IpAddr,
};
use structs::raw::Raw;
use ui::run_ui;

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
pub struct MessageBuckets {
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

    run_ui(message_table_regulator, dns_resolver_store);

    rotator.join().unwrap();
    expiror.join().unwrap();
    dns_resolver.join().unwrap();
    sniffer_actor.join().unwrap();
    message_hub_thread.join().unwrap();

    Ok(())
}
