pub mod actors;
pub mod centrifuge;
pub mod compatibility;
pub mod message;
pub mod nom_http;
pub mod raw_helper_fns;
pub mod structs;
pub mod ui;

use actors::{dns_resolver_actor::DNSResolverActor, sniffer_actor::SnifferActor};
use conrod::{
    backend::glium::glium::{self},
    glium::Surface,
    widget::{self, collapsible_area::Ids},
    widget_ids, Colorable, Positionable, Widget,
};
use message::{Direction, MessageRecord, MessageTableRecordTags};
use pktparse::ethernet::MacAddress;
use pnet::datalink::{self, NetworkInterface};
use raw_helper_fns::collect_ip_address_from_message;
use ui::run_ui;
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet, VecDeque},
    ffi::OsString,
    net::IpAddr,
    sync::{mpsc, Arc, RwLock},
    time::{self, Duration},
    vec,
};
use structs::raw::Raw;

// #[derive(Debug)]
// pub struct Message {
//     raw: Raw,
// }

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

pub struct EventLoop {
    ui_needs_update: bool,
    last_update: std::time::Instant,
}

impl EventLoop {
    pub fn new() -> Self {
        EventLoop {
            last_update: std::time::Instant::now(),
            ui_needs_update: true,
        }
    }

    /// Produce an iterator yielding all available events.
    pub fn next(
        &mut self,
        events_loop: &mut glium::glutin::EventsLoop,
    ) -> Vec<glium::glutin::Event> {
        // We don't want to loop any faster than 60 FPS, so wait until it has been at least 16ms
        // since the last yield.
        let last_update = self.last_update;
        let sixteen_ms = std::time::Duration::from_millis(16);
        let duration_since_last_update = std::time::Instant::now().duration_since(last_update);
        if duration_since_last_update < sixteen_ms {
            std::thread::sleep(sixteen_ms - duration_since_last_update);
        }

        // Collect all pending events.
        let mut events = Vec::new();
        events_loop.poll_events(|event| events.push(event));

        // If there are no events and the UI does not need updating, wait
        // for the next event.
        if events.is_empty() && !self.ui_needs_update {
            events_loop.run_forever(|event| {
                events.push(event);
                glium::glutin::ControlFlow::Break
            });
        }

        self.ui_needs_update = false;
        self.last_update = std::time::Instant::now();

        events
    }

    /// Notifies the event loop that the `Ui` requires another update whether
    /// or not there are any pending events.
    ///
    /// This is primarily used on the occasion that some part of the UI is
    /// still animating and requires further updates to do so.
    pub fn needs_update(&mut self) {
        self.ui_needs_update = true;
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
    run_ui();

    {
        loop {
            for _ in [1..10] {
                println!("");
            }
            let upstream_data = {
                let upstream_read = &message_table_regulator
                    .upstream_buckets
                    .historical_buckets
                    .read()
                    .unwrap();
                upstream_read.iter().fold::<Vec<Vec<MessageRecord>>, _>(
                    vec![],
                    |mut accumulator, item| {
                        let vec_ref = item.1.clone();
                        accumulator.push(vec_ref);
                        accumulator
                    },
                )
            };

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
                HashMap::<&IpAddr, u64>::new(),
                |mut ip_payload_map, vec| {
                    vec.iter().for_each(|item| match &item.source.ip {
                        Some(ip) => {
                            ip_payload_map.insert(ip, {
                                let mut sum: u64 = match ip_payload_map.get(ip) {
                                    Some(val) => *val,
                                    None => 0_u16.into(),
                                };
                                let current: u64 = item.tags.iter().fold(0, |sum, tag| match tag {
                                    MessageTableRecordTags::IPv4(header_length) => *header_length,
                                    MessageTableRecordTags::IPv6(header_length) => *header_length,
                                    _ => 0,
                                }) as u64;

                                sum += current;
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
    }


    rotator.join().unwrap();
    expiror.join().unwrap();
    dns_resolver.join().unwrap();
    sniffer_actor.join().unwrap();
    message_hub_thread.join().unwrap();

    Ok(())
}
