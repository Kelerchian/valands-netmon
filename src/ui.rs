use crate::{
    actors::dns_resolver_actor::DNSResolverStore,
    message::{Direction, MessageRecord, MessageTableRecordTags},
    MessageTableRegulator,
};
use eframe::{egui, epi};
use std::{
    cmp::Ordering,
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

struct Data {
    downstream: Vec<Vec<MessageRecord>>,
    upstream: Vec<Vec<MessageRecord>>,
}

pub struct UIState {
    is_active: Arc<RwLock<bool>>,
    dns_resolver_store: Arc<RwLock<DNSResolverStore>>,
    direction: Arc<RwLock<Direction>>,
    data: Arc<RwLock<Option<Data>>>,
}

impl UIState {
    fn new(dns_resolver_store: &Arc<RwLock<DNSResolverStore>>) -> Self {
        Self {
            dns_resolver_store: Arc::clone(dns_resolver_store),
            is_active: Arc::new(RwLock::new(true)),
            direction: Arc::new(RwLock::new(Direction::Download)),
            data: Default::default(),
        }
    }
}

impl Clone for UIState {
    fn clone(&self) -> Self {
        Self {
            is_active: self.is_active.clone(),
            dns_resolver_store: self.dns_resolver_store.clone(),
            direction: self.direction.clone(),
            data: self.data.clone(),
        }
    }
}

struct AppState {
    state: UIState,
}

impl AppState {
    fn new(dns_resolver_store: &Arc<RwLock<DNSResolverStore>>) -> Self {
        Self {
            state: UIState::new(dns_resolver_store),
        }
    }
}

impl epi::App for AppState {
    fn name(&self) -> &str {
        "Valands Netmon"
    }

    fn update(&mut self, ctx: &egui::CtxRef, frame: &epi::Frame) {
        if let Ok(mut direction) = self.state.direction.write() {
            if let Ok(data) = self.state.data.read() {
                if let Some(data) = &*data {

                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.vertical(|ui| {
                            ui.radio_value(&mut *direction, Direction::Download, "Downstream");
                            ui.radio_value(&mut *direction, Direction::Upload, "Upstream");
                        });
                        egui::Grid::new("thegrid").show(ui, |ui| {
                            let data = {
                                match *direction {
                                    Direction::Upload => &data.upstream,
                                    _ => &data.downstream
                                }
                            };
                            data.iter().for_each(|data| {
                                data.iter().for_each(|data|{
                                    ui.label(format!("dest:{:?}", &data.dest));
                                    ui.label(format!("source:{:?}", &data.source));
                                    ui.label(format!("tags:{:?}", &data.tags));
                                    ui.end_row();
                                });
                            });
                        });
                    });
                }
            }

        }
    }
}

pub fn run_worker(
    ui_state: &UIState,
    message_table_regulator: Arc<MessageTableRegulator>,
    dns_resolver_store: Arc<RwLock<DNSResolverStore>>,
) -> std::thread::JoinHandle<()> {
    let is_active_arc = Arc::clone(&ui_state.is_active);
    let data = Arc::clone(&ui_state.data);
    let dns_resolver_store = Arc::clone(&dns_resolver_store);
    std::thread::Builder::new()
        .name(String::from("UI worker"))
        .spawn(move || loop {
            if {
                let is_active = *is_active_arc.read().unwrap();
                !is_active
            } {
                break;
            };

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

            if let Ok(mut write) = data.write() {
                *write = Some(Data {
                    upstream: upstream_data,
                    downstream: downstream_data,
                });
            }

            std::thread::sleep(Duration::from_millis(1000));
        })
        .unwrap()
}

pub fn run_ui(
    message_table_regulator: Arc<MessageTableRegulator>,
    dns_resolver_store: Arc<RwLock<DNSResolverStore>>,
) {
    let ui_config = UIState::new(&dns_resolver_store);
    let app = AppState {
        state: ui_config.clone(),
    };
    let native_options = eframe::NativeOptions::default();
    let worker_thread = run_worker(&ui_config, message_table_regulator, dns_resolver_store);

    eframe::run_native(Box::new(app), native_options);

    worker_thread.join().unwrap();
}
