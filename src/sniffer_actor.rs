use std::{cell::RefCell, sync::mpsc, time::Duration};

use pnet::datalink::{self, Channel, Config, DataLinkReceiver, NetworkInterface};

use crate::{centrifuge::parse_eth, structs::raw::Raw};

pub struct SnifferActor {
    thread_handles: RefCell<Option<Vec<std::thread::JoinHandle<()>>>>,
}

impl SnifferActor {
    pub fn new(
        network_interfaces: &Vec<NetworkInterface>,
        message_sender_channel: &mpsc::Sender<Raw>,
    ) -> SnifferActor {
        #[cfg(any(target_os = "windows"))]
        fn filter_sniffable_interfaces(interface: &&NetworkInterface) -> bool {
            !interface.ips.is_empty()
        }
        #[cfg(not(target_os = "windows"))]
        fn filter_sniffable_interfaces(interface: &&NetworkInterface) -> bool {
            !interface.ips.is_empty() && interface.is_up()
        }

        SnifferActor {
            thread_handles: RefCell::new(Some(
                network_interfaces
                    .iter()
                    .filter(filter_sniffable_interfaces)
                    .map(|interface| {
                        let interface = interface.clone();
                        let name = format!("sniffer_{}", interface.name);
                        let hub_sender = message_sender_channel.clone();
                        std::thread::Builder::new()
                            .name(name.clone())
                            .spawn(move || {
                                let data_link_sniffer = Sniffer {
                                    hub_sender,
                                    interface,
                                    receiver: RefCell::new(None),
                                };
                                loop {
                                    data_link_sniffer.run();
                                }
                            })
                            .unwrap()
                    })
                    .collect::<Vec<_>>(),
            )),
        }
    }

    pub fn join(&self) -> Result<(), ()> {
        match self.thread_handles.take() {
            Some(vec) => {
                let mut join_results = vec![];
                for join_handle in vec {
                    join_results.push(join_handle.join());
                }

                if join_results.iter().any(|result| result.is_err()) {
                    Err(())
                } else {
                    Ok(())
                }
            }
            None => Ok(()),
        }
    }
}

impl Drop for SnifferActor {
    fn drop(&mut self) {
        self.join().unwrap();
    }
}

pub struct Sniffer {
    pub hub_sender: mpsc::Sender<Raw>,
    pub interface: NetworkInterface,
    pub receiver: RefCell<Option<Box<dyn DataLinkReceiver>>>,
}
impl Sniffer {
    pub fn run(&self) {
        let mut receiver_refcell = self.receiver.borrow_mut();
        match receiver_refcell.as_deref_mut() {
            None => {
                // Attempt inquire channel
                match datalink::channel(
                    &&self.interface,
                    Config {
                        read_timeout: Some(Duration::new(1, 0)),
                        read_buffer_size: 65536,
                        ..Default::default()
                    },
                ) {
                    Ok(Channel::Ethernet(_data_link_sender, data_link_receiver_proto)) => {
                        *receiver_refcell = Some(data_link_receiver_proto);
                        std::thread::park_timeout(std::time::Duration::from_millis(10));
                    }
                    _ => {
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                    }
                }
            }
            Some(datalink_receiver) => {
                match datalink_receiver.next() {
                    // If next yield bytes, read
                    Ok(bytes) => {
                        match parse_eth(bytes) {
                            Err(x) => {}
                            Ok(raw) => {
                                let mut attempt_remaining = 10;
                                loop {
                                    if attempt_remaining == 0 {
                                        break;
                                    }
                                    match self.hub_sender.send(raw.clone()) {
                                        Ok(_) => break,
                                        Err(_) => {
                                            attempt_remaining -= 1;
                                            std::thread::park_timeout(Duration::from_millis(5));
                                        }
                                    }
                                }
                            }
                        };
                    }
                    // If next fails
                    Err(err) => {
                        match err.kind() {
                            std::io::ErrorKind::TimedOut => {
                                std::thread::park_timeout(Duration::from_millis(10));
                            }
                            _ => {
                                // Sleep and unset data_link_receive because of timeout
                                std::thread::park_timeout(Duration::from_millis(1000));
                                *receiver_refcell = None;
                            }
                        }
                    }
                };
            }
        }
    }
}
