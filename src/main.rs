use core::time;
use pnet::{
    datalink::{self, Channel, Config, DataLinkReceiver, NetworkInterface},
    ipnetwork::IpNetwork,
    packet::{self, Packet},
};
use std::{cell::RefCell, collections::HashSet, net::IpAddr, sync::mpsc, time::Duration};

#[cfg(any(target_os = "windows"))]
fn filter_sniffable_interfaces(interface: &&NetworkInterface) -> bool {
    !interface.ips.is_empty()
}
#[cfg(not(target_os = "windows"))]
fn filter_sniffable_interfaces(interface: &&NetworkInterface) -> bool {
    !interface.ips.is_empty() && interface.is_up()
}

#[derive(Debug)]
pub enum Direction {
    Download,
    Upload,
    Loop,
    None,
}

impl Direction {
    pub fn determine(ips: &HashSet<IpNetwork>, source_ip: IpAddr, destination_ip: IpAddr) -> Self {
        let source_is_local = ips.iter().any(|ip_network| ip_network.ip() == source_ip);
        let destination_is_local = ips
            .iter()
            .any(|ip_network| ip_network.ip() == destination_ip);
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
    ether_type: packet::ethernet::EtherType,
    direction: Direction,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    size: usize,
}

struct Sniffer {
    bucket_sender: mpsc::Sender<Message>,
    ips_set: HashSet<IpNetwork>,
    interface: NetworkInterface,
    receiver: RefCell<Option<Box<dyn DataLinkReceiver>>>,
}
impl Sniffer {
    fn handle_ethernet_packet(&self, ethernet_packet: &packet::ethernet::EthernetPacket) {
        use packet::ethernet::EtherTypes;
        use packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet};
        let ethernet_payload = ethernet_packet.payload();
        let destructured_ip_packet_info: Option<(IpAddr, IpAddr, usize)> =
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => match Ipv4Packet::new(ethernet_payload) {
                    Some(ip_packet) => {
                        let source_ip: IpAddr = ip_packet.get_source().into();
                        let destination_ip: IpAddr = ip_packet.get_destination().into();
                        let ip_payload_size = ip_packet.payload().len();
                        Some((source_ip, destination_ip, ip_payload_size))
                    }
                    None => None,
                },
                EtherTypes::Ipv6 => match Ipv6Packet::new(ethernet_payload) {
                    Some(ip_packet) => {
                        let source_ip: IpAddr = ip_packet.get_source().into();
                        let destination_ip: IpAddr = ip_packet.get_destination().into();
                        let ip_payload_size = ip_packet.payload().len();
                        Some((source_ip, destination_ip, ip_payload_size))
                    }
                    None => None,
                },
                _ => None,
            };

        if let Some((source_ip, destination_ip, size)) = destructured_ip_packet_info {
            let mut attempt_remaining = 10;
            loop {
                if attempt_remaining == 0 {
                    break;
                }
                match self.bucket_sender.send(Message {
                    ether_type: ethernet_packet.get_ethertype(),
                    direction: Direction::determine(&self.ips_set, source_ip, destination_ip),
                    source_ip,
                    destination_ip,
                    size,
                }) {
                    Ok(_) => break,
                    Err(_) => {
                        attempt_remaining -= 1;
                        std::thread::park_timeout(Duration::from_millis(5));
                    }
                }
            }
        }
    }

    fn run(&self) {
        use packet::ethernet::EthernetPacket;
        let mut receiver_refcell = self.receiver.borrow_mut();
        match receiver_refcell.as_deref_mut() {
            None => {
                // Attempt inquire channel
                match datalink::channel(
                    &&self.interface,
                    Config {
                        read_timeout: Some(time::Duration::new(1, 0)),
                        read_buffer_size: 65536,
                        ..Default::default()
                    },
                ) {
                    Ok(Channel::Ethernet(_data_link_sender, data_link_receiver_proto)) => {
                        *receiver_refcell = Some(data_link_receiver_proto);
                    }
                    _ => {
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                    }
                }
            }
            Some(datalink_receiver) => {
                match datalink_receiver.next() {
                    // If next yield bytes, read
                    Ok(bytes) => match EthernetPacket::new(bytes) {
                        Some(ethernet_packet) => self.handle_ethernet_packet(&ethernet_packet),
                        None => {}
                    },
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let network_interfaces = datalink::interfaces();
    let ips_set = generate_local_ips_set_from_interfaces(&network_interfaces);
    let (bucket_sender, bucket_receiver) = mpsc::channel::<Message>();

    let bucket_thread = std::thread::Builder::new()
        .name(String::from("message_bucket"))
        .spawn(move || loop {
            let maybe_message = bucket_receiver.recv_timeout(Duration::from_millis(10));
            if let Ok(message) = maybe_message {
                println!("{:?}", message);
            }
        })
        .unwrap();

    let sniffer_thread_options = network_interfaces
        .iter()
        .filter(filter_sniffable_interfaces)
        .map(|interface| {
            let interface = interface.clone();
            let name = format!("sniffer_{}", interface.name);
            let ips_set = ips_set.clone();
            let bucket_sender = bucket_sender.clone();
            std::thread::Builder::new()
                .name(name.clone())
                .spawn(move || {
                    let data_link_sniffer = Sniffer {
                        bucket_sender,
                        ips_set,
                        interface,
                        receiver: RefCell::new(None),
                    };
                    loop {
                        data_link_sniffer.run();
                    }
                })
        })
        .collect::<Vec<_>>();

    bucket_thread.join().unwrap();

    for maybe_thread in sniffer_thread_options {
        if let Ok(thread) = maybe_thread {
            thread.join().unwrap();
        }
    }

    Ok(())
}
