

#[derive(Debug, PartialEq, Clone)]
pub enum ARP {
    Request(pktparse::arp::ArpPacket),
    Reply(pktparse::arp::ArpPacket),
}
