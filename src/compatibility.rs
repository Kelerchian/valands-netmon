/**
 * This file contains fns to convert pktparse structs to libpnet structs and vice versa
 */
use pktparse::ethernet::MacAddress;
use pnet::util::MacAddr;

pub fn mac_addr_to_mac_address(mac_addr: &MacAddr) -> MacAddress {
    MacAddress([
        mac_addr.0, mac_addr.1, mac_addr.2, mac_addr.3, mac_addr.4, mac_addr.5,
    ])
}