use std::{
    cell::RefCell,
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    Resolver,
};

pub struct DNSResolverActor {
    pub store: Arc<RwLock<DNSResolverStore>>,
    /**
     * The usage of Option here is dirty here
     * but I need fast solution over the alternative.
     */
    pub thread_handle: RefCell<Option<std::thread::JoinHandle<()>>>,
}

impl Default for DNSResolverActor {
    fn default() -> Self {
        let store_rwlock_arc: Arc<RwLock<DNSResolverStore>> = Default::default();
        let store_rwlock_arc_clone = Arc::clone(&store_rwlock_arc);
        let dns_resolver =
            Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();

        let thread_handle = std::thread::Builder::new()
            .name(String::from("name_resolver"))
            .spawn(move || loop {
                let unresolved_ips: Vec<IpAddr> = {
                    let dns_resolver_store = store_rwlock_arc.read().unwrap();
                    dns_resolver_store.get_unresolved_ips()
                };

                if unresolved_ips.len() == 0 {
                    continue;
                }

                let resolved_ips: Vec<(IpAddr, String)> = unresolved_ips
                    .iter()
                    .filter_map(|ip_addr| -> Option<(IpAddr, String)> {
                        // TODO: optimize with rayon
                        let reverse_lookup_result = dns_resolver.reverse_lookup(ip_addr.clone());
                        match reverse_lookup_result {
                            Ok(reverse_lookup) => match reverse_lookup.iter().next() {
                                Some(name) => Some((ip_addr.clone(), name.to_string())),
                                None => None,
                            },
                            Err(x) => None,
                        }
                    })
                    .collect();

                if resolved_ips.len() == 0 {
                    continue;
                }

                let mut dns_resolver_store = store_rwlock_arc.write().unwrap();
                resolved_ips.iter().for_each(|(ip_address_ref, hostname)| {
                    // println!("resolved: {} -> {}", ip_address_ref, hostname);
                    dns_resolver_store.insert(ip_address_ref, hostname.clone());
                });

                std::thread::park_timeout(Duration::from_millis(10));
            })
            .unwrap();

        Self {
            store: store_rwlock_arc_clone,
            thread_handle: RefCell::new(Some(thread_handle)),
        }
    }
}

impl Drop for DNSResolverActor {
    fn drop(&mut self) {
        self.join().unwrap();
    }
}

impl DNSResolverActor {
    pub fn join(&self) -> Result<(), ()> {
        let mut thread_handle = self.thread_handle.borrow_mut();
        match thread_handle.take() {
            Some(handle) => match handle.join() {
                Ok(_) => Ok(()),
                Err(_) => Err(()),
            },
            None => Ok(()),
        }
    }
}

#[derive(Default)]
pub struct DNSResolverStore {
    pub map: HashMap<IpAddr, Option<String>>,
}

impl DNSResolverStore {
    pub fn is_registered(&self, ip_address_ref: &IpAddr) -> bool {
        self.map.contains_key(ip_address_ref)
    }

    pub fn register_default_if_empty(&mut self, ip_address_ref: &IpAddr) {
        let ip_address = ip_address_ref.clone();
        if !self.map.contains_key(&ip_address) {
            self.map.insert(ip_address, None);
        }
    }

    pub fn insert(&mut self, ip_address_ref: &IpAddr, hostname: String) -> Option<Option<String>> {
        self.map.insert(*ip_address_ref, Some(hostname))
    }

    pub fn get(&self, ip_address_ref: &IpAddr) -> Option<&String> {
        match self.map.get(ip_address_ref) {
            Some(container) => match container {
                Some(name) => Some(name),
                _ => None,
            },
            None => None,
        }
    }

    pub fn get_unresolved_ips(&self) -> Vec<IpAddr> {
        self.map
            .iter()
            .filter(|(_, val)| val.is_none())
            .map(|(key, _)| key.clone())
            .collect()
    }
}
