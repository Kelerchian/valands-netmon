use std::{collections::HashSet, net::IpAddr, time::{Duration, self}, sync::Arc};
use pktparse::ethernet::MacAddress;
use pnet::datalink::NetworkInterface;
use crate::{MessageBuckets, generate_local_macs_set_from_interfaces, generate_local_ips_set_from_interfaces, message::{MessageRecord, Direction}, structs::raw::Raw};



pub struct MessageTableRegulator {
    pub local_ips: HashSet<IpAddr>,
    pub local_macs: Vec<MacAddress>,
    pub rotation_duration: Duration,
    pub expiry_duration: Duration,
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