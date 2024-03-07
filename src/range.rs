use std::{collections::HashSet, hash::Hash, net::IpAddr};

use cidr::IpCidr;

use crate::ports::PortRange;

///ScanRnge contains information which hosts and ports on those hosts to scan
pub struct ScanRange<'a> {
    ports: Option<PortRange>,
    addrs: &'a [IpCidr],
    excludes: &'a [IpAddr],
}

impl<'a> ScanRange<'a> {
    /// Create new `ScanRange` which covers given address range and ports.
    /// Addresses in `excludes` will be excluded from scan.
    pub fn create(addrs: &'a [IpCidr], excludes: &'a [IpAddr], ports: PortRange) -> ScanRange<'a> {
        ScanRange {
            addrs,
            ports: Some(ports),
            excludes,
        }
    }

    /// Get the number of ports to scan on each host
    pub fn get_port_count(&self) -> u16 {
        match self.ports {
            None => 0,
            Some(ref p) => p.port_count(),
        }
    }

    pub fn ports(&mut self) -> Option<PortRange> {
        self.ports.take()
    }
}

impl ScanRange<'_> {
    /// Get iterator for hosts to scan
    pub fn hosts(&'_ self) -> impl Iterator<Item = IpAddr> + '_ {
        self.addrs
            .iter()
            .flat_map(|cidr| cidr.iter().addresses())
            .filter(move |a| !self.excludes.contains(a))
    }
}

// ChunkIter can be used to provide chunks from given iterator
// Each call to `chunk` produces a `HasSet` containing at most `chunk_size`
// elements from `iter`.
pub struct ChunkIter<T: Iterator> {
    iter: T,
    chunk_size: usize,
}

impl<T> ChunkIter<T>
where
    T: Iterator,
    T::Item: Eq + Hash,
{
    pub fn new(iter: T, chunk_size: usize) -> Self {
        ChunkIter { iter, chunk_size }
    }

    pub fn chunk(&mut self) -> Option<HashSet<T::Item>> {
        let mut ret = HashSet::with_capacity(self.chunk_size);
        for _i in 0..self.chunk_size {
            match self.iter.next() {
                Some(val) => ret.insert(val),
                None => break,
            };
        }
        if ret.is_empty() {
            None
        } else {
            Some(ret)
        }
    }
}

impl<T> Iterator for ChunkIter<T>
where
    T: Iterator,
    T::Item: Eq + Hash,
{
    type Item = HashSet<T::Item>;

    fn next(&mut self) -> Option<Self::Item> {
        self.chunk()
    }
}

#[cfg(test)]

mod tests {
    use std::convert::TryFrom;

    use super::*;
    use cidr::IpCidr;

    #[test]
    fn test_basic() {
        let cidr1 = "192.168.1.1".parse::<IpCidr>().unwrap();
        let cidr2 = "192.168.1.2".parse::<IpCidr>().unwrap();

        let addresses = vec![cidr1, cidr2];
        let excludes: Vec<IpAddr> = Vec::new();
        let ports = PortRange::try_from("1-10").unwrap();

        let sr = ScanRange::create(&addresses, &excludes, ports);

        let hosts: Vec<IpAddr> = sr.hosts().collect();
        assert_eq!(hosts.len(), 2);

        assert_eq!(hosts[0], "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(hosts[1], "192.168.1.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_cidr() {
        let cidr1 = "192.168.1.0/24".parse::<IpCidr>().unwrap();
        let addresses = vec![cidr1];
        let excludes: Vec<IpAddr> = Vec::new();

        let sr = ScanRange::create(&addresses, &excludes, PortRange::try_from("1-10").unwrap());

        let hosts: Vec<IpAddr> = sr.hosts().collect();
        assert_eq!(hosts.len(), 256);
        for (i, addr) in hosts.iter().enumerate() {
            let addrstr = format!("192.168.1.{}", i);
            assert_eq!(*addr, addrstr.parse::<IpAddr>().unwrap())
        }
    }

    #[test]
    fn test_with_excludes() {
        let cidr1 = "192.168.1.0/24".parse::<IpCidr>().unwrap();
        let cidr2 = "192.168.2.1".parse::<IpCidr>().unwrap();
        let addresses = vec![cidr1, cidr2];
        let mut excludes: Vec<IpAddr> = Vec::new();
        for i in 10..21 {
            excludes.push(format!("192.168.1.{}", i).parse().unwrap());
        }

        let sr = ScanRange::create(&addresses, &excludes, PortRange::try_from("1-10").unwrap());
        let hosts: Vec<IpAddr> = sr.hosts().collect();
        assert_eq!(hosts.len(), 246);
        for e in excludes {
            assert!(!hosts.contains(&e))
        }
    }

    #[test]
    fn test_chunks() {
        let mut chunks = ChunkIter::new(0..5, 2);

        let ch1 = chunks.chunk().unwrap();
        assert!(ch1.len() == 2 && ch1.contains(&0) && ch1.contains(&1));
        let ch2 = chunks.chunk().unwrap();
        assert!(ch2.len() == 2 && ch2.contains(&2) && ch2.contains(&3));
        let ch3 = chunks.chunk().unwrap();
        assert!(ch3.len() == 1 && ch3.contains(&4));
        assert!(chunks.chunk().is_none());
    }

    #[test]
    fn test_chunk_iter() {
        let chunks = ChunkIter::new(0..5, 2);
        let values = chunks.flatten().collect::<Vec<i32>>();
        assert!(values.len() == 5);
        for i in 0..5 {
            assert!(values.contains(&i))
        }
    }
}
