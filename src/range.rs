use std::net::IpAddr;

use cidr::{Cidr, IpCidr};

use crate::ports::PortRange;

/// HostRange holds ports to scan for each host in `ScanRange`.
pub struct HostRange {
    pub host: IpAddr,
    pub ports: PortRange,
}

///ScanRnge contains information which hosts and ports on those hosts to scan
/// Use `hosts` to get iterator which returns `HosIterator` for each host to
/// scan. `HostRange` can be used to get iterators for ports to scan on
/// that host.
pub struct ScanRange<'a> {
    ports: PortRange,
    addrs: &'a [IpCidr],
    excludes: &'a [IpAddr],
}

impl<'a> ScanRange<'a> {
    /// Ceate new `ScanRange` which will return given ports on given
    /// hosts/networks. The addresses in `excludes` are excluded from
    /// resulting iterators.
    pub fn create(addrs: &'a [IpCidr], excludes: &'a [IpAddr], ports: PortRange) -> ScanRange<'a> {
        ScanRange {
            addrs,
            ports,
            excludes,
        }
    }

    /// Get the number of ports to scan on each host
    pub fn get_port_count(&self) -> u16 {
        self.ports.port_count()
    }
}

impl ScanRange<'_> {
    /// Get iterator which returns `HostRange` for each host in range
    pub fn hosts(&'_ self) -> impl Iterator<Item = HostRange> + '_ {
        return self
            .addrs
            .iter()
            .flat_map(|cidr| cidr.iter())
            .filter(move |a| !self.excludes.contains(a))
            .map(move |a| HostRange {
                host: a,
                ports: self.ports.clone(),
            });
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

        let hosts: Vec<HostRange> = sr.hosts().collect();
        assert_eq!(hosts.len(), 2);

        assert_eq!(hosts[0].host, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(hosts[1].host, "192.168.1.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_cidr() {
        let cidr1 = "192.168.1.0/24".parse::<IpCidr>().unwrap();
        let addresses = vec![cidr1];
        let excludes: Vec<IpAddr> = Vec::new();

        let sr = ScanRange::create(&addresses, &excludes, PortRange::try_from("1-10").unwrap());

        let hosts: Vec<HostRange> = sr.hosts().collect();
        assert_eq!(hosts.len(), 256);
        for (i, range) in hosts.iter().enumerate() {
            let addrstr = format!("192.168.1.{}", i);
            assert_eq!(range.host, addrstr.parse::<IpAddr>().unwrap())
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
        let hosts: Vec<IpAddr> = sr.hosts().map(|i| i.host).collect();
        assert_eq!(hosts.len(), 246);
        for e in excludes {
            assert!(!hosts.contains(&e))
        }
    }
}
