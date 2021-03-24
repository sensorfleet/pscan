use crate::ports;
use crate::scanner;
use std::{convert::TryFrom, fmt, net::IpAddr, time::Duration};

pub const ARG_ADDRESS_NAME: &str = "address";
pub const ARG_EXCLUDE_NAME: &str = "exclude";
pub const ARG_PORTS_NAME: &str = "ports";
pub const ARG_CONCURRENT_COUNT_NAME: &str = "batch-count";
pub const ARG_TIMEOUT_NAME: &str = "timeout";
pub const ARG_OUTPUT_FILE_NAME: &str = "json";

#[derive(Debug)]
pub enum Error {
    Message(String),
    IntError(std::num::ParseIntError),
    NetParseError(cidr::NetworkParseError),
    AddrError(std::net::AddrParseError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Message(m) => write!(f, "{}", m),
            Error::IntError(e) => write!(f, "{}", e),
            Error::AddrError(e) => write!(f, "{}", e),
            Error::NetParseError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Message(_) => None,
            Error::IntError(e) => Some(e),
            Error::AddrError(e) => Some(e),
            Error::NetParseError(e) => Some(e),
        }
    }
}
impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error::IntError(e)
    }
}

impl From<cidr::NetworkParseError> for Error {
    fn from(e: cidr::NetworkParseError) -> Self {
        Error::NetParseError(e)
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(e: std::net::AddrParseError) -> Self {
        Error::AddrError(e)
    }
}

impl From<&str> for Error {
    fn from(m: &str) -> Self {
        Error::Message(m.to_owned())
    }
}

impl From<ports::Error> for Error {
    fn from(e: ports::Error) -> Self {
        return Self::from(format!("{}", e).as_str());
    }
}

fn parse_addresses(val: &str) -> Result<Vec<cidr::IpCidr>, Error> {
    let mut ret = Vec::new();

    if !val.contains(',') {
        // assume single address
        let addr = val.trim().parse::<cidr::IpCidr>()?;
        ret.push(addr);
    } else {
        for a in val.split(',') {
            ret.push(a.trim().parse::<cidr::IpCidr>()?);
        }
    }
    Ok(ret)
}

// parse comman separated IP addresses. Expecting plain IP addresses, not
// networks in address/mask
fn parse_single_addresses(val: &str) -> Result<Vec<IpAddr>, Error> {
    let mut ret = Vec::new();
    if !val.contains(',') {
        let addr = val.trim().parse::<IpAddr>()?;
        ret.push(addr)
    } else {
        for a in val.split(',') {
            ret.push(a.trim().parse::<IpAddr>()?);
        }
    }
    Ok(ret)
}

pub struct Config {
    addresses: Option<Vec<cidr::IpCidr>>,
    excludes: Option<Vec<IpAddr>>,
    ports: Option<ports::PortRange>,
    concurrent_count: Option<usize>,
    timeout: Option<Duration>,
    output_file: Option<String>,
}

impl<'a> TryFrom<clap::ArgMatches<'a>> for Config {
    type Error = Error;

    fn try_from(value: clap::ArgMatches) -> Result<Self, Self::Error> {
        let addresses = match value.value_of(ARG_ADDRESS_NAME) {
            None => None,
            Some(a) => Some(parse_addresses(a)?),
        };
        let excludes = match value.value_of(ARG_EXCLUDE_NAME) {
            None => None,
            Some(a) => Some(parse_single_addresses(a)?),
        };
        let ports = match value.value_of(ARG_PORTS_NAME) {
            None => None,
            Some(a) => Some(ports::PortRange::try_from(a)?),
        };
        let concurrent_count: Option<usize> = match value.value_of(ARG_CONCURRENT_COUNT_NAME) {
            None => None,
            Some(a) => Some(a.parse()?),
        };
        let timeout = match value.value_of(ARG_TIMEOUT_NAME) {
            None => None,
            Some(a) => Some(Duration::from_millis(a.parse()?)),
        };
        let output_file = value.value_of(ARG_OUTPUT_FILE_NAME).map(|a| a.to_owned());

        Ok(Config {
            addresses,
            excludes,
            ports,
            concurrent_count,
            timeout,
            output_file,
        })
    }
}

impl Config {
    pub fn as_params(&self) -> scanner::ScanParameters {
        scanner::ScanParameters {
            concurrent_scans: self.concurrent_count.unwrap(),
            wait_timeout: self.timeout.unwrap(),
            enable_adaptive_timing: false,
        }
    }

    pub fn addrs(&mut self) -> Vec<cidr::IpCidr> {
        self.addresses.take().unwrap()
    }

    pub fn exludes(&mut self) -> Vec<IpAddr> {
        self.excludes.take().unwrap_or(Vec::new())
    }

    pub fn output_file(&mut self) -> Option<String> {
        self.output_file.take()
    }

    pub fn ports(&mut self) -> ports::PortRange {
        self.ports.take().unwrap()
    }
}
