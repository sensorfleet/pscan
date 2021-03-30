use crate::ports;
use crate::scanner;
use serde::{Deserialize, Deserializer};
use std::{convert::TryFrom, fmt, fs, net::IpAddr, path::Path, time::Duration};

pub const ARG_TARGET_NAME: &str = "target";
pub const ARG_EXCLUDE_NAME: &str = "exclude";
pub const ARG_PORTS_NAME: &str = "ports";
pub const ARG_CONCURRENT_SCANS_NAME: &str = "concurrent-scans";
pub const ARG_TIMEOUT_NAME: &str = "timeout";
pub const ARG_JSON_NAME: &str = "json";
pub const ARG_CONFIG_FILE_NAME: &str = "config";

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

// Parse comma separated addresses or mask + netmasks, return
// vector containing parsed addresses as cidr::IpCidr or Error
// indicating error.
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

// produce error message detailing deserializstion failure for given component
fn deserialize_failed_for(component: &str, err: Error) -> String {
    format!("{}: {}", component, err.to_string().as_str())
}

fn deserialize_from_string<'de, T, F, D>(component: &str, des: D, p: F) -> Result<T, D::Error>
where
    F: Fn(&str) -> Result<T, Error>,
    D: Deserializer<'de>,
{
    let val = String::deserialize(des)?;
    Ok(p(&val).map_err(|e| serde::de::Error::custom(deserialize_failed_for(component, e))))?
}

fn deserialize_target<'de, D>(des: D) -> Result<Option<Vec<cidr::IpCidr>>, D::Error>
where
    D: Deserializer<'de>,
{
    let r = deserialize_from_string("addresses", des, parse_addresses)?;
    Ok(Some(r))
}

fn deserialize_excludes<'de, D>(des: D) -> Result<Option<Vec<IpAddr>>, D::Error>
where
    D: Deserializer<'de>,
{
    let r = deserialize_from_string("excludes", des, parse_single_addresses)?;
    Ok(Some(r))
}

fn deserialize_ports<'de, D>(des: D) -> Result<Option<ports::PortRange>, D::Error>
where
    D: Deserializer<'de>,
{
    let r = deserialize_from_string("ports", des, |s| {
        ports::PortRange::try_from(s).map_err(Error::from)
    })?;
    Ok(Some(r))
}

fn deserialize_timeout<'de, D>(des: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    let dur = u64::deserialize(des)?;
    Ok(Some(Duration::from_millis(dur)))
}
// Configuration parameters parsed from command line or JSON file
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(deserialize_with = "deserialize_target")]
    target: Option<Vec<cidr::IpCidr>>,
    #[serde(default, deserialize_with = "deserialize_excludes")]
    excludes: Option<Vec<IpAddr>>,
    #[serde(default, deserialize_with = "deserialize_ports")]
    ports: Option<ports::PortRange>,
    #[serde(rename(deserialize = "concurrent-scans"))]
    concurrent_scans: Option<usize>,
    #[serde(default, deserialize_with = "deserialize_timeout")]
    timeout: Option<Duration>,
    json: Option<String>,
}

// helper for parsing value  from command line parameter
fn parse_from_string<F, T>(matches: &clap::ArgMatches, key: &str, p: F) -> Result<Option<T>, Error>
where
    F: Fn(&str) -> Result<T, Error>,
{
    if let Some(value) = matches.value_of(key) {
        Ok(Some(p(value)?))
    } else {
        Ok(None)
    }
}

impl<'a> TryFrom<clap::ArgMatches<'a>> for Config {
    type Error = Error;

    fn try_from(value: clap::ArgMatches) -> Result<Self, Self::Error> {
        let target = parse_from_string(&value, ARG_TARGET_NAME, parse_addresses)?;
        let excludes = parse_from_string(&value, ARG_EXCLUDE_NAME, parse_single_addresses)?;
        let ports = parse_from_string(&value, ARG_PORTS_NAME, |s| {
            ports::PortRange::try_from(s).map_err(Error::from)
        })?;
        let concurrent_scans = parse_from_string(&value, ARG_CONCURRENT_SCANS_NAME, |s| {
            s.parse().map_err(Error::from)
        })?;
        let timeout = parse_from_string(&value, ARG_TIMEOUT_NAME, |s| {
            Ok(Duration::from_millis(s.parse()?))
        })?;
        let json = value.value_of(ARG_JSON_NAME).map(|a| a.to_owned());

        Ok(Config {
            target,
            excludes,
            ports,
            concurrent_scans,
            timeout,
            json,
        })
    }
}

// helper for checking if value for configuration is overridden in
// command line.
fn get_or_override<T, F>(
    val: Option<T>,
    matches: &clap::ArgMatches,
    key: &str,
    p: F,
) -> Result<Option<T>, Error>
where
    F: Fn(&str) -> Result<T, Error>,
{
    if matches.occurrences_of(key) > 0 {
        // true override from command line arguments
        return parse_from_string(matches, key, p);
    }
    if val.is_none() {
        // no vaulue set yet and no true override, see if there is default value
        // returns None if there was no default set for command line argument
        return parse_from_string(matches, key, p);
    }
    // no override and we have already value, return it
    Ok(val)
}

impl Config {
    // Get `ScanParameters` from values in this configuration
    pub fn as_params(&self) -> scanner::ScanParameters {
        scanner::ScanParameters {
            concurrent_scans: self.concurrent_scans.unwrap(),
            wait_timeout: self.timeout.unwrap(),
            enable_adaptive_timing: false,
        }
    }

    pub fn target(&mut self) -> Vec<cidr::IpCidr> {
        self.target.take().unwrap()
    }

    pub fn exludes(&mut self) -> Vec<IpAddr> {
        self.excludes.take().unwrap_or(Vec::new())
    }

    pub fn json(&mut self) -> Option<String> {
        self.json.take()
    }

    pub fn ports(&mut self) -> ports::PortRange {
        self.ports.take().unwrap()
    }

    // Override the current configuration values with ones from command line,
    // if there are any values given on command line.
    pub fn override_with(self, matches: &clap::ArgMatches) -> Result<Config, Error> {
        let target = get_or_override(self.target, matches, ARG_TARGET_NAME, parse_addresses)?;
        let excludes = get_or_override(
            self.excludes,
            matches,
            ARG_EXCLUDE_NAME,
            parse_single_addresses,
        )?;
        let ports = get_or_override(self.ports, matches, ARG_PORTS_NAME, |s| {
            ports::PortRange::try_from(s).map_err(Error::from)
        })?;
        let concurrent_scans = get_or_override(
            self.concurrent_scans,
            matches,
            ARG_CONCURRENT_SCANS_NAME,
            |s| s.parse().map_err(Error::from),
        )?;
        let timeout = get_or_override(self.timeout, matches, ARG_TIMEOUT_NAME, |s| {
            Ok(Duration::from_millis(s.parse()?))
        })?;
        let json = get_or_override(self.json, matches, ARG_JSON_NAME, |s| Ok(s.to_owned()))?;

        Ok(Config {
            target,
            excludes,
            ports,
            concurrent_scans,
            timeout,
            json,
        })
    }

    // Verify that configuration contains all necessary values
    pub fn verify(&self) -> Result<(), Error> {
        let mut missing_fields: Vec<&str> = Vec::new();
        if self.target.is_none() {
            missing_fields.push("targets to scan");
        }
        if self.ports.is_none() {
            missing_fields.push("ports to scan")
        }
        if self.timeout.is_none() {
            missing_fields.push("connection timeout")
        }
        if self.concurrent_scans.is_none() {
            missing_fields.push("concurrent scanner count")
        }

        if !missing_fields.is_empty() {
            let fields = missing_fields.iter().fold(String::new(), |mut acc, s| {
                acc.push_str(format!("{}, ", s).as_str());
                acc
            });

            return Err(Error::Message(format!(
                "missing configuration values for: {}",
                fields.strip_suffix(", ").unwrap()
            )));
        }
        Ok(())
    }

    // Read configuration from given JSON file
    pub fn from_json_file(file_name: &str) -> Result<Config, Error> {
        let p = Path::new(file_name);
        if !p.exists() {
            return Err(Error::Message(format!(
                "configuration file {} not found",
                file_name
            )));
        }
        let data = fs::read_to_string(p)
            .map_err(|e| Error::Message(format!("unable to read configuration file: {}", e)))?;
        serde_json::from_str(&data).map_err(|e| Error::Message(e.to_string()))
    }
}
