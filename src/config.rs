use crate::ports;
use crate::scanner;
use serde::{Deserialize, Deserializer};
use std::{convert::TryFrom, fmt, fs, net::IpAddr, path::Path, time::Duration};

pub const ARG_TARGET: &str = "target";
pub const ARG_EXCLUDE: &str = "exclude";
pub const ARG_PORTS: &str = "ports";
pub const ARG_CONCURRENT_SCANS: &str = "concurrent-scans";
pub const ARG_TIMEOUT: &str = "timeout";
pub const ARG_JSON: &str = "json";
pub const ARG_CONFIG_FILE: &str = "config";
pub const ARG_RETRY_ON_ERROR: &str = "retry-on-error";
pub const ARG_TRY_COUNT: &str = "try-count";
pub const ARG_READ_BANNER_SIZE: &str = "read-banner-size";
pub const ARG_READ_BANNER_TIMEOUT: &str = "read-banner-timeout";
pub const ARG_READ_BANNER: &str = "read-banner";
pub const ARG_VERBOSE: &str = "verbose";

pub fn build_commandline_args() -> clap::App<'static, 'static> {
    clap::App::new("Simple port scanner")
        .version("0.0.1")
        .about("Scans ports")
        .arg(
            clap::Arg::with_name(ARG_TARGET)
                .long(ARG_TARGET)
                .short("t")
                .takes_value(true)
                .required(false)
                .help("Address(es) of the host(s) to scan, IP addresses, or CIDRs separated by comma"),
        )
        .arg(
            clap::Arg::with_name(ARG_EXCLUDE)
                .long(ARG_EXCLUDE)
                .short("e")
                .takes_value(true)
                .required(false)
                .help("Comma -separated list of addresses to exclude from scanning")
        )
        .arg(
            clap::Arg::with_name(ARG_PORTS)
                .long(ARG_PORTS)
                .short("p")
                .takes_value(true)
                .required(false)
                .default_value("1-100")
                .help("Ports to scan"),
        )
        .arg(
            clap::Arg::with_name(ARG_CONCURRENT_SCANS)
                .long(ARG_CONCURRENT_SCANS)
                .short("b")
                .takes_value(true)
                .required(false)
                .help("Number of concurrent scans to run")
                .default_value("100"),
        )
        // .arg(
        //     clap::Arg::with_name("adaptive-timing")
        //         .long("enable-adaptive-timing")
        //         .short("A")
        //         .takes_value(false)
        //         .required(false)
        //         .help("Enable adaptive timing (adapt timeout based on detected connection delay)"),
        // )
        .arg(
            clap::Arg::with_name(ARG_TIMEOUT)
                .long(ARG_TIMEOUT)
                .short("T")
                .takes_value(true)
                .default_value("1000")
                .required(false)
                .help("Timeout in ms to wait for response before determening port as closed/firewalled")
        )
        .arg(clap::Arg::with_name(ARG_JSON)
            .long(ARG_JSON)
            .short("j")
            .takes_value(true)
            .required(false)
            .help("Write output as JSON into given file, - to write to stdout")
        )
        .arg(clap::Arg::with_name(ARG_CONFIG_FILE)
            .long(ARG_CONFIG_FILE)
            .short("C")
            .takes_value(true)
            .required(false)
            .help("Read configuration from given JSON file")
        )
        .arg(clap::Arg::with_name(ARG_RETRY_ON_ERROR)
            .long(ARG_RETRY_ON_ERROR)
            .short("R")
            .takes_value(false)
            .required(false)
            .help("Retry scan a few times on (possible transient) network error")
        ).arg(clap::Arg::with_name(ARG_TRY_COUNT)
            .long(ARG_TRY_COUNT)
            .short("r")
            .takes_value(true)
            .required(false)
            .default_value("2")
            .help("Number of times to try a port which receives no response (including the initial try)")
        ).arg(clap::Arg::with_name(ARG_VERBOSE)
            .long(ARG_VERBOSE)
            .short("v")
            .takes_value(false)
            .required(false)
            .help("Verbose output")
        ).arg(clap::Arg::with_name(ARG_READ_BANNER)
            .long(ARG_READ_BANNER)
            .short("B")
            .takes_value(false)
            .required(false)
            .help("Try to read up to read-banner-size bytes (with read-banner-timeout) when connection is established")
        ).arg(clap::Arg::with_name(ARG_READ_BANNER_TIMEOUT)
            .long(ARG_READ_BANNER_TIMEOUT)
            .takes_value(true)
            .default_value("1000")
            .required(false)
            .help("Timeout in ms to wait for when reading banner from open port")
        ).arg(clap::Arg::with_name(ARG_READ_BANNER_SIZE)
            .long(ARG_READ_BANNER_SIZE)
            .takes_value(true)
            .default_value("256")
            .required(false)
            .help("Maximum number of bytes to read when reading banner from open port")
        )
}

#[derive(Debug)]
pub enum Error {
    Message(String),
    ParseInt(std::num::ParseIntError),
    ParseNet(cidr::NetworkParseError),
    ParseAddr(std::net::AddrParseError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Message(m) => write!(f, "{}", m),
            Error::ParseInt(e) => write!(f, "{}", e),
            Error::ParseAddr(e) => write!(f, "{}", e),
            Error::ParseNet(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Message(_) => None,
            Error::ParseInt(e) => Some(e),
            Error::ParseAddr(e) => Some(e),
            Error::ParseNet(e) => Some(e),
        }
    }
}
impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error::ParseInt(e)
    }
}

impl From<std::str::ParseBoolError> for Error {
    fn from(e: std::str::ParseBoolError) -> Self {
        Error::Message(format!("{}", e))
    }
}

impl From<cidr::NetworkParseError> for Error {
    fn from(e: cidr::NetworkParseError) -> Self {
        Error::ParseNet(e)
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(e: std::net::AddrParseError) -> Self {
        Error::ParseAddr(e)
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

fn deserialize_duration<'de, D>(des: D) -> Result<Option<Duration>, D::Error>
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
    #[serde(default, deserialize_with = "deserialize_target")]
    target: Option<Vec<cidr::IpCidr>>,
    #[serde(default, deserialize_with = "deserialize_excludes")]
    excludes: Option<Vec<IpAddr>>,
    #[serde(default, deserialize_with = "deserialize_ports")]
    ports: Option<ports::PortRange>,
    #[serde(rename(deserialize = "concurrent-scans"))]
    concurrent_scans: Option<usize>,
    #[serde(default, deserialize_with = "deserialize_duration")]
    timeout: Option<Duration>,
    json: Option<String>,
    #[serde(rename(deserialize = "retry-on-error"))]
    retry_on_error: Option<bool>,
    #[serde(rename(deserialize = "try-count"))]
    try_count: Option<usize>,
    #[serde(rename(deserialize = "read-banner"))]
    read_banner: Option<bool>,
    #[serde(rename(deserialize = "read-banner-size"))]
    read_banner_size: Option<usize>,
    #[serde(
        rename(deserialize = "read-banner-timeout"),
        deserialize_with = "deserialize_duration"
    )]
    read_banner_timeout: Option<Duration>,
    verbose: Option<bool>,
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
        let target = parse_from_string(&value, ARG_TARGET, parse_addresses)?;
        let excludes = parse_from_string(&value, ARG_EXCLUDE, parse_single_addresses)?;
        let ports = parse_from_string(&value, ARG_PORTS, |s| {
            ports::PortRange::try_from(s).map_err(Error::from)
        })?;
        let concurrent_scans = parse_from_string(&value, ARG_CONCURRENT_SCANS, |s| {
            s.parse().map_err(Error::from)
        })?;
        let timeout = parse_from_string(&value, ARG_TIMEOUT, |s| {
            Ok(Duration::from_millis(s.parse()?))
        })?;
        let json = value.value_of(ARG_JSON).map(|a| a.to_owned());
        let retry_on_error = Some(value.is_present(ARG_RETRY_ON_ERROR));
        let try_count =
            parse_from_string(&value, ARG_TRY_COUNT, |s| s.parse().map_err(Error::from))?;
        let read_banner_size = parse_from_string(&value, ARG_READ_BANNER_SIZE, |s| {
            s.parse().map_err(Error::from)
        })?;
        let read_banner_timeout = parse_from_string(&value, ARG_READ_BANNER_TIMEOUT, |s| {
            Ok(Duration::from_millis(s.parse()?))
        })?;
        let read_banner = Some(value.is_present(ARG_READ_BANNER));
        let verbose = Some(value.is_present(ARG_VERBOSE));

        Ok(Config {
            target,
            excludes,
            ports,
            concurrent_scans,
            timeout,
            json,
            retry_on_error,
            try_count,
            read_banner,
            read_banner_size,
            read_banner_timeout,
            verbose,
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
        let (read_banner_size, read_banner_timeout) = if self.read_banner.unwrap_or(false) {
            (self.read_banner_size, self.read_banner_timeout)
        } else {
            (None, None)
        };

        scanner::ScanParameters {
            concurrent_scans: self.concurrent_scans.unwrap(),
            wait_timeout: self.timeout.unwrap(),
            enable_adaptive_timing: false,
            retry_on_error: self.retry_on_error.unwrap(),
            try_count: self.try_count.unwrap(),
            read_banner_size,
            read_banner_timeout,
        }
    }

    pub fn target(&mut self) -> Vec<cidr::IpCidr> {
        self.target.take().unwrap()
    }

    pub fn exludes(&mut self) -> Vec<IpAddr> {
        self.excludes.take().unwrap_or_default()
    }

    pub fn json(&mut self) -> Option<String> {
        self.json.take()
    }

    pub fn ports(&mut self) -> ports::PortRange {
        self.ports.take().unwrap()
    }

    pub fn verbose(&self) -> bool {
        self.verbose.unwrap_or(false)
    }

    // Override the current configuration values with ones from command line,
    // if there are any values given on command line.
    pub fn override_with(self, matches: &clap::ArgMatches) -> Result<Config, Error> {
        let target = get_or_override(self.target, matches, ARG_TARGET, parse_addresses)?;
        let excludes =
            get_or_override(self.excludes, matches, ARG_EXCLUDE, parse_single_addresses)?;
        let ports = get_or_override(self.ports, matches, ARG_PORTS, |s| {
            ports::PortRange::try_from(s).map_err(Error::from)
        })?;
        let concurrent_scans =
            get_or_override(self.concurrent_scans, matches, ARG_CONCURRENT_SCANS, |s| {
                s.parse().map_err(Error::from)
            })?;
        let timeout = get_or_override(self.timeout, matches, ARG_TIMEOUT, |s| {
            Ok(Duration::from_millis(s.parse()?))
        })?;
        let json = get_or_override(self.json, matches, ARG_JSON, |s| Ok(s.to_owned()))?;
        let retry_on_error = {
            if matches.is_present(ARG_RETRY_ON_ERROR) {
                Some(true)
            } else {
                self.retry_on_error.or(Some(false))
            }
        };
        let try_count = get_or_override(self.try_count, matches, ARG_TRY_COUNT, |s| {
            s.parse().map_err(Error::from)
        })?;
        let read_banner = {
            if matches.is_present(ARG_READ_BANNER) {
                Some(true)
            } else {
                self.read_banner.or(Some(false))
            }
        };
        let read_banner_size =
            get_or_override(self.read_banner_size, matches, ARG_READ_BANNER_SIZE, |s| {
                s.parse().map_err(Error::from)
            })?;
        let read_banner_timeout = get_or_override(
            self.read_banner_timeout,
            matches,
            ARG_READ_BANNER_TIMEOUT,
            |s| Ok(Duration::from_millis(s.parse()?)),
        )?;
        let verbose = {
            if matches.is_present(ARG_VERBOSE) {
                Some(true)
            } else {
                self.verbose.or(Some(false))
            }
        };

        Ok(Config {
            target,
            excludes,
            ports,
            concurrent_scans,
            timeout,
            json,
            retry_on_error,
            try_count,
            read_banner,
            read_banner_size,
            read_banner_timeout,
            verbose,
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
        if let Some(c) = self.try_count {
            if c == 0 {
                return Err(Error::Message(format!(
                    "Invalid {} {}, expecting non-zero positive count",
                    ARG_TRY_COUNT, c
                )));
            }
        } else {
            missing_fields.push(ARG_TRY_COUNT);
        }

        if self.read_banner.unwrap_or(false) {
            // make sure we have all parametes for reading banner
            // however, we should always have these values from
            // command line parameter defaults.
            if self.read_banner_size.is_none() {
                missing_fields.push("Size for reading banner");
            }
            if self.read_banner_timeout.is_none() {
                missing_fields.push("timeout for reading banner");
            }
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
