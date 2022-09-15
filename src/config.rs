use crate::ports;
use crate::range;
use crate::scanner;
use serde::{Deserialize, Deserializer};
use std::{convert::TryFrom, fmt, fs, net::IpAddr, path::Path, time::Duration};

// names for the command line arguments
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
pub const ARG_CONCURRENT_HOSTS: &str = "concurrent-hosts";

/// Current version
pub const PSCAN_VERSION: &str = "0.2.0-dev";

/// Build command line arguments for the program.
pub fn build_commandline_args() -> clap::Command<'static> {
    clap::Command::new("TCP port scanner")
        .version(PSCAN_VERSION)
        .arg(
            clap::Arg::new(ARG_TARGET)
                .long(ARG_TARGET)
                .short('t')
                .takes_value(true)
                .required(false)
                .help("Address(es) of the host(s) to scan, IP addresses, or CIDRs separated by comma"),
        )
        .arg(
            clap::Arg::new(ARG_EXCLUDE)
                .long(ARG_EXCLUDE)
                .short('e')
                .takes_value(true)
                .required(false)
                .help("Comma -separated list of addresses to exclude from scanning")
        )
        .arg(
            clap::Arg::new(ARG_PORTS)
                .long(ARG_PORTS)
                .short('p')
                .takes_value(true)
                .required(false)
                .default_value("1-100")
                .help("Ports to scan"),
        )
        .arg(
            clap::Arg::new(ARG_CONCURRENT_SCANS)
                .long(ARG_CONCURRENT_SCANS)
                .short('b')
                .takes_value(true)
                .required(false)
                .help("Number of concurrent scans to run")
                .default_value("100"),
        )
        .arg(
            clap::Arg::new(ARG_CONCURRENT_HOSTS)
                .long(ARG_CONCURRENT_HOSTS)
                .short('H')
                .takes_value(true)
                .required(false)
                .help("Number of hosts to scan concurrently. Can be used to limit the number of hosts \
                   to scan at the same time, if number of concurrent threads is large. \
                   If no value is set, number of concurrent scans is used"
                )
        )
        .arg(
            clap::Arg::new(ARG_TIMEOUT)
                .long(ARG_TIMEOUT)
                .short('T')
                .takes_value(true)
                .default_value("1000")
                .required(false)
                .help("Timeout in ms to wait for response before determening port as closed/firewalled")
        )
        .arg(clap::Arg::new(ARG_JSON)
            .long(ARG_JSON)
            .short('j')
            .takes_value(true)
            .required(false)
            .help("Write output as JSON into given file, - to write to stdout")
        )
        .arg(clap::Arg::new(ARG_CONFIG_FILE)
            .long(ARG_CONFIG_FILE)
            .short('C')
            .takes_value(true)
            .required(false)
            .help("Read configuration from given JSON file")
        )
        .arg(clap::Arg::new(ARG_RETRY_ON_ERROR)
            .long(ARG_RETRY_ON_ERROR)
            .short('R')
            .takes_value(false)
            .required(false)
            .help("Retry scan a few times on (possible transient) network error")
        ).arg(clap::Arg::new(ARG_TRY_COUNT)
            .long(ARG_TRY_COUNT)
            .short('r')
            .takes_value(true)
            .required(false)
            .default_value("2")
            .help("Number of times to try a port which receives no response (including the initial try)")
        ).arg(clap::Arg::new(ARG_VERBOSE)
            .long(ARG_VERBOSE)
            .short('v')
            .takes_value(false)
            .required(false)
            .help("Verbose output")
        ).arg(clap::Arg::new(ARG_READ_BANNER)
            .long(ARG_READ_BANNER)
            .short('B')
            .takes_value(false)
            .required(false)
            .help("Try to read up to read-banner-size bytes (with read-banner-timeout) when connection is established")
        ).arg(clap::Arg::new(ARG_READ_BANNER_TIMEOUT)
            .long(ARG_READ_BANNER_TIMEOUT)
            .takes_value(true)
            .default_value("1000")
            .required(false)
            .help("Timeout in ms to wait for when reading banner from open port")
        ).arg(clap::Arg::new(ARG_READ_BANNER_SIZE)
            .long(ARG_READ_BANNER_SIZE)
            .takes_value(true)
            .default_value("256")
            .required(false)
            .help("Maximum number of bytes to read when reading banner from open port")
    )
}

/// Error returned when parsing command line or configuration values
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
            Error::Message(m) => m.fmt(f),
            Error::ParseInt(e) => e.fmt(f),
            Error::ParseAddr(e) => e.fmt(f),
            Error::ParseNet(e) => e.fmt(f),
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
        Error::Message(e.to_string())
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
        Self::from(e.to_string().as_str())
    }
}

/// Parse comma separated addresses or mask + netmasks, return
/// vector containing parsed addresses as cidr::IpCidr or Error
/// indicating error.
pub fn parse_addresses(val: &str) -> Result<Vec<cidr::IpCidr>, Error> {
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

/// parse comma separated IP addresses. Expecting plain IP addresses, not
/// networks in address/mask
pub fn parse_single_addresses(val: &str) -> Result<Vec<IpAddr>, Error> {
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

/// produce error message detailing deserializstion failure for given component
fn deserialize_failed_for<E>(component: &str, err: E) -> String
where
    E: std::error::Error,
{
    format!(
        "invalid value for {}: {}",
        component,
        err.to_string().as_str()
    )
}
/// Deserialize given type with serde and return the result in Option.
/// If deserialization fails, use given component name in error message
fn deserialize_type<'de, D, T>(des: D, component: &str) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::Deserialize<'de>,
{
    Ok(Some(T::deserialize(des).map_err(|e| {
        serde::de::Error::custom(deserialize_failed_for(component, e))
    })?))
}

/// Deserialize a string value from JSON and then use given function `p` to
/// convert the string to its final type.
fn deserialize_from_string<'de, T, F, D>(component: &str, des: D, p: F) -> Result<T, D::Error>
where
    F: Fn(&str) -> Result<T, Error>,
    D: Deserializer<'de>,
{
    let val = String::deserialize(des)
        .map_err(|e| serde::de::Error::custom(deserialize_failed_for(component, e)))?;
    Ok(p(&val).map_err(|e| serde::de::Error::custom(deserialize_failed_for(component, e))))?
}

/// Deserialize `target` value from JSON
fn deserialize_target<'de, D>(des: D) -> Result<Vec<cidr::IpCidr>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_from_string(ARG_TARGET, des, parse_addresses)
}

/// Deserialize 'excludes' value from JSON
fn deserialize_exclude<'de, D>(des: D) -> Result<Vec<IpAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_from_string(ARG_EXCLUDE, des, parse_single_addresses)
}

/// Deserialize 'ports' value from JSON
fn deserialize_ports<'de, D>(des: D) -> Result<Option<ports::PortRange>, D::Error>
where
    D: Deserializer<'de>,
{
    let r = deserialize_from_string(ARG_PORTS, des, |s| {
        ports::PortRange::try_from(s).map_err(Error::from)
    })?;
    Ok(Some(r))
}

fn deserialize_timeout<'de, D>(des: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(deserialize_type(des, ARG_TIMEOUT)?.map(Duration::from_millis))
}
fn deserialize_banner_timeout<'de, D>(des: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(deserialize_type(des, ARG_READ_BANNER_TIMEOUT)?.map(Duration::from_millis))
}

fn deserialize_retry_on_error<'de, D>(des: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_type(des, ARG_RETRY_ON_ERROR)
}
fn deserialize_read_banner<'de, D>(des: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_type(des, ARG_READ_BANNER)
}

fn deserialize_verbose<'de, D>(des: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_type(des, ARG_VERBOSE)
}

fn deserialize_concurrent_scans<'de, D>(des: D) -> Result<Option<usize>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_type(des, ARG_CONCURRENT_SCANS)
}

fn deserialize_concurrent_hosts<'de, D>(des: D) -> Result<Option<usize>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_type(des, ARG_CONCURRENT_HOSTS)
}

fn deserialize_try_count<'de, D>(des: D) -> Result<Option<usize>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_type(des, ARG_TRY_COUNT)
}
fn deserialize_banner_size<'de, D>(des: D) -> Result<Option<usize>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_type(des, ARG_READ_BANNER_SIZE)
}

/// Configuration parameters parsed from command line or JSON file
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, deserialize_with = "deserialize_target")]
    target: Vec<cidr::IpCidr>,
    #[serde(default, deserialize_with = "deserialize_exclude")]
    exclude: Vec<IpAddr>,
    #[serde(default, deserialize_with = "deserialize_ports")]
    ports: Option<ports::PortRange>,
    #[serde(
        default,
        rename(deserialize = "concurrent-scans"),
        deserialize_with = "deserialize_concurrent_scans"
    )]
    concurrent_scans: Option<usize>,
    #[serde(
        default,
        rename(deserialize = "concurrent-hosts"),
        deserialize_with = "deserialize_concurrent_hosts"
    )]
    concurrent_hosts: Option<usize>,
    #[serde(default, deserialize_with = "deserialize_timeout")]
    timeout: Option<Duration>,
    json: Option<String>,
    #[serde(
        default,
        rename(deserialize = "retry-on-error"),
        deserialize_with = "deserialize_retry_on_error"
    )]
    retry_on_error: Option<bool>,
    #[serde(
        default,
        rename(deserialize = "try-count"),
        deserialize_with = "deserialize_try_count"
    )]
    try_count: Option<usize>,
    #[serde(
        default,
        rename(deserialize = "read-banner"),
        deserialize_with = "deserialize_read_banner"
    )]
    read_banner: Option<bool>,
    #[serde(
        default,
        rename(deserialize = "read-banner-size"),
        deserialize_with = "deserialize_banner_size"
    )]
    read_banner_size: Option<usize>,
    #[serde(
        default,
        rename(deserialize = "read-banner-timeout"),
        deserialize_with = "deserialize_banner_timeout"
    )]
    read_banner_timeout: Option<Duration>,
    #[serde(default, deserialize_with = "deserialize_verbose")]
    verbose: Option<bool>,
}

/// helper for parsing a value from command line parameter
/// Command line parameter is expected to be a string, if it is available
/// the given function `p` is used to convert the string to its final type.
fn parse_from_string<F, T>(matches: &clap::ArgMatches, key: &str, p: F) -> Result<Option<T>, Error>
where
    F: Fn(&str) -> Result<T, Error>,
{
    if let Some(value) = matches.value_of(key) {
        Ok(Some(p(value).map_err(|e| {
            Error::Message(format!(
                "invalid value for {}: {}",
                key,
                e.to_string().as_str()
            ))
        })?))
    } else {
        Ok(None)
    }
}

impl TryFrom<clap::ArgMatches> for Config {
    type Error = Error;

    fn try_from(value: clap::ArgMatches) -> Result<Self, Self::Error> {
        let target = parse_from_string(&value, ARG_TARGET, parse_addresses)?.unwrap_or_default();
        let exclude =
            parse_from_string(&value, ARG_EXCLUDE, parse_single_addresses)?.unwrap_or_default();
        let ports = parse_from_string(&value, ARG_PORTS, |s| {
            ports::PortRange::try_from(s).map_err(Error::from)
        })?;
        let concurrent_scans = parse_from_string(&value, ARG_CONCURRENT_SCANS, |s| {
            s.parse().map_err(Error::from)
        })?;
        let concurrent_hosts: Option<usize> =
            parse_from_string(&value, ARG_CONCURRENT_HOSTS, |s| {
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
            exclude,
            ports,
            concurrent_scans,
            concurrent_hosts,
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

/// Helper for checking if value for configuration is overridden in
/// command line.
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
    /// Get `ScanParameters` from values in this configuration
    pub fn as_params(&self) -> scanner::ScanParameters {
        let (read_banner_size, read_banner_timeout) = if self.read_banner.unwrap_or(false) {
            (self.read_banner_size, self.read_banner_timeout)
        } else {
            (None, None)
        };

        scanner::ScanParameters {
            concurrent_scans: self.concurrent_scans.unwrap(),
            concurrent_hosts: self
                .concurrent_hosts
                .unwrap_or_else(|| self.concurrent_scans.unwrap()),
            wait_timeout: self.timeout.unwrap(),
            enable_adaptive_timing: false,
            retry_on_error: self.retry_on_error.unwrap(),
            try_count: self.try_count.unwrap(),
            read_banner_size,
            read_banner_timeout,
        }
    }

    // Get ScanRange from configuration values.
    // If `verify()` has been called this method will not return `None`
    pub fn get_range(&self) -> Option<range::ScanRange> {
        Some(range::ScanRange::create(
            &self.target,
            &self.exclude,
            self.ports.as_ref()?.clone(),
        ))
    }

    /// Get the json value from configuration.
    pub fn json(&self) -> Option<&str> {
        self.json.as_deref()
    }

    /// Check if verbose is set on configuration
    pub fn verbose(&self) -> bool {
        self.verbose.unwrap_or(false)
    }

    /// Override the current configuration values with ones from command line,
    /// if there are any values given on command line.
    /// Consumes current configuration and returns new value
    pub fn override_with(self, matches: &clap::ArgMatches) -> Result<Config, Error> {
        let target = get_or_override(Some(self.target), matches, ARG_TARGET, parse_addresses)?
            .unwrap_or_default();
        let exclude = get_or_override(
            Some(self.exclude),
            matches,
            ARG_EXCLUDE,
            parse_single_addresses,
        )?
        .unwrap_or_default();
        let ports = get_or_override(self.ports, matches, ARG_PORTS, |s| {
            ports::PortRange::try_from(s).map_err(Error::from)
        })?;
        let concurrent_scans =
            get_or_override(self.concurrent_scans, matches, ARG_CONCURRENT_SCANS, |s| {
                s.parse().map_err(Error::from)
            })?;
        let concurrent_hosts =
            get_or_override(self.concurrent_hosts, matches, ARG_CONCURRENT_HOSTS, |s| {
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
            exclude,
            ports,
            concurrent_scans,
            concurrent_hosts,
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

    /// Verify that configuration contains all necessary values
    pub fn verify(&self) -> Result<(), Error> {
        let mut missing_fields: Vec<&str> = Vec::new();
        if self.target.is_empty() {
            missing_fields.push(ARG_TARGET);
        }
        if self.ports.is_none() {
            missing_fields.push(ARG_PORTS);
        }
        if self.timeout.is_none() {
            missing_fields.push(ARG_TIMEOUT);
        }
        if let Some(c) = self.concurrent_scans {
            if c == 0 {
                return Err(Error::Message(format!(
                    "invalid value for {}: Value needs to be non-zero",
                    ARG_CONCURRENT_SCANS
                )));
            }
        } else {
            missing_fields.push(ARG_CONCURRENT_SCANS);
        }
        if let Some(h) = self.concurrent_hosts {
            if h == 0 {
                return Err(Error::Message(format!(
                    "invalid value for {}: Value needs to be non-zero",
                    ARG_CONCURRENT_HOSTS
                )));
            }
        }
        if let Some(c) = self.try_count {
            if c == 0 {
                return Err(Error::Message(format!(
                    "invalid value for {}: value needs to be non-zero",
                    ARG_TRY_COUNT
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
                missing_fields.push(ARG_READ_BANNER_SIZE);
            }
            if self.read_banner_timeout.is_none() {
                missing_fields.push(ARG_READ_BANNER_TIMEOUT);
            }
        }

        if !missing_fields.is_empty() {
            let fields = missing_fields.join(", ");

            return Err(Error::Message(format!(
                "missing configuration values for: {}",
                fields
            )));
        }
        Ok(())
    }

    /// Read configuration from given JSON file
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use cidr::{Cidr, IpCidr};

    use super::*;

    #[test]
    fn test_parse_address() {
        let addrstr = "192.168.1.1";
        let ip = IpAddr::from_str(addrstr).unwrap();

        let netstr = "192.168.1.0/24";

        let addrline = format!("{}, {}", addrstr, netstr);

        let result = parse_addresses(&addrline);
        assert!(result.is_ok());
        let addrs = result.unwrap();
        assert_eq!(addrs.len(), 2);
        assert!(addrs[0].is_ipv4() && addrs[0].is_host_address());
        assert_eq!(addrs[0].first_address(), ip);

        assert!(addrs[1].is_ipv4() && !addrs[1].is_host_address());
        assert_eq!(addrs[1].network_length(), 24);
        assert!(addrs[1].contains(&ip));

        let result_s = parse_single_addresses(addrstr);
        assert!(result_s.is_ok());
        let addrs_s = result_s.unwrap();
        assert_eq!(addrs_s.len(), 1);
        assert_eq!(addrs_s[0], ip);
    }

    #[test]
    fn test_parse_invalid_address() {
        let invalid_addrs = [
            "192.168.1.300",
            "foo",
            "192.168.1.0/200",
            "192.168.1.1/",
            "192.168.1.bar",
            "",
            "192.168.1.1/24",
        ];

        for addr in invalid_addrs {
            assert!(
                parse_addresses(addr).is_err(),
                "invalid addr {} was parsed",
                addr
            );
            assert!(
                parse_single_addresses(addr).is_err(),
                "invalid addr {} was parsed by parse_single_addresses()",
                addr
            );
        }
    }

    #[test]
    fn test_cmdline_to_config() {
        let cmdline = [
            "--target",
            "192.168.1.1, 192.168.1.0/24",
            "-p",
            "22,80,8080",
            "-v",
            "-B",
            "--concurrent-scans",
            "600",
            "--read-banner-size",
            "1024",
        ];

        let app = build_commandline_args().no_binary_name(true);
        let m = app.get_matches_from(cmdline);
        let cfg = Config::try_from(m).unwrap();
        assert!(cfg.verify().is_ok());

        assert!(cfg.verbose());
        assert!(cfg.read_banner.unwrap());
        assert!(!cfg.target.is_empty());
        assert!(cfg.ports.is_some());
        assert_eq!(cfg.target.len(), 2);

        assert_eq!(cfg.concurrent_scans.unwrap(), 600);
        assert_eq!(cfg.read_banner_size.unwrap(), 1024);
    }

    struct OverwriteTest<'a> {
        name: &'a str,
        arg: &'a [&'a str],
        check: Box<dyn FnOnce(Config) -> bool>,
    }

    #[test]
    fn test_config_overwrite() {
        let tests = [
            OverwriteTest {
                name: "target",
                arg: &["--target", "192.168.1.2"],
                check: Box::new(|c| {
                    c.target[0]
                        .first_address()
                        .eq(&IpAddr::from_str("192.168.1.2").unwrap())
                }),
            },
            OverwriteTest {
                name: "ports",
                arg: &["--ports", "22"],
                check: Box::new(|c| {
                    let p = (0..c.ports.as_ref().unwrap().port_count() as usize)
                        .into_iter()
                        .map(|i| c.ports.as_ref().unwrap().get(i));
                    assert_eq!(p.len(), 1);
                    let ports = p.collect::<Vec<u16>>();
                    assert_eq!(ports.len(), 1);
                    ports[0] == 22
                }),
            },
            OverwriteTest {
                name: "exclude",
                arg: &["--exclude", "192.168.1.3"],
                check: Box::new(|c| c.exclude[0].eq(&IpAddr::from_str("192.168.1.3").unwrap())),
            },
            OverwriteTest {
                name: "concurrent-scans",
                arg: &["--concurrent-scans", "100"],
                check: Box::new(|c| c.concurrent_scans.unwrap() == 100),
            },
            OverwriteTest {
                name: "timeout",
                arg: &["--timeout", "1000"],
                check: Box::new(|c| c.timeout.unwrap() == Duration::from_millis(1000)),
            },
            OverwriteTest {
                name: "json",
                arg: &["--json", "foo.json"],
                check: Box::new(|c| c.json.unwrap() == "foo.json"),
            },
            OverwriteTest {
                name: "retry_on_error",
                arg: &["--retry-on-error"],
                check: Box::new(|c| c.retry_on_error.unwrap()),
            },
            OverwriteTest {
                name: "try_count",
                arg: &["--try-count", "3"],
                check: Box::new(|c| c.try_count.unwrap() == 3),
            },
            OverwriteTest {
                name: "read_banner",
                arg: &["--read-banner"],
                check: Box::new(|c| c.read_banner.unwrap()),
            },
            OverwriteTest {
                name: "read_banner_size",
                arg: &["--read-banner-size", "64"],
                check: Box::new(|c| c.read_banner_size.unwrap() == 64),
            },
            OverwriteTest {
                name: "read_banner_timeout",
                arg: &["--read-banner-timeout", "1000"],
                check: Box::new(|c| c.read_banner_timeout.unwrap() == Duration::from_millis(1000)),
            },
            OverwriteTest {
                name: "verbose",
                arg: &["--verbose"],
                check: Box::new(|c| c.verbose.unwrap()),
            },
            OverwriteTest {
                name: "concurrent-hosts",
                arg: &["--concurrent-hosts", "1"],
                check: Box::new(|c| c.concurrent_hosts.unwrap() == 1),
            },
        ];

        for t in tests {
            // Generate a "base" config and overwrite it with test values
            // to ensure that values get overwritten
            let cfg = Config {
                target: parse_addresses("192.168.1.1").unwrap(),
                ports: Some(ports::PortRange::try_from("1-10").unwrap()),
                exclude: parse_single_addresses("192.168.1.2").unwrap(),
                concurrent_scans: Some(1),
                concurrent_hosts: None,
                timeout: Some(Duration::from_millis(100)),
                json: Some("config.json".to_owned()),
                retry_on_error: Some(false),
                try_count: Some(1),
                read_banner: Some(false),
                read_banner_size: Some(128),
                read_banner_timeout: Some(Duration::from_millis(100)),
                verbose: Some(false),
            };

            let m = build_commandline_args()
                .no_binary_name(true)
                .get_matches_from(t.arg);

            let new_cfg = cfg.override_with(&m).unwrap();
            assert!((t.check)(new_cfg), "Overwrite test for {} failed", t.name)
        }
    }

    #[test]
    fn test_config_from_json() {
        let raw_json = r#"
        {
            "target": "192.168.1.0/24",
            "ports": "1,2",
            "exclude": "192.168.1.1",
            "concurrent-scans": 600,
            "timeout": 1000,
            "retry-on-error": true,
            "try-count": 3,
            "read-banner": true,
            "read-banner-size": 512,
            "read-banner-timeout": 1200,
            "verbose": true,
            "concurrent-hosts": 100
        }
        "#;

        let cfg: Config = serde_json::from_str(raw_json).unwrap();

        let addrs = cfg.target;
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], IpCidr::from_str("192.168.1.0/24").unwrap());

        let pi = (0..cfg.ports.as_ref().unwrap().port_count() as usize)
            .into_iter()
            .map(|i| cfg.ports.as_ref().unwrap().get(i));
        let ports = pi.collect::<Vec<u16>>();
        assert_eq!(ports.len(), 2);
        assert!(ports[0] == 1 && ports[1] == 2);

        let ex_addrs = cfg.exclude;
        assert_eq!(ex_addrs.len(), 1);
        assert_eq!(ex_addrs[0], IpAddr::from_str("192.168.1.1").unwrap());

        assert_eq!(cfg.concurrent_scans.unwrap(), 600);
        assert_eq!(cfg.timeout.unwrap(), Duration::from_millis(1000));
        assert!(cfg.retry_on_error.unwrap());
        assert_eq!(cfg.try_count.unwrap(), 3);
        assert!(cfg.read_banner.unwrap());
        assert_eq!(cfg.read_banner_size.unwrap(), 512);
        assert_eq!(
            cfg.read_banner_timeout.unwrap(),
            Duration::from_millis(1200)
        );
        assert!(cfg.verbose.unwrap());
        assert_eq!(cfg.concurrent_hosts.unwrap(), 100)
    }

    #[test]
    fn test_cfg_as_scan_params() {
        let raw_json = r#"
        {
            "target": "192.168.1.0/24",
            "ports": "1,2",
            "exclude": "192.168.1.1",
            "concurrent-scans": 600,
            "timeout": 1000,
            "retry-on-error": true,
            "try-count": 3,
            "read-banner": true,
            "read-banner-size": 512,
            "read-banner-timeout": 1200,
            "verbose": true
        }
        "#;

        let cfg: Config = serde_json::from_str(raw_json).unwrap();

        let params = cfg.as_params();
        assert_eq!(params.concurrent_scans, cfg.concurrent_scans.unwrap());
        assert_eq!(params.wait_timeout, cfg.timeout.unwrap());
        assert_eq!(
            params.read_banner_size.unwrap(),
            cfg.read_banner_size.unwrap()
        );
        assert_eq!(
            params.read_banner_timeout.unwrap(),
            cfg.read_banner_timeout.unwrap()
        );
        assert_eq!(params.try_count, cfg.try_count.unwrap());
        assert_eq!(params.retry_on_error, cfg.retry_on_error.unwrap());
        assert_eq!(params.concurrent_hosts, cfg.concurrent_scans.unwrap());
    }

    #[test]
    fn test_cfg_as_scan_params_no_banner() {
        let raw_json = r#"
        {
            "target": "192.168.1.0/24",
            "ports": "1,2",
            "exclude": "192.168.1.1",
            "concurrent-scans": 600,
            "timeout": 1000,
            "retry-on-error": true,
            "try-count": 3,
            "read-banner": false,
            "read-banner-size": 512,
            "read-banner-timeout": 1200,
            "verbose": true
        }
        "#;

        let cfg: Config = serde_json::from_str(raw_json).unwrap();
        let params = cfg.as_params();
        // no read_banner set in config, the read banner parameters should
        // not be set on scan parameters even if they have value in
        // configuration
        assert!(params.read_banner_size.is_none() && params.read_banner_timeout.is_none());
    }

    #[test]
    fn test_cfg_as_scan_params_concurrent_hosts() {
        let raw_json = r#"
        {
            "target": "192.168.1.0/24",
            "ports": "1,2",
            "exclude": "192.168.1.1",
            "concurrent-scans": 600,
            "concurrent-hosts": 500,
            "timeout": 1000,
            "retry-on-error": true,
            "try-count": 3,
            "read-banner": true,
            "read-banner-size": 512,
            "read-banner-timeout": 1200,
            "verbose": true
        }
        "#;

        let cfg: Config = serde_json::from_str(raw_json).unwrap();

        let params = cfg.as_params();
        assert_eq!(params.concurrent_hosts, 500);
        assert_eq!(params.concurrent_scans, 600);
    }

    #[test]
    fn test_config_with_defaults() {
        let cfg = Config {
            target: Default::default(),
            exclude: Default::default(),
            ports: None,
            concurrent_scans: None,
            concurrent_hosts: None,
            timeout: None,
            json: None,
            retry_on_error: None,
            try_count: None,
            read_banner: None,
            read_banner_size: None,
            read_banner_timeout: None,
            verbose: None,
        };

        let empty_cmdline: Vec<&str> = Vec::new();

        let m = build_commandline_args()
            .no_binary_name(true)
            .get_matches_from(&empty_cmdline);

        let mut new_cfg = cfg.override_with(&m).unwrap();
        // when no command line options are given and configuration is empty
        // we should set the default values for fields we have sane defaults
        assert!(new_cfg.ports.is_some());
        assert!(new_cfg.concurrent_scans.is_some());
        assert!(new_cfg.timeout.is_some());
        assert!(new_cfg.retry_on_error.is_some());
        assert!(new_cfg.try_count.is_some());
        assert!(new_cfg.read_banner.is_some());
        assert!(new_cfg.read_banner_size.is_some());
        assert!(new_cfg.read_banner_timeout.is_some());
        assert!(new_cfg.verbose.is_some());

        // no values should be set for fields we have no proper defaults for
        assert!(new_cfg.target.is_empty());
        assert!(new_cfg.json.is_none());
        assert!(new_cfg.exclude.is_empty());

        // verify should return errors
        assert!(new_cfg.verify().is_err());

        new_cfg.target = parse_addresses("192.168.1.1").unwrap();
        // .. and now the configuration should be ok
        assert!(new_cfg.verify().is_ok());
        assert!(new_cfg.get_range().is_some());
        assert!(new_cfg.concurrent_hosts.is_none())
    }

    #[test]
    fn test_minimal_config() {
        let raw_json = r#"
        {
            "target": "192.168.1.1"
        }
        "#;

        let cfg: Config = serde_json::from_str(raw_json).unwrap();

        // we need to parse empty command line to set the
        // defaults with override_with()

        let app = build_commandline_args().no_binary_name(true);
        let vec: Vec<String> = vec![];
        let m = app.get_matches_from(vec);

        let cfg2 = cfg.override_with(&m).unwrap();

        assert!(cfg2.verify().is_ok(), "verify not ok {:?}", cfg2.verify());

        assert!(cfg2.get_range().is_some());
    }
}
