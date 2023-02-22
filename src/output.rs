use serde::ser::SerializeMap;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::fmt::{self, Display};
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Message field value for scan complete
const JSON_MESSAGE_SCAN_COMPLETE: &str = "scan_complete";

/// Information about single scanned host
#[derive(Serialize)]
pub struct HostInfo {
    #[serde(rename(serialize = "host"))]
    address: IpAddr, // address for the host
    #[serde(rename(serialize = "open_ports"))]
    open_ports: Vec<u16>, // ports found to be open
    #[serde(rename(serialize = "closed"))]
    closed_count: u32, // number of closed ports
    #[serde(rename(serialize = "filtered"))]
    filtered_count: u32, // number of filtered ports, that is, ports not responding
    #[serde(skip)]
    down: bool, // true if host was determined to be down
    #[serde(skip)]
    min_delay: Option<Duration>, // minumum time for response, if any
    #[serde(skip)]
    max_delay: Option<Duration>, // maximum time for responses, if any
    banners: Banners, // banners read from open ports
}

/// Container for banners read from open ports
#[derive(Default)]
struct Banners {
    values: HashMap<u16, Vec<u8>>,
}

impl Display for Banners {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = String::new();
        builder.push_str("\n\t Banners received from open ports:\n");
        for (port, b) in &self.values {
            let _ = match std::str::from_utf8(b) {
                Ok(s) => write!(builder, "\t\tPort: {} \"{}\"", port, s),
                Err(_e) => write!(builder, "\t\tPort: {}: {} bytes of data", port, b.len()),
            };
        }
        write!(f, "{}", builder)
    }
}

impl Serialize for Banners {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.values.len()))?;
        for (k, v) in &self.values {
            let serialized_k = k.to_string();
            let serialized_data = base64::encode(v);
            map.serialize_entry(&serialized_k, &serialized_data)?;
        }
        map.end()
    }
}

impl Banners {
    /// Returns true if there are no banners collected
    fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl HostInfo {
    /// Create new empty `HostInfo` for given address
    pub fn create(addr: IpAddr) -> Self {
        HostInfo {
            address: addr,
            open_ports: Vec::new(),
            down: false,
            closed_count: 0,
            filtered_count: 0,
            min_delay: None,
            max_delay: None,
            banners: Default::default(),
        }
    }

    /// Add new open port
    pub fn add_open_port(&mut self, port: u16) {
        self.open_ports.push(port);
    }

    /// Add new closed port
    pub fn add_closed_port(&mut self, _port: u16) {
        self.closed_count += 1;
    }

    /// Add new filtered port
    pub fn add_filtered_port(&mut self, _port: u16) {
        self.filtered_count += 1;
    }

    /// Mark to host as being down
    pub fn mark_down(&mut self) {
        self.down = true
    }

    /// Check if host has been marked down
    pub fn is_down(&self) -> bool {
        self.down
    }

    /// Add a recived banner for given port.
    pub fn add_banner(&mut self, port: u16, banner: Vec<u8>) {
        self.banners.values.insert(port, banner);
    }

    /// Get number of ports reported open
    pub fn open_port_count(&self) -> usize {
        self.open_ports.len()
    }

    /// Add delay information. That is, time it took to get a response from host.
    pub fn add_delay(&mut self, delay: Duration) {
        if let Some(d) = self.min_delay {
            if delay < d {
                self.min_delay = Some(delay)
            }
        } else {
            self.min_delay = Some(delay)
        }
        if let Some(d) = self.max_delay {
            if delay > d {
                self.max_delay = Some(delay)
            }
        } else {
            self.max_delay = Some(delay)
        }
    }

    /// Get delay information, (min, max), for this host
    pub fn get_delays(&self) -> (Duration, Duration) {
        (
            self.min_delay.unwrap_or_else(|| Duration::from_secs(0)),
            self.max_delay.unwrap_or_else(|| Duration::from_secs(0)),
        )
    }
}

impl fmt::Display for HostInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut pstr = String::new();
        let status = {
            if self.down {
                "Down"
            } else {
                "Up"
            }
        };
        let _ = write!(
            pstr,
            "{} is {} \n\t{} Open Ports:",
            self.address,
            status,
            self.open_ports.len()
        );
        for port in &self.open_ports {
            let _ = write!(pstr, " {}", port);
        }
        let _ = write!(
            pstr,
            "\n\t{} ports closed and {} filtered",
            self.closed_count, self.filtered_count
        );
        let delays = self.get_delays();
        let _ = write!(
            pstr,
            " (delays: min {}ms, max {}ms)",
            delays.0.as_millis(),
            delays.1.as_millis()
        );

        if !self.banners.is_empty() {
            pstr.push_str(&self.banners.to_string());
        }
        write!(f, "{}", pstr)
    }
}
/// `ScanComplete` information to print as JSON. Contains the results of
/// a scan.
#[derive(Serialize)]
struct ScanComplete<'a> {
    message: &'a str,
    number_of_hosts: usize,
    number_of_ports: usize,
    results: &'a [&'a HostInfo],
}

/// Write given information as JSON to a file with name `fname`.
/// `number_of_hosts` and `number_of_ports` should be the count of hosts
/// and the total number of ports scanned on each.
pub async fn write_json_into(
    fname: &str,
    number_of_hosts: usize,
    number_of_ports: usize,
    info: Vec<&HostInfo>,
) -> Result<(), tokio::io::Error> {
    let complete = ScanComplete {
        number_of_hosts,
        number_of_ports,
        message: JSON_MESSAGE_SCAN_COMPLETE,
        results: &info,
    };

    let mut output_data = serde_json::to_string(&complete)?;
    output_data.push('\n');
    let mut wr: Pin<Box<dyn AsyncWrite>> = if fname.trim() == "-" {
        Box::pin(tokio::io::stdout())
    } else {
        Box::pin(tokio::fs::File::create(fname).await?)
    };
    wr.write_all(output_data.as_bytes()).await?;
    wr.flush().await?;

    Ok(())
}

/// Write given rerults to stdout in human readable form.
/// `number_of_hosts` and `number_of_ports` should be the count of hosts
/// and the total number of ports scanned on each.
pub fn write_results_to_stdout(
    number_of_hosts: usize,
    number_of_ports: usize,
    infos: &[HostInfo],
) -> Result<(), tokio::io::Error> {
    print!("Scan complete:\n ");
    let mut number_of_down_hosts = 0;
    let mut number_of_silent_hosts = 0;
    for info in infos {
        if info.is_down() {
            number_of_down_hosts += 1;
            continue;
        } else if info.open_port_count() == 0 {
            number_of_silent_hosts += 1;
            continue;
        }
        println!("{}\n", info);
    }
    println!(
        "{} ports on {} hosts scanned, {} hosts did not have open ports, {} hosts reported down by OS",
        number_of_ports, number_of_hosts, number_of_silent_hosts, number_of_down_hosts
    );
    Ok(())
}

/// Write human readable informaiton about single scanned host. Used in
/// verbose mode to print information to user.
pub fn write_single_host_info(info: &HostInfo) {
    if info.down {
        println!("{}: down", info.address)
    } else if info.open_port_count() == 0 {
        println!("{}: no open ports", info.address)
    } else {
        println!("{}", info)
    }
}
