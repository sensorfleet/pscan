use async_std::fs::File;
use async_std::prelude::*;
use serde::ser::SerializeMap;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::{self, Display};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Serialize)]
pub struct HostInfo {
    #[serde(rename(serialize = "host"))]
    address: IpAddr,
    #[serde(rename(serialize = "open_ports"))]
    open_ports: Vec<u16>,
    #[serde(rename(serialize = "closed"))]
    closed_count: u32,
    #[serde(rename(serialize = "filtered"))]
    filtered_count: u32,
    #[serde(skip)]
    down: bool,
    #[serde(skip)]
    min_delay: Option<Duration>,
    #[serde(skip)]
    max_delay: Option<Duration>,
    banners: Option<Banners>,
}

struct Banners {
    values: HashMap<u16, Vec<u8>>,
}

impl Display for Banners {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = String::new();
        builder.push_str("\n\t Banners received from open ports:\n");
        for (port, b) in &self.values {
            match std::str::from_utf8(b) {
                Ok(s) => builder.push_str(&format!("\t\tPort: {} \"{}\"", port, s)),
                Err(_e) => {
                    builder.push_str(&format!("\t\tPort: {}: {} bytes of data", port, b.len()))
                }
            }
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

impl Default for Banners {
    fn default() -> Self {
        Self {
            values: Default::default(),
        }
    }
}

impl HostInfo {
    pub fn create(addr: IpAddr) -> Self {
        HostInfo {
            address: addr,
            open_ports: Vec::new(),
            down: false,
            closed_count: 0,
            filtered_count: 0,
            min_delay: None,
            max_delay: None,
            banners: None,
        }
    }

    pub fn add_open_port(&mut self, port: u16) {
        self.open_ports.push(port)
    }

    pub fn add_closed_port(&mut self, _port: u16) {
        self.closed_count += 1;
    }

    pub fn add_filtered_port(&mut self, _port: u16) {
        self.filtered_count += 1;
    }

    pub fn mark_down(&mut self) {
        self.down = true
    }

    pub fn is_down(&self) -> bool {
        self.down
    }

    pub fn add_banner(&mut self, port: u16, banner: Vec<u8>) {
        let b = self.banners.get_or_insert(Default::default());
        b.values.insert(port, banner);
    }

    pub fn open_port_count(&self) -> usize {
        self.open_ports.len()
    }

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
        pstr.push_str(&format!(
            "{} is {} \n\t{} Open Ports:",
            self.address,
            status,
            self.open_ports.len()
        ));
        for port in &self.open_ports {
            pstr.push_str(&format!(" {}", port))
        }
        pstr.push_str(&format!(
            "\n\t{} ports closed and {} filtered",
            self.closed_count, self.filtered_count
        ));
        let delays = self.get_delays();
        pstr.push_str(&format!(
            " (delays: min {}ms, max {}ms)",
            delays.0.as_millis(),
            delays.1.as_millis()
        ));

        if let Some(b) = &self.banners {
            pstr.push_str(&b.to_string());
        }
        write!(f, "{}", pstr)
    }
}

pub async fn write_json_into(
    fname: &str,
    info: Vec<&HostInfo>,
) -> Result<(), async_std::io::Error> {
    let mut output_data = serde_json::to_string(&info)?;
    output_data.push('\n');
    if fname.trim() == "-" {
        async_std::io::stdout()
            .write_all(output_data.as_bytes())
            .await?;
    } else {
        let mut f = File::create(fname).await?;
        f.write_all(output_data.as_bytes()).await?;
    }

    Ok(())
}

pub fn write_results_to_stdout(infos: &[HostInfo]) -> Result<(), async_std::io::Error> {
    print!("Scan complete:\n ");
    let mut down_hosts = 0;
    let mut no_open_ports = 0;
    for info in infos {
        if info.is_down() {
            down_hosts += 1;
            continue;
        } else if info.open_port_count() == 0 {
            no_open_ports += 1;
            continue;
        }
        println!("{}\n", info);
    }
    println!(
        "{} hosts scanned, {} hosts did not have open ports, {} hosts reported down by OS",
        infos.len(),
        no_open_ports,
        down_hosts
    );
    return Ok(());
}

pub fn write_single_host_info(info: &HostInfo) {
    if info.down {
        println!("{}: down", info.address)
    } else if info.open_port_count() == 0 {
        println!("{}: no open ports", info.address)
    } else {
        println!("{}", info)
    }
}
