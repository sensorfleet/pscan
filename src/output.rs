use async_std::fs::File;
use async_std::prelude::*;
use serde::Serialize;
use std::fmt;
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
