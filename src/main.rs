#[macro_use]
extern crate log;

use async_std::net::IpAddr;
use async_std::prelude::*;
use async_std::sync;
use async_std::sync::Receiver;
use async_std::task::Builder;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::time::Duration;
mod output;
mod ports;
mod scanner;
mod tools;

async fn collect_results(rx: Receiver<scanner::ScanResult>, output_file: Option<String>) {
    let mut host_infos: HashMap<IpAddr, output::HostInfo> = HashMap::new();

    while let Ok(res) = rx.recv().await {
        let info = host_infos
            .entry(res.address)
            .or_insert_with(|| output::HostInfo::create(res.address));
        match res.state {
            scanner::PortState::Open(d) => {
                info.add_open_port(res.port);
                info.add_delay(d);
            }
            scanner::PortState::Closed(d) => {
                info.add_closed_port(res.port);
                info.add_delay(d);
            }
            scanner::PortState::ConnTimeout(_) | scanner::PortState::CallTImeout(_) => {
                info.add_filtered_port(res.port)
            }
            scanner::PortState::HostDown() => info.mark_down(),
        }
    }
    trace!("Collector stopping");

    if let Some(fname) = output_file {
        let opens: Vec<&output::HostInfo> = host_infos
            .values()
            .filter(|h| !h.is_down() && (h.open_port_count() > 0 || h.closed_port_count() > 0))
            // .filter(|h| !h.is_down())
            .collect();

        if let Err(e) = output::write_json_into(&fname, opens).await {
            println!("Unable to write JSON output: {}", e);
        }
    } else {
        print!("Scan complete:\n ");
        let mut down_hosts = 0;
        let mut no_open_ports = 0;
        for (_a, p) in &host_infos {
            if p.is_down() {
                down_hosts += 1;
                continue;
            } else if p.open_port_count() == 0 {
                no_open_ports += 1;
                continue;
            }
            println!("{}\n", p);
        }
        println!(
            "{} hosts scanned, {} hosts did not have open ports, {} hosts reported down by OS",
            host_infos.len(),
            no_open_ports,
            down_hosts
        );
    }
}

#[derive(Debug)]
enum ParamError {
    Message(String),
    IntError(std::num::ParseIntError),
    AddrError(cidr::NetworkParseError),
}

impl fmt::Display for ParamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParamError::Message(m) => write!(f, "{}", m),
            ParamError::IntError(e) => write!(f, "{}", e),
            ParamError::AddrError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ParamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParamError::Message(_) => None,
            ParamError::IntError(e) => Some(e),
            ParamError::AddrError(e) => Some(e),
        }
    }
}
impl From<std::num::ParseIntError> for ParamError {
    fn from(e: std::num::ParseIntError) -> Self {
        ParamError::IntError(e)
    }
}

impl From<cidr::NetworkParseError> for ParamError {
    fn from(e: cidr::NetworkParseError) -> Self {
        ParamError::AddrError(e)
    }
}

impl From<&str> for ParamError {
    fn from(m: &str) -> Self {
        ParamError::Message(m.to_owned())
    }
}

fn parse_addresses(val: &str) -> Result<Vec<cidr::IpCidr>, ParamError> {
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

fn exit_error(message: Option<String>) -> ! {
    let mut code = 0;
    if let Some(msg) = message {
        error!("{}", msg);
        code = 127;
    }

    std::process::exit(code);
}

#[async_std::main]
async fn main() {
    env_logger::init();

    let app = clap::App::new("Simple port scanner")
        .version("0.0.1")
        .about("Scans ports")
        .arg(
            clap::Arg::with_name("address")
                .long("target")
                .short("t")
                .takes_value(true)
                .required(true)
                .help("Address(es) of the host(s) to scan, IP addresses, or CIDRs separated by comma"),
        )
        .arg(
            clap::Arg::with_name("ports")
                .long("ports")
                .short("p")
                .takes_value(true)
                .required(false)
                .default_value("1-100")
                .help("Ports to scan"),
        )
        .arg(
            clap::Arg::with_name("batch-count")
                .long("concurrent-scans")
                .short("b")
                .takes_value(true)
                .required(false)
                .help("Number of concurrent scans to run")
                .default_value("100"),
        )
        .arg(
            clap::Arg::with_name("adaptive-timing")
                .long("enable-adaptive-timing")
                .short("A")
                .takes_value(false)
                .required(false)
                .help("Enable adaptive timing (adapt timeout based on detected connection delay)"),
        )
        .arg(
            clap::Arg::with_name("timeout")
                .long("timeout")
                .short("t")
                .takes_value(true)
                .default_value("1000")
                .required(false)
                .help("Timeout in ms to wait for response before determening port as closed/firewalled")
        )
        .arg(clap::Arg::with_name("json")
            .long("json")
            .short("j")
            .takes_value(true)
            .required(false)
            .help("Write output as JSON into given file, - to write to stdout")
        );

    let matches = match app.get_matches_safe() {
        Ok(m) => m,
        Err(e) => match e.kind {
            clap::ErrorKind::HelpDisplayed | clap::ErrorKind::VersionDisplayed => {
                println!("{}", e.message);
                exit_error(None);
            }
            _ => exit_error(Some(e.message)),
        },
    };

    let addr = match parse_addresses(matches.value_of("address").unwrap()) {
        Ok(a) => a,
        Err(p) => {
            exit_error(Some(format!("Unable to parse target address(es): {}", p)));
        }
    };

    let batch_count: usize = match matches.value_of("batch-count").unwrap().parse() {
        Ok(c) => c,
        Err(e) => {
            exit_error(Some(format!(
                "Unable to parse number of concurrent scans: {}",
                e
            )));
        }
    };

    let range = match ports::PortRange::try_from(matches.value_of("ports").unwrap()) {
        Ok(r) => r,
        Err(e) => {
            exit_error(Some(format!("Unable to parse port range: {}", e)));
        }
    };

    let timeout: u64 = match matches.value_of("timeout").unwrap().parse() {
        Ok(t) => t,
        Err(e) => {
            exit_error(Some(format!("Unable to parse timeout value: {}", e)));
        }
    };

    let output_file = matches.value_of("json").map(|s| s.to_owned());

    let mut params: scanner::ScanParameters = Default::default();
    params.concurrent_scans = batch_count;
    params.enable_adaptive_timing = matches.is_present("adaptive-timing");
    params.wait_timeout = Duration::from_millis(timeout);

    let (tx, rx) = sync::channel(10);
    if let Ok(col) = Builder::new()
        .name("collector".to_owned())
        .spawn(collect_results(rx, output_file))
    {
        let scan = scanner::Scanner::new(params);

        col.join(scan.scan(scanner::ScanRange::create(&addr, range), tx))
            .await;
    } else {
        error!("Could not spawn scanner")
    }
}
