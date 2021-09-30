#[macro_use]
extern crate log;

use async_std::channel::Receiver;
use async_std::net::IpAddr;
use async_std::prelude::*;
use async_std::task::Builder;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook_async_std::Signals;
use std::sync::{atomic::AtomicBool, Arc};

use std::collections::HashMap;
use std::convert::TryFrom;

mod config;
mod output;
mod ports;
mod range;
mod scanner;
mod tools;

async fn collect_results(rx: Receiver<scanner::ScanResult>) -> Vec<output::HostInfo> {
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
            scanner::PortState::Timeout(_) => info.add_filtered_port(res.port),
            scanner::PortState::HostDown() => info.mark_down(),
            scanner::PortState::NetError() => info.mark_down(),
        }
    }
    trace!("Collector stopping");
    return host_infos.drain().map(|(_, v)| v).collect();
}

async fn output_results(
    infos: &[output::HostInfo],
    output_file: Option<String>,
) -> Result<(), async_std::io::Error> {
    if let Some(fname) = output_file {
        let opens: Vec<&output::HostInfo> = infos
            .iter()
            .filter(|h| !h.is_down() && h.open_port_count() > 0)
            .collect();
        output::write_json_into(&fname, opens).await
    } else {
        output::write_results_to_stdout(infos)
    }
}

fn exit_error(message: Option<String>) -> ! {
    let mut code = 0;
    if let Some(msg) = message {
        error!("{}", msg);
        code = 127;
    }

    std::process::exit(code);
}

async fn sighandler(signals: Signals, flag: Arc<AtomicBool>) {
    let mut s = signals.fuse();

    while let Some(sig) = s.next().await {
        match sig {
            SIGINT | SIGTERM => {
                debug!("Received termination signal, setting flag");
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            _ => warn!("Received unexpected signal"),
        }
    }
}

#[async_std::main]
async fn main() {
    env_logger::init();

    let app = clap::App::new("Simple port scanner")
        .version("0.0.1")
        .about("Scans ports")
        .arg(
            clap::Arg::with_name(config::ARG_TARGET_NAME)
                .long("target")
                .short("t")
                .takes_value(true)
                .required(false)
                .help("Address(es) of the host(s) to scan, IP addresses, or CIDRs separated by comma"),
        )
        .arg(
            clap::Arg::with_name(config::ARG_EXCLUDE_NAME)
                .long("exclude")
                .short("e")
                .takes_value(true)
                .required(false)
                .help("Comma -separated list of addresses to exclude from scanning")
        )
        .arg(
            clap::Arg::with_name(config::ARG_PORTS_NAME)
                .long("ports")
                .short("p")
                .takes_value(true)
                .required(false)
                .default_value("1-100")
                .help("Ports to scan"),
        )
        .arg(
            clap::Arg::with_name(config::ARG_CONCURRENT_SCANS_NAME)
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
            clap::Arg::with_name(config::ARG_TIMEOUT_NAME)
                .long("timeout")
                .short("T")
                .takes_value(true)
                .default_value("1000")
                .required(false)
                .help("Timeout in ms to wait for response before determening port as closed/firewalled")
        )
        .arg(clap::Arg::with_name(config::ARG_JSON_NAME)
            .long("json")
            .short("j")
            .takes_value(true)
            .required(false)
            .help("Write output as JSON into given file, - to write to stdout")
        )
        .arg(clap::Arg::with_name(config::ARG_CONFIG_FILE_NAME)
            .long("config")
            .short("C")
            .takes_value(true)
            .required(false)
            .help("Read configuration from given JSON file")
        )
        .arg(clap::Arg::with_name(config::ARG_RETRY_ON_ERROR_NAME)
            .long("retry-on-error")
            .short("R")
            .takes_value(false)
            .required(false)
            .help("Retry scan a few times on (possible transient) network error")
        ).arg(clap::Arg::with_name(config::ARG_TRY_COUNT)
            .long("try-count")
            .short("r")
            .takes_value(true)
            .required(false)
            .default_value("2")
            .help("Number of times to try a port which receives no response (including the initial try)")
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

    let adaptive_timeout_enabled = matches.is_present("adaptive-timeout");

    let cfg_from_file = if matches.is_present(config::ARG_CONFIG_FILE_NAME) {
        // First load configuration from given file
        match config::Config::from_json_file(
            matches.value_of(config::ARG_CONFIG_FILE_NAME).unwrap(),
        ) {
            Ok(c) => Some(c),
            Err(e) => exit_error(Some(format!("Error while reading configuration: {}", e))),
        }
    } else {
        None
    };

    let mut cfg = if let Some(cf) = cfg_from_file {
        match cf.override_with(&matches) {
            Err(e) => exit_error(Some(format!("Configuration error: {}", e))),
            Ok(c) => c,
        }
    } else {
        match config::Config::try_from(matches) {
            Err(e) => exit_error(Some(format!("Configuration error: {}", e))),
            Ok(c) => c,
        }
    };

    // make sure configuration is good
    if let Err(e) = cfg.verify() {
        exit_error(Some(format!("Configuration error: {}", e)))
    }

    let mut params: scanner::ScanParameters = cfg.as_params();
    if adaptive_timeout_enabled {
        params.enable_adaptive_timing = true;
    }

    if params.retry_on_error {
        info!("Retry on error set")
    }

    let (tx, rx) = async_std::channel::bounded(10);

    let signals = match Signals::new(&[SIGINT, SIGTERM]) {
        Ok(h) => h,
        Err(e) => exit_error(Some(format!("Unable to register signal handler: {}", e))),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let handle = signals.handle();

    let sig_h = async_std::task::spawn(sighandler(signals, Arc::clone(&stop)));

    if let Ok(col) = Builder::new()
        .name("collector".to_owned())
        .spawn(collect_results(rx))
    {
        let scan = scanner::Scanner::create(params, stop.clone());
        let (infos, _) = col
            .join(scan.scan(
                range::ScanRange::create(&cfg.target(), &cfg.exludes(), cfg.ports()),
                tx,
            ))
            .await;
        // print resuts now that scan is complete
        if let Err(er) = output_results(&infos, cfg.json()).await {
            error!("Unable to output results: {}", er);
        }
    } else {
        error!("Could not spawn scanner")
    }
    handle.close();
    debug!(
        "Waiting for sighandler task, stop is {}",
        stop.load(std::sync::atomic::Ordering::SeqCst)
    );
    sig_h.await;
    if stop.load(std::sync::atomic::Ordering::SeqCst) {
        std::process::exit(2);
    }
    std::process::exit(0);
}
