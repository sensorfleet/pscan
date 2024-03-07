use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook_tokio::Signals;
use std::net::IpAddr;
use std::sync::{atomic::AtomicBool, Arc};
use tokio::sync::mpsc::UnboundedReceiver;

use futures::StreamExt;
use std::collections::HashMap;
use std::convert::TryFrom;

mod config;
mod output;
mod ports;
mod range;
mod scanner;

/// This function is run on its own task to collect the scan results.
/// Returns once the `Receiver` closes and returs the collected `HostInfo`.
async fn collect_results(
    mut rx: UnboundedReceiver<scanner::ScanInfo>,
    verbose: bool,
) -> Vec<output::HostInfo> {
    let mut host_infos: HashMap<IpAddr, output::HostInfo> = HashMap::new();

    while let Some(res) = rx.recv().await {
        match res {
            scanner::ScanInfo::PortStatus(status) => {
                let info = host_infos
                    .entry(status.address)
                    .or_insert_with(|| output::HostInfo::create(status.address));
                match status.state {
                    scanner::PortState::Open(d, banner) => {
                        info.add_open_port(status.port);
                        info.add_delay(d);
                        if let Some(value) = banner {
                            info.add_banner(status.port, value);
                        }
                    }
                    scanner::PortState::Closed(d) => {
                        info.add_closed_port(status.port);
                        info.add_delay(d);
                    }
                    scanner::PortState::Timeout(_) => info.add_filtered_port(status.port),
                    scanner::PortState::HostDown() => info.mark_down(),
                    scanner::PortState::NetError() => info.mark_down(),
                }
            }
            scanner::ScanInfo::HostScanned(addr) => {
                if verbose {
                    if let Some(info) = host_infos.get(&addr) {
                        output::write_single_host_info(info)
                    }
                }
            }
        }
    }
    tracing::trace!("Collector stopping");
    return host_infos.drain().map(|(_, v)| v).collect();
}

/// Print the results, if `output_file` is `None`, then information is printed
/// on command line, if it contains value, then information is printed as
/// JSON to a file.
async fn output_results(
    infos: &[output::HostInfo],
    number_of_ports: usize,
    output_file: Option<&str>,
) -> Result<(), tokio::io::Error> {
    let number_of_hosts = infos.len();
    if let Some(fname) = output_file {
        let opens: Vec<&output::HostInfo> = infos
            .iter()
            .filter(|h| !h.is_down() && h.open_port_count() > 0)
            .collect();
        output::write_json_into(fname, number_of_hosts, number_of_ports, opens).await
    } else {
        output::write_results_to_stdout(number_of_hosts, number_of_ports, infos)
    }
}

/// Exit the program with error code and optional error message.
fn exit_error(message: Option<String>) -> ! {
    let mut code = 0;
    if let Some(msg) = message {
        tracing::error!("{}", msg);
        code = 127;
    }

    std::process::exit(code);
}

/// Signal handler task, sets the given `flag` to true if signal is received
async fn sighandler(signals: Signals, flag: Arc<AtomicBool>) {
    let mut s = signals.fuse();

    while let Some(sig) = s.next().await {
        match sig {
            SIGINT | SIGTERM => {
                tracing::debug!("Received termination signal, setting flag");
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            _ => tracing::warn!("Received unexpected signal"),
        }
    }
}

#[tokio::main]
async fn main() {
    #[cfg(debug_assertions)]
    tracing_subscriber::fmt()
        .pretty()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    #[cfg(not(debug_assertions))]
    tracing_subscriber::fmt::init();

    let app = config::build_commandline_args();

    let matches = match app.try_get_matches() {
        Ok(m) => m,
        Err(e) => match e.kind() {
            clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                println!("{}", e);
                exit_error(None);
            }
            _ => exit_error(Some(e.to_string())),
        },
    };

    let cfg_from_file = if matches.contains_id(config::ARG_CONFIG_FILE) {
        // First load configuration from given file
        match config::Config::from_json_file(
            matches.get_one::<String>(config::ARG_CONFIG_FILE).unwrap(),
        ) {
            Ok(c) => Some(c),
            Err(e) => exit_error(Some(format!("Configuration error: {}", e))),
        }
    } else {
        None
    };

    let cfg = if let Some(cf) = cfg_from_file {
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

    let verbose = cfg.verbose();
    let params: scanner::ScanParameters = cfg.as_params();

    if params.retry_on_error {
        tracing::info!("Retry on error set")
    }

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    let signals = match Signals::new([SIGINT, SIGTERM]) {
        Ok(h) => h,
        Err(e) => exit_error(Some(format!("Unable to register signal handler: {}", e))),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let handle = signals.handle();

    let sig_h = tokio::task::spawn(sighandler(signals, Arc::clone(&stop)));

    let range = cfg.get_range().unwrap();
    let number_of_ports = range.get_port_count() as usize;

    let col = tokio::task::spawn(collect_results(rx, verbose));
    let scan = scanner::Scanner::create(params, stop.clone());
    let (col_result, scanstatus) = tokio::join!(col, scan.scan(range, tx));
    if let Err(e) = scanstatus {
        if e.is_fatal() {
            // fatal error, results can not be trusted.
            exit_error(Some(e.to_string()));
        } else {
            tracing::error!("Error while scanning: {}", e);
        }
    }
    match col_result {
        Ok(infos) => {
            // print results now that scan is complete
            if let Err(er) = output_results(&infos, number_of_ports, cfg.json()).await {
                tracing::error!("Unable to output results: {}", er);
            }
        }
        Err(error) => {
            exit_error(Some(error.to_string()));
        }
    };
    handle.close();
    tracing::debug!(
        "Waiting for sighandler task, stop is {}",
        stop.load(std::sync::atomic::Ordering::SeqCst)
    );
    if let Err(e) = sig_h.await {
        tracing::warn!("signal handler error: {}", e);
    }
    if stop.load(std::sync::atomic::Ordering::SeqCst) {
        std::process::exit(2);
    }
    std::process::exit(0);
}
