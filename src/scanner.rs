use async_std::channel::Sender;
use async_std::future;
use async_std::io::ErrorKind;
use async_std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use async_std::sync::Arc;
use async_std::task::{self, JoinHandle};
use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use std::{fmt, sync::atomic::AtomicBool};

use crate::ports::PortIterator;
use crate::range::{HostIterator, ScanRange};
use crate::tools::{SemHandle, Semaphore};

// OS -specific error codes for error conditions
#[cfg(target_os = "macos")]
mod os_errcodes {
    pub(crate) static OS_ERR_HOST_DOWN: i32 = 64;
    pub(crate) static OS_ERR_NET_UNREACH: i32 = 51;
}
#[cfg(target_os = "linux")]
mod os_errcodes {
    pub(crate) static OS_ERR_HOST_DOWN: i32 = 113;
    pub(crate) static OS_ERR_NET_UNREACH: i32 = 101;
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod os_errcodes {
    pub(crate) static OS_ERR_HOST_DOWN: i32 = -999;
    pub(crate) static OS_ERR_NET_UNREACH: i32 = 999;
}

static DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_millis(2000);

static MAX_STRIPE_LEN: u16 = 100;

// Detected state of a port
pub enum PortState {
    Open(Duration),        // port is open
    Closed(Duration),      // port is closed
    ConnTimeout(Duration), // TCP connection timeout occurred
    CallTImeout(Duration), // connection was aborted due our timeout
    HostDown(),            // Remote host is likely down
    Retry(),
}

// Scanning error
enum ScanError {
    Down(String), // Host was detected to be down
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Down(msg) => write!(f, "{}", msg),
        }
    }
}
// Scanning result for single host/port
pub struct ScanResult {
    pub address: IpAddr,
    pub port: u16,
    pub state: PortState,
}

// Handle OtherError returned by Connect.
// Try to detect at least if host is down.
fn handle_other_error(
    e: std::io::Error,
    connection_time: Duration,
) -> Result<PortState, ScanError> {
    e.raw_os_error()
        .map_or(Ok(PortState::Closed(connection_time)), |n| {
            if n == os_errcodes::OS_ERR_HOST_DOWN {
                Ok(PortState::HostDown())
            } else if n == os_errcodes::OS_ERR_NET_UNREACH {
                Ok(PortState::Retry())
            } else {
                debug!("Connect returned error code: {} (kind {:?})", n, e.kind());
                Ok(PortState::Closed(connection_time))
            }
        })
}

// try to connect to given SockerAddr.
// Returns Ok(PortState) if a state of port could be determined, Err(ScanError)
// if error occurred while scanning.
async fn try_port(sa: SocketAddr, conn_timeout: Duration) -> Result<PortState, ScanError> {
    trace!("Trying {}", sa);
    let start = Instant::now();
    let res = future::timeout(conn_timeout, TcpStream::connect(sa)).await;
    let c = match res {
        Ok(v) => v,
        Err(_) => {
            trace!("Connection timed out");
            return Ok(PortState::CallTImeout(start.elapsed()));
        }
    };
    let c_time = start.elapsed();

    trace!("connect() took {}ms", c_time.as_millis());

    match c {
        Ok(s) => {
            info!("port {} Connection succesfull", sa.port());
            // if let Err(e) = s.write_all("FOO".as_bytes()).await {
            //     warn!("Could not write: {}", e)
            // } else {
            //     warn!("Was able to write")
            // }
            if let Err(e) = s.shutdown(Shutdown::Both) {
                warn!("Unable to shutdown connection: {}", e)
            }
            info!("Connection took {}ms", start.elapsed().as_millis());
            Ok(PortState::Open(start.elapsed()))
        }
        Err(e) => {
            trace!("Connection failed: {}", e);
            match e.kind() {
                ErrorKind::TimedOut => Ok(PortState::ConnTimeout(c_time)),
                ErrorKind::ConnectionRefused => Ok(PortState::Closed(c_time)),
                _ => handle_other_error(e, c_time),
            }
        }
    }
}

#[derive(Copy, Clone)]
// available scans we can perform.
// In future, there is hopefully more than one.
pub enum ScanType {
    Tcp,
}

// minimum timeout value to report for adaptive timeout
static MIN_TIMEOUT: Duration = Duration::from_millis(25);

impl ScanType {
    // Scan for single port in given host. Result will be sent
    // using `tx` Sender. `conn_timeout` will indicate how long to wait
    // for response.
    async fn cycle(
        &self,
        sa: SocketAddr,
        tx: Arc<Sender<ScanResult>>,
        conn_timeout: Duration,
        retry_on_error: bool,
    ) -> Result<Duration, ScanError> {
        let mut retry_count: i32 = 0;
        loop {
            let state = match self {
                ScanType::Tcp => try_port(sa, conn_timeout).await?,
            };
            let next_timeout_guess = match state {
                PortState::Open(d) | PortState::Closed(d) => {
                    // We have actual connection to the host
                    // Use the duration from that connection as best assumption
                    // of RTT and adjust the connection timeout with that
                    trace!("RTT from last actual connect {}ms", d.as_millis());
                    if d * 5 < MIN_TIMEOUT {
                        Some(MIN_TIMEOUT)
                    } else {
                        Some(d * 5)
                    }
                }
                PortState::ConnTimeout(d) => {
                    // TCP connection timeout, the stack gave up, this is as
                    // much we should wait in any case.
                    debug!("TCP connection timeout in {}ms", d.as_millis());
                    Some(d)
                }
                PortState::CallTImeout(d) => {
                    // we hit our own timeout, can not make adjustments
                    trace!("Own timeout hit in {}ms", d.as_millis());
                    Some(conn_timeout)
                }
                PortState::HostDown() => {
                    info!("Remote host is down");
                    if let Err(e) = tx
                        .send(ScanResult {
                            address: sa.ip(),
                            port: 0,
                            state: PortState::HostDown(),
                        })
                        .await
                    {
                        warn!("Result channel closed! ({})", e)
                    }
                    return Err(ScanError::Down(format!("Host {} is down", sa.ip())));
                }
                PortState::Retry() => None,
            };
            if next_timeout_guess.is_none() {
                if !retry_on_error {
                    return Err(ScanError::Down(format!(
                        "Host {} could not be connected",
                        sa.ip()
                    )));
                }
                retry_count = retry_count + 1;
                if retry_count > 5 {
                    info!("Host {} retried enough", sa.ip());
                    return Err(ScanError::Down(format!(
                        "Host {} retried {} times",
                        sa.ip(),
                        retry_count
                    )));
                }
                info!("waiting 500ms before next retry (count {})", retry_count);
                task::sleep(Duration::from_millis(500)).await;
                continue;
            }
            if let Err(_e) = tx
                .send(ScanResult {
                    address: sa.ip(),
                    port: sa.port(),
                    state,
                })
                .await
            {
                warn!("Result channel closed!")
            }
            return Ok(next_timeout_guess.unwrap());
        }
    }
}
// parameters for whole scan operation
#[derive(Clone, Copy)]
pub struct ScanParameters {
    pub wait_timeout: Duration,       // Duration to wait for responses
    pub concurrent_scans: usize,      // number of concurrent tasks to run
    pub enable_adaptive_timing: bool, // should adaptive timeout be used
    pub retry_on_error: bool,         // should we retry on network error
}

impl Default for ScanParameters {
    fn default() -> Self {
        ScanParameters {
            wait_timeout: DEFAULT_CONNECTION_TIMEOUT,
            concurrent_scans: 100,
            enable_adaptive_timing: false,
            retry_on_error: false,
        }
    }
}

pub struct Scanner {
    sem: Semaphore,
    r#type: ScanType,
    params: ScanParameters,
    stop: Arc<AtomicBool>,
}

impl Scanner {
    pub fn create(params: ScanParameters, stop: Arc<AtomicBool>) -> Scanner {
        Scanner {
            sem: Semaphore::new(params.concurrent_scans),
            r#type: ScanType::Tcp,
            params,
            stop,
        }
    }

    pub async fn scan(self, range: ScanRange<'_>, tx: Sender<ScanResult>) {
        let ports_per_thread = u16::max(
            range.get_port_count() / self.params.concurrent_scans as u16,
            1,
        )
        .min(MAX_STRIPE_LEN);
        let atx = Arc::new(tx);
        debug!("Scanning with {} ports per stripe", ports_per_thread);

        let mut waiters = FuturesUnordered::new();
        for mut hostit in range.hosts() {
            hostit.ports.adjust_step(ports_per_thread);
            if self.stop.load(std::sync::atomic::Ordering::SeqCst) {
                warn!("Stopping hostloop due to signal");
                break;
            }
            let h = self.scan_host(hostit, atx.clone()).await;
            waiters.push(task::spawn(h.wait()))
        }
        // all host tasks have been spawned
        debug!("Waiting for all hosts to complete");
        while let Some(()) = waiters.next().await {}
    }

    async fn scan_host(&self, host: HostIterator, tx: Arc<Sender<ScanResult>>) -> Host {
        debug!("Starting to scan host {}", host.host);
        let tasks = FuturesUnordered::new();
        let ctx = HostContext {
            up: Arc::new(AtomicBool::new(true)),
            stop_signal: self.stop.clone(),
            tx: tx.clone(),
        };

        for stripe in host.ports {
            // this is the gatekeeper making sure we do not start too many
            // concurrent tasks
            let semh = self.sem.wait().await;
            if !ctx.keep_running() {
                // host down, no need to continue further
                break;
            }
            let handle = task::spawn(scan_port_stripe(
                host.host,
                stripe,
                self.r#type,
                self.params,
                semh,
                ctx.clone(),
            ));
            tasks.push(handle);
        }
        return Host {
            addr: host.host,
            tasks,
            _context: ctx,
        };
    }
}

#[derive(Clone)]
struct HostContext {
    up: Arc<AtomicBool>,
    stop_signal: Arc<AtomicBool>,
    tx: Arc<Sender<ScanResult>>,
    // max_timeout: Duration,
}

impl HostContext {
    fn keep_running(&self) -> bool {
        return self
            .up
            .fetch_and(!self.stop_signal.load(Ordering::SeqCst), Ordering::SeqCst);
    }

    fn host_down(&self) {
        self.up.store(false, Ordering::SeqCst);
    }
}

struct Host {
    addr: IpAddr,
    tasks: FuturesUnordered<JoinHandle<()>>,
    _context: HostContext,
}

impl Host {
    async fn wait(mut self) {
        while let Some(()) = self.tasks.next().await {}
        info!("Host {} scan complete", self.addr);
    }
}

async fn scan_port_stripe(
    addr: IpAddr,
    stripe: PortIterator,
    typ: ScanType,
    params: ScanParameters,
    sem: SemHandle,
    ctx: HostContext,
) {
    debug!("Starting stripe {:?} for {}", stripe, addr);
    for p in stripe {
        if !ctx.keep_running() {
            break;
        }
        let sa = SocketAddr::new(addr, p);
        match typ
            .cycle(
                sa,
                ctx.tx.clone(),
                params.wait_timeout,
                params.retry_on_error,
            )
            .await
        {
            Ok(_) => {}
            Err(e) => {
                warn!("Terminating stripe for {} due to error: {}", addr, e);
                ctx.host_down();
                break;
            }
        }
    }
    sem.signal();
    trace!("stripe complete for {}", addr)
}
