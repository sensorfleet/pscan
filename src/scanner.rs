use async_std::future;
use async_std::io::ErrorKind;
use async_std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use async_std::prelude::*;
use async_std::sync::Arc;
use async_std::sync::RwLock;
use async_std::sync::Sender;
use async_std::task;
use cidr::{Cidr, IpCidr};
use std::fmt;
use std::iter::Iterator;
use std::time::{Duration, Instant};

use crate::ports::{PortIterator, PortRange};
use crate::tools;

// OS -specific error codes for error conditions
#[cfg(target_os = "macos")]
static OS_ERR_HOST_DOWN: i32 = 64;
#[cfg(target_os = "linux")]
static OS_ERR_HOST_DOWN: i32 = 113;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
static OS_ERR_HOST_DOWN: i32 = -999;

static DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_millis(2000);

// Detected state of a port
pub enum PortState {
    Open(Duration),        // port is open
    Closed(Duration),      // port is closed
    ConnTimeout(Duration), // TCP connection timeout occurred
    CallTImeout(Duration), // connection was aborted due our timeout
    HostDown(),            // Remote host is likely down
}

// Timeout keeps track of timeouts for connections.
// it can be updated if connection was established or if it was rejected.
// this allows to tune further timeouts.
// Information will be kept for a given host for some range of ports.
struct Timeout {
    // current value
    val: Duration,
    // for calculating average
    sum: u64,
    count: u64,
    // will be set to false if we think host is down
    up: bool,
}

impl Timeout {
    // Create new timeout with given timeout value
    fn new(default: Duration) -> Self {
        Timeout {
            val: default,
            sum: 0,
            count: 0,
            up: true,
        }
    }

    // update timeout with new detected timeout value
    fn set(&mut self, val: Duration) {
        self.sum += val.as_millis() as u64;
        self.count += 1;
        self.val = Duration::from_millis(self.sum / self.count);
        info!("Adaptive timeout updated to {}ms", self.val.as_millis());
    }

    // get the current timeout value
    fn get(&self) -> Option<Duration> {
        if !self.up {
            None
        } else {
            Some(self.val)
        }
    }

    // mark the host to be down
    fn mark_down(&mut self) {
        self.up = false
    }
}

// RangeItem represents a host and range of ports to scan
struct RangeItem {
    addr: IpAddr,                  // host we are scanning
    range: PortRange,              // range of ports to scan
    timeout: Arc<RwLock<Timeout>>, // adaptive timeout value for this scan
}

// ScanRange contains information about all hosts and ports we are about to scan
pub struct ScanRange {
    items: Vec<RangeItem>, // hosts and ports in them to scan
    idx: usize,            // index of next item to scan
}

impl ScanRange {
    // Create range to scan from given set of IP addresses and port range
    pub fn create(addrs: &[IpCidr], range: PortRange) -> Self {
        let mut items = Vec::with_capacity(addrs.len());
        for a in addrs {
            for addrit in a.iter() {
                items.push(RangeItem {
                    addr: addrit,
                    range: range.clone(),
                    timeout: Arc::new(RwLock::new(Timeout::new(DEFAULT_CONNECTION_TIMEOUT))),
                })
            }
        }
        ScanRange { items, idx: 0 }
    }

    // set the number of concurrent scans we plan to run.
    // This allows us to tune the number of ports to scan on each iteration
    fn concurrent_scans(&mut self, scans: u16) {
        // XXX assumes same range of ports are to be scanned for each host.
        // this is true for now
        let port_count = self.items[0].range.port_count() as u16;
        let ppt = port_count / scans;
        let step = {
            if ppt < 1 {
                1
            } else {
                self.items[0].range.get_step().min(ppt)
            }
        };
        info!(
            "Running with {} concurrent scans, {} ports per iteration",
            scans, step,
        );

        for it in self.items.iter_mut() {
            it.range.adjust_step(step);
        }
    }

    // set the default timeout for scans
    fn default_timeout(&mut self, default: Duration) {
        for it in self.items.iter_mut() {
            it.timeout = Arc::new(RwLock::new(Timeout::new(default)));
        }
    }
}

impl Iterator for ScanRange {
    type Item = ScanIter;

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.items.len() {
            if let Some(ctx) = self.items[self.idx].timeout.try_read() {
                // we can use try_read here, if we can not acquire the lock
                // the scan will not proceed anyway, this just speeds things up
                if !ctx.up {
                    self.idx += 1;
                    continue;
                }
            }
            if let Some(range) = self.items[self.idx].range.next() {
                return Some(ScanIter {
                    addr: self.items[self.idx].addr,
                    ports: range,
                    a_timeout: self.items[self.idx].timeout.clone(),
                });
            }
            self.idx += 1;
        }
        None
    }
}

// Iterator which returns SocketAddress to scan first.
// Allows also to tune the adaptive timeout for host being scanned.
pub struct ScanIter {
    addr: IpAddr,
    ports: PortIterator,
    a_timeout: Arc<RwLock<Timeout>>,
}

impl Iterator for ScanIter {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        match self.ports.next() {
            Some(port) => Some(SocketAddr::new(self.addr, port)),
            None => None,
        }
    }
}

impl ScanIter {
    // update timeout estimate
    async fn update_timeout(&mut self, to: Duration) {
        info!(
            "Updating timeout for {} with {}ms",
            self.addr,
            to.as_millis()
        );
        let mut l_timeout = self.a_timeout.write().await;
        l_timeout.set(to);
    }

    // get initial timeout value to use for this scan round
    async fn get_initial_timeout(&self) -> Option<Duration> {
        let l_timeout = self.a_timeout.read().await;
        l_timeout.get()
    }

    // indicate that the host was detected to be down
    async fn host_down(&mut self) {
        let mut l_ctx = self.a_timeout.write().await;
        l_ctx.mark_down();
    }
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
            if n == OS_ERR_HOST_DOWN {
                Ok(PortState::HostDown())
            } else {
                debug!("Connect returned error code: {}", n);
                Ok(PortState::Closed(connection_time))
            }
        })
}

// try to connect to given SockerAddr.
// Returns Ok(PortState) if a state of port could be determined, Err(ScanError)
// if error occurred while scanning.
async fn try_port(sa: SocketAddr, conn_timeout: Duration) -> Result<PortState, ScanError> {
    debug!("Trying {}", sa);
    let start = Instant::now();
    let res = future::timeout(conn_timeout, TcpStream::connect(sa)).await;
    let c = match res {
        Ok(v) => v,
        Err(_) => {
            debug!("Connection timed out");
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
            debug!("Connection failed: {}", e);
            match e.kind() {
                ErrorKind::TimedOut => Ok(PortState::ConnTimeout(c_time)),
                ErrorKind::ConnectionRefused => Ok(PortState::Closed(c_time)),
                ErrorKind::Other => handle_other_error(e, c_time),
                _ => {
                    warn!(
                        "Connect returned error with Kind {:?}, errno {:?}",
                        e.kind(),
                        e.raw_os_error()
                    );
                    Ok(PortState::Closed(c_time))
                }
            }
        }
    }
}

#[derive(Copy, Clone)]
// available scans we can perform.
// In future, there is hopefully more than one.
pub enum ScanType {
    TCP,
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
    ) -> Result<Duration, ScanError> {
        let state = match self {
            ScanType::TCP => try_port(sa, conn_timeout).await?,
        };
        let next_timeout_guess = match state {
            PortState::Open(d) | PortState::Closed(d) => {
                // We have actual connection to the host
                // Use the duration from that connection as best assumption
                // of RTT and adjust the connection timeout with that
                debug!("RTT from last actual connect {}ms", d.as_millis());
                if d * 5 < MIN_TIMEOUT {
                    MIN_TIMEOUT
                } else {
                    d * 5
                }
            }
            PortState::ConnTimeout(d) => {
                // TCP connection timeout, the stack gave up, this is as
                // much we should wait in any case.
                debug!("TCP connection timeout in {}ms", d.as_millis());
                d
            }
            PortState::CallTImeout(d) => {
                // we hit our own timeout, can not make adjustments
                debug!("Own timeout hit in {}ms", d.as_millis());
                conn_timeout
            }
            PortState::HostDown() => {
                info!("Remote host is down");
                tx.send(ScanResult {
                    address: sa.ip(),
                    port: 0,
                    state: PortState::HostDown(),
                })
                .await;
                return Err(ScanError::Down(format!("Host {} is down", sa.ip())));
            }
        };
        tx.send(ScanResult {
            address: sa.ip(),
            port: sa.port(),
            state,
        })
        .await;
        Ok(next_timeout_guess)
    }
}

// parameters for whole scan operation
pub struct ScanParameters {
    pub wait_timeout: Duration,       // Duration to wait for responses
    pub concurrent_scans: usize,      // number of concurrent tasks to run
    pub enable_adaptive_timing: bool, // should adaptive timeout be used
}

impl Default for ScanParameters {
    fn default() -> Self {
        ScanParameters {
            wait_timeout: DEFAULT_CONNECTION_TIMEOUT,
            concurrent_scans: 100,
            enable_adaptive_timing: true,
        }
    }
}

// Scanner instance to run a scan
pub struct Scanner {
    sem: tools::Semaphore,  // semaphore to limit number of concurrent threads
    typ: ScanType,          // scan type
    params: ScanParameters, // parameters for scanning
}

impl Scanner {
    // create new scanner instance with given parameters
    pub fn new(params: ScanParameters) -> Self {
        Scanner {
            sem: tools::Semaphore::new(params.concurrent_scans),
            typ: ScanType::TCP,
            params,
        }
    }

    // Run a scan for given range of hosts and ports. Send results using
    // given sender.
    pub async fn scan(self, mut range: ScanRange, tx: Sender<ScanResult>) {
        let mut tasks = Vec::new();
        let atx = Arc::new(tx);
        range.concurrent_scans(self.params.concurrent_scans as u16);
        range.default_timeout(self.params.wait_timeout);

        for mut item in range {
            let h = self.sem.wait().await;

            let typ = self.typ;
            let tmp = atx.clone();
            // get the initial value for timeout to use
            let mut c_timeout = match item.get_initial_timeout().await {
                Some(d) => d,
                None => {
                    // Host is determined to be down, no need to scan
                    h.signal();
                    continue;
                }
            };
            let adaptive_timeout = self.params.enable_adaptive_timing;
            let handle = task::spawn(async move {
                let mut adjusted = false;
                for sa in &mut item {
                    match typ.cycle(sa, tmp.clone(), c_timeout).await {
                        Ok(adjusted_timeout) => {
                            if adaptive_timeout && adjusted_timeout != c_timeout {
                                c_timeout = adjusted_timeout;
                                adjusted = true;
                                trace!("Timeout adjusted to {}ms", c_timeout.as_millis());
                            }
                        }
                        Err(e) => match e {
                            ScanError::Down(msg) => {
                                warn!("Terminating loop due fatal error: {}", msg);
                                item.host_down().await;
                                break;
                            }
                        },
                    }
                }
                if adaptive_timeout && adjusted {
                    // contribute to the common timeout
                    item.update_timeout(c_timeout).await;
                }
                h.signal()
            });
            tasks.push(handle);
        }
        trace!("Spawned tasks, waiting for them to finish");
        for t in tasks {
            t.await;
        }
    }
}
