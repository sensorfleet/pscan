use async_std::channel::Sender;
use async_std::future;
use async_std::io::{ErrorKind, ReadExt};
use async_std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use async_std::sync::Arc;
use async_std::task::{self, JoinHandle};
use futures::stream::{FuturesUnordered, StreamExt};
use futures::Future;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use std::{fmt, sync::atomic::AtomicBool};

use crate::ports::PortIterator;
use crate::range::{HostIterator, ScanRange};
use crate::tools::{SemHandle, Semaphore};

// OS -specific error codes for error conditions
#[cfg(target_os = "macos")]
mod os_errcodes {
    pub(crate) const OS_ERR_HOST_DOWN: i32 = 64;
    pub(crate) const OS_ERR_NET_UNREACH: i32 = 51;
    pub(crate) const OS_ERR_TOO_MANY_FILES: i32 = 24;
}
#[cfg(target_os = "linux")]
mod os_errcodes {
    pub(crate) const OS_ERR_HOST_DOWN: i32 = 113;
    pub(crate) const OS_ERR_NET_UNREACH: i32 = 101;
    pub(crate) const OS_ERR_TOO_MANY_FILES: i32 = 24;
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod os_errcodes {
    pub(crate) const OS_ERR_HOST_DOWN: i32 = -999;
    pub(crate) const OS_ERR_NET_UNREACH: i32 = 999;
    pub(crate) const OS_ERR_TOO_MANY_FILES: i32 = 24;
}

static DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_millis(2000);

static MAX_STRIPE_LEN: u16 = 100;

// Detected state of a port
pub enum PortState {
    Open(Duration, Option<Vec<u8>>), // port is open, contains banner if we did read any
    Closed(Duration),                // port is closed
    Timeout(Duration),               // Did not get response withint timeout
    HostDown(),                      // Host was reported unreachable by OS
    NetError(),                      // Host could not be connected due network error
}

// Scanning error
#[derive(Clone)]
pub enum ScanError {
    Down(String), // Host was detected to be down
    TooManyFiles(),
}

impl ScanError {
    pub fn is_fatal(&self) -> bool {
        matches!(self, ScanError::TooManyFiles())
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Down(msg) => write!(f, "{}", msg),
            ScanError::TooManyFiles() => write!(
                f,
                "Too many concurrent scans. Decrease number of concurrent scans, \
                or increase open file limit (ulimit -n)"
            ),
        }
    }
}
// Scanning result for single host/port
pub struct PortResult {
    pub address: IpAddr,
    pub port: u16,
    pub state: PortState,
}

pub enum ScanInfo {
    PortStatus(PortResult),
    HostScanned(IpAddr),
}

// Handle OtherError returned by Connect.
// Try to detect at least if host is down.
fn handle_other_error(
    e: std::io::Error,
    connection_time: Duration,
) -> Result<PortState, ScanError> {
    e.raw_os_error()
        .map_or(Ok(PortState::Closed(connection_time)), |n| match n {
            os_errcodes::OS_ERR_HOST_DOWN => Ok(PortState::HostDown()),
            os_errcodes::OS_ERR_NET_UNREACH => Ok(PortState::NetError()),
            os_errcodes::OS_ERR_TOO_MANY_FILES => Err(ScanError::TooManyFiles()),
            _ => {
                debug!("Connect returned error code: {} (kind {:?})", n, e.kind());
                Ok(PortState::Closed(connection_time))
            }
        })
}

// try to connect to given SockerAddr.
// Returns Ok(PortState) if a state of port could be determined, Err(ScanError)
// if error occurred while scanning.
async fn try_port<F, C, Fut>(
    sa: SocketAddr,
    conn_timeout: Duration,
    handler: F,
    context: C,
) -> Result<PortState, ScanError>
where
    F: FnOnce(TcpStream, C) -> Fut,
    Fut: Future<Output = Option<Vec<u8>>>,
{
    trace!("Trying {}", sa);
    let start = Instant::now();
    let res = future::timeout(conn_timeout, TcpStream::connect(sa)).await;
    let c_time = start.elapsed();

    let c = match res {
        Ok(v) => v,
        Err(_) => {
            trace!("Connection timed out");
            return Ok(PortState::Timeout(c_time));
        }
    };

    trace!("connect() took {}ms", c_time.as_millis());

    match c {
        Ok(s) => {
            info!("port {} Connection succesfull", sa.port());
            let data = handler(s, context).await;
            info!("Connection took {}ms", c_time.as_millis());
            Ok(PortState::Open(c_time, data))
        }
        Err(e) => {
            trace!("Connection failed: {}", e);
            match e.kind() {
                ErrorKind::TimedOut => Ok(PortState::Timeout(c_time)),
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
    TcpBanner(usize, Duration),
}

async fn close_connection(s: TcpStream, how: Shutdown) -> Option<Vec<u8>> {
    if let Err(e) = s.shutdown(how) {
        warn!("Unable to shutdown connection: {}", e)
    }
    None
}

struct RdParms {
    size: usize,
    timeout: Duration,
}

async fn read_banner(mut s: TcpStream, p: RdParms) -> Option<Vec<u8>> {
    let mut buf = vec![0; p.size];
    info!(
        "Trying to read {} bytes of banner from {:?} with {}ms timeout",
        p.size,
        s.peer_addr().unwrap(),
        p.timeout.as_millis()
    );

    let ret = future::timeout(p.timeout, s.read(&mut buf)).await;
    info!("Read returned {:?}", ret);
    let r = match ret {
        Ok(Ok(0)) => None,
        Ok(Ok(len)) => {
            buf.resize(len, 0);
            Some(buf)
        }
        Ok(Err(e)) => {
            warn!("Error while reading data from {:?}: {}", s.peer_addr(), e);
            None
        }
        Err(_) => None,
    };
    close_connection(s, Shutdown::Both).await;
    r
}

// minimum timeout value to report for adaptive timeout

impl ScanType {
    // Scan for single port in given host. Result will be sent
    // using `tx` Sender. `conn_timeout` will indicate how long to wait
    // for response.
    async fn cycle(
        &self,
        sa: SocketAddr,
        tx: Arc<Sender<ScanInfo>>,
        conn_timeout: Duration,
        retry_on_error: bool,
        try_count: usize,
    ) -> Result<Option<Duration>, ScanError> {
        let mut nr_of_tries: usize = 0;
        loop {
            nr_of_tries += 1;
            let state = match self {
                ScanType::Tcp => {
                    try_port(sa, conn_timeout, close_connection, Shutdown::Both).await?
                }
                ScanType::TcpBanner(size, timeout) => {
                    let p = RdParms {
                        size: *size,
                        timeout: *timeout,
                    };
                    try_port(sa, conn_timeout, read_banner, p).await?
                }
            };
            let ret = match state {
                PortState::Open(d, _) | PortState::Closed(d) => Ok(Some(d)),
                PortState::Timeout(_) => {
                    if nr_of_tries >= try_count {
                        Ok(None)
                    } else {
                        debug!(
                            "Retrying port {} due to timeout, tried {}/{}",
                            sa.port(),
                            nr_of_tries,
                            try_count
                        );
                        continue;
                    }
                }
                PortState::HostDown() => {
                    info!("Remote host is down");
                    Err(ScanError::Down(format!("Host {} is down", sa.ip())))
                }
                PortState::NetError() => {
                    if !retry_on_error {
                        Err(ScanError::Down(format!(
                            "Host {}, network error, marking down",
                            sa.ip()
                        )))
                    } else if nr_of_tries >= try_count {
                        Err(ScanError::Down(format!(
                            "Host {}, tried {}/{} times, network error",
                            sa.ip(),
                            nr_of_tries,
                            try_count
                        )))
                    } else {
                        info!(
                            "waiting 500ms before next retry ({}/{} tries)",
                            nr_of_tries, try_count
                        );
                        task::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                }
            };
            if let Err(_e) = tx
                .send(ScanInfo::PortStatus(PortResult {
                    address: sa.ip(),
                    port: sa.port(),
                    state,
                }))
                .await
            {
                warn!("Result channel closed!")
            }
            return ret;
        }
    }
}
// parameters for whole scan operation
#[derive(Clone, Copy)]
pub struct ScanParameters {
    pub wait_timeout: Duration,          // Duration to wait for responses
    pub concurrent_scans: usize,         // number of concurrent tasks to run
    pub enable_adaptive_timing: bool,    // should adaptive timeout be used
    pub retry_on_error: bool,            // should we retry on network error
    pub try_count: usize,                // number of times to try if there is no response
    pub read_banner_size: Option<usize>, // number of bytes to read if connection is established
    pub read_banner_timeout: Option<Duration>, // how long to wait for banner
}

impl Default for ScanParameters {
    fn default() -> Self {
        ScanParameters {
            wait_timeout: DEFAULT_CONNECTION_TIMEOUT,
            concurrent_scans: 100,
            enable_adaptive_timing: false,
            retry_on_error: false,
            try_count: 2,
            read_banner_size: None,
            read_banner_timeout: None,
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
        let t = if params.read_banner_timeout.is_some() && params.read_banner_size.is_some() {
            ScanType::TcpBanner(
                params.read_banner_size.unwrap(),
                params.read_banner_timeout.unwrap(),
            )
        } else {
            ScanType::Tcp
        };

        Scanner {
            sem: Semaphore::new(params.concurrent_scans),
            r#type: t,
            params,
            stop,
        }
    }

    pub async fn scan(self, range: ScanRange<'_>, tx: Sender<ScanInfo>) -> Result<(), ScanError> {
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
        let mut retval = Ok(());
        while let Some(ret) = waiters.next().await {
            match ret {
                Err(e) => retval = Err(e),
                _ => (),
            };
        }
        return retval;
    }

    async fn scan_host(&self, host: HostIterator, tx: Arc<Sender<ScanInfo>>) -> Host {
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
            context: ctx,
        };
    }
}

#[derive(Clone)]
struct HostContext {
    up: Arc<AtomicBool>,
    stop_signal: Arc<AtomicBool>,
    tx: Arc<Sender<ScanInfo>>,
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

    fn fatal(&mut self) {
        warn!("Setting global stop due to fatal error");
        self.stop_signal.store(true, Ordering::SeqCst);
    }
}

struct Host {
    addr: IpAddr,
    tasks: FuturesUnordered<JoinHandle<Result<(), ScanError>>>,
    context: HostContext,
}

impl Host {
    async fn wait(mut self) -> Result<(), ScanError> {
        let mut ret = Ok(());
        while let Some(res) = self.tasks.next().await {
            if let Err(e) = res {
                if e.is_fatal() {
                    ret = Err(e);
                }
            }
        }
        if let Err(e) = self.context.tx.send(ScanInfo::HostScanned(self.addr)).await {
            warn!("Unable to send scan info: {}", e);
        }
        info!("Host {} scan complete", self.addr);
        ret
    }
}

async fn scan_port_stripe(
    addr: IpAddr,
    stripe: PortIterator,
    typ: ScanType,
    params: ScanParameters,
    sem: SemHandle,
    mut ctx: HostContext,
) -> Result<(), ScanError> {
    debug!("Starting stripe {:?} for {}", stripe, addr);
    let mut ret = Ok(());
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
                params.try_count,
            )
            .await
        {
            Ok(_) => {}
            Err(e) => {
                warn!("Terminating stripe for {} due to error: {}", addr, e);
                if e.is_fatal() {
                    ctx.fatal();
                } else {
                    ctx.host_down();
                }
                ret = Err(e);
                break;
            }
        }
    }
    sem.signal();
    trace!("stripe complete for {}", addr);
    ret
}
