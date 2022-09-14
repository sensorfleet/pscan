use async_std::channel::Sender;
use async_std::future;
use async_std::io::{ErrorKind, ReadExt};
use async_std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use async_std::sync::{Arc, Mutex};
use async_std::task;
use futures::Future;
use rand::seq::SliceRandom;
use std::collections::HashMap;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use std::{fmt, sync::atomic::AtomicBool};

use crate::range::{ChunkIter, ScanRange};
use crate::tools::Semaphore;

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

/// Detected state of a port
#[derive(Debug)]
pub enum PortState {
    Open(Duration, Option<Vec<u8>>), // port is open, contains banner if we did read any
    Closed(Duration),                // port is closed
    Timeout(Duration),               // Did not get response withint timeout
    HostDown(),                      // Host was reported unreachable by OS
    NetError(),                      // Host could not be connected due network error
}

/// Scanning error
#[derive(Clone)]
pub enum ScanError {
    Down(String),   // Host was detected to be down
    TooManyFiles(), // OS reported too many open files
}

impl ScanError {
    /// Check if error is fatal.
    /// Fatal errors should terminate scanning.
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
/// Scanning result for a port in host.
pub struct PortResult {
    pub address: IpAddr,
    pub port: u16,
    pub state: PortState,
}

/// Scan information emitted by scanner durin scan.
pub enum ScanInfo {
    /// A port has been scanned, contains the scanning result
    PortStatus(PortResult),
    /// Scanning of host has been completed, all requested ports are scanned.
    HostScanned(IpAddr),
}

/// Handle OtherError returned by Connect.
/// Handles cases for which there are no specific ErrorKind
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

/// Try to connect to given SockerAddr and return the detected state of port.
/// If no response is received from the port within given timeout, port state
/// will be set to PortState::Timeout.
///
/// The given handler is called with context if connection is established.
/// The handler should terminate the connection if it should not be left
/// open. Callback context is used because Rust does not support async closures
/// yet. Data returned by callback is included in PortState::Open returned.
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
            info!("Connection to {} succesfull", sa);
            let data = handler(s, context).await;
            info!("Connection took {}ms", c_time.as_millis());
            Ok(PortState::Open(c_time, data))
        }
        Err(e) => {
            trace!("Connection to {} failed: {}", sa, e);
            match e.kind() {
                ErrorKind::TimedOut => Ok(PortState::Timeout(c_time)),
                ErrorKind::ConnectionRefused => Ok(PortState::Closed(c_time)),
                ErrorKind::PermissionDenied => Ok(PortState::HostDown()),
                _ => handle_other_error(e, c_time),
            }
        }
    }
}

#[derive(Clone)]
/// ScanType determines the type of scan to perform.
pub enum ScanType {
    /// Scan for open TCP ports
    Tcp,
    /// Scan for open TCP ports and try to read a banner from open ports.
    /// Parameters are number of bytes to read and how long to wait for data.
    TcpBanner(usize, Duration),
    /// this is only for unit tests, provide return values from hashmap
    Test(Arc<Mutex<HashMap<SocketAddr, Result<PortState, ScanError>>>>),
}

/// Close given TcpStream.
/// Always returns None
async fn close_connection(s: TcpStream, how: Shutdown) -> Option<Vec<u8>> {
    if let Err(e) = s.shutdown(how) {
        warn!("Unable to shutdown connection: {}", e)
    }
    None
}

/// Callback parameters for `read_banner()` function
struct RdParms {
    size: usize,
    timeout: Duration,
}

/// `try_port()` callback that can be used to read banner from open TCP port
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

impl ScanType {
    /// Do a scan for given SocketAddr.
    /// Connection is tried for `conn_timeout`, if no response is received
    /// connection is tried `try_count` times (`try_count` 1 indicates no
    /// retries).
    /// If `retry_on_error` is `true` retries the connection `try_count` times
    /// if network error is returned.
    ///
    /// The result of scanning is sent using `tx` `Sender`. Returned time,
    /// if present, indicates how long it took to get response from host.
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
                ScanType::Test(m) => {
                    let mut val = m.lock().await;
                    val.remove(&sa).unwrap_or(Ok(PortState::HostDown()))?
                }
            };
            let ret = match state {
                PortState::Open(d, _) | PortState::Closed(d) => Ok(Some(d)),
                PortState::Timeout(_) => {
                    if nr_of_tries >= try_count {
                        Ok(None)
                    } else {
                        debug!(
                            "Retrying {} due to timeout, tried {}/{}",
                            sa, nr_of_tries, try_count
                        );
                        continue;
                    }
                }
                PortState::HostDown() => {
                    info!("Remote host {} is down", sa.ip());
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
/// Parameters for scan operation
#[derive(Clone, Copy)]
pub struct ScanParameters {
    pub wait_timeout: Duration,          // Duration to wait for responses
    pub concurrent_scans: usize,         // number of concurrent tasks to run
    pub concurrent_hosts: usize,         // number of hosts to scan at the same time
    pub enable_adaptive_timing: bool,    // should adaptive timeout be used
    pub retry_on_error: bool,            // should we retry on network error
    pub try_count: usize,                // number of times to try if there is no response
    pub read_banner_size: Option<usize>, // number of bytes to read if connection is established
    pub read_banner_timeout: Option<Duration>, // how long to wait for banner
    pub randomize: bool,
}

impl Default for ScanParameters {
    fn default() -> Self {
        ScanParameters {
            wait_timeout: DEFAULT_CONNECTION_TIMEOUT,
            concurrent_scans: 100,
            concurrent_hosts: 100,
            enable_adaptive_timing: false,
            retry_on_error: false,
            try_count: 2,
            read_banner_size: None,
            read_banner_timeout: None,
            randomize: false,
        }
    }
}

///Scanner can be used to scan for open TCP ports.
pub struct Scanner {
    sem: Arc<Semaphore>,    // semaphore controlling number of concurrent tasks
    r#type: ScanType,       // type of scan to perform
    params: ScanParameters, // parameters for scans
    stop: Arc<AtomicBool>,  // flag indicating that scanning should stop
}

impl Scanner {
    /// Create new scanner with given parameters.
    /// The `stop` flag can be used to stop ongoing scan.
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
            sem: Arc::new(Semaphore::new(params.concurrent_scans)),
            r#type: t,
            params,
            stop,
        }
    }

    #[allow(dead_code)]
    fn create_test(
        params: ScanParameters,
        stop: Arc<AtomicBool>,
        map: HashMap<SocketAddr, Result<PortState, ScanError>>,
    ) -> Scanner {
        Scanner {
            sem: Arc::new(Semaphore::new(params.concurrent_scans)),
            r#type: ScanType::Test(Arc::new(Mutex::new(map))),
            params,
            stop,
        }
    }

    /// Do a scan for given range. Results will be sent using `tx` `Sender`.
    pub async fn scan(self, range: ScanRange<'_>, tx: Sender<ScanInfo>) -> Result<(), ScanError> {
        let atx = Arc::new(tx);
        let host_chunks = ChunkIter::new(range.hosts(), self.params.concurrent_hosts);
        let mut ports = range.ports.port_iter().collect::<Vec<u16>>();

        if self.params.randomize {
            let mut rng = rand::thread_rng();
            ports.shuffle(&mut rng);
        }

        // return value, this gets set from task if fatal error occurs and w
        // need to indicate the error. Needs to be protected by mutex since
        // this might be accessed from scanning task.
        let rv = Arc::new(Mutex::new(None));

        let last_port = ports.last().unwrap().to_owned();

        'outer: for host_set in host_chunks.map(|c| Arc::new(Mutex::new(c))) {
            for port in &ports {
                for sa in host_set
                    .lock()
                    .await
                    .iter()
                    .map(|h| SocketAddr::new(*h, *port))
                {
                    let handle = self.sem.wait().await;
                    if self.stop.load(Ordering::SeqCst) {
                        warn!("Stopping scanning due to signal");
                        handle.signal();
                        break 'outer;
                    }

                    let tx = Arc::clone(&atx);
                    let typ = ScanType::clone(&self.r#type);
                    let s = Arc::clone(&self.stop);
                    let is_last = *port == last_port;
                    let r = Arc::clone(&rv);
                    let d_map = host_set.clone();

                    task::spawn(async move {
                        let ret = scan_single(&typ, &self.params, tx.clone(), sa).await;
                        handle.signal();
                        if let Err(e) = ret {
                            if !e.is_fatal() {
                                trace!("Marking host {} down", sa.ip());
                                if d_map.lock().await.remove(&sa.ip()) {
                                    if let Err(e) = tx.send(ScanInfo::HostScanned(sa.ip())).await {
                                        warn!("Unable to send host scanned indication: {}", e);
                                    }
                                }
                            } else {
                                info!("stopping due to fatal error while scanning");
                                if let Err(e) = tx.send(ScanInfo::HostScanned(sa.ip())).await {
                                    warn!("Unable to send host scanned indication: {}", e);
                                }
                                let mut ret = r.lock().await;
                                *ret = Some(e);
                                s.store(true, Ordering::SeqCst);
                            }
                        } else if is_last {
                            if let Err(e) = tx.send(ScanInfo::HostScanned(sa.ip())).await {
                                warn!("Unable to send host scanned indication: {}", e);
                            }
                        }
                    });
                }
            }
        }
        debug!("waiting for all tasks to complete");
        self.sem.wait_empty().await;
        let r = rv.lock().await.take();
        match r {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

// do a scan for single port on host
// Returns Ok if scanning succeeded, Err if there was error preventing the
// scan to succeed (host was down, could not be reached, etc).
async fn scan_single(
    typ: &ScanType,
    params: &ScanParameters,
    tx: Arc<Sender<ScanInfo>>,
    sa: SocketAddr,
) -> Result<(), ScanError> {
    match typ
        .cycle(
            sa,
            tx,
            params.wait_timeout,
            params.retry_on_error,
            params.try_count,
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config, ports};
    use std::{convert::TryFrom, str::FromStr};

    #[async_std::test]
    async fn test_simple() {
        let params = ScanParameters {
            wait_timeout: Duration::from_millis(100),
            concurrent_scans: 2,
            concurrent_hosts: 2,
            enable_adaptive_timing: false,
            retry_on_error: false,
            try_count: 2,
            read_banner_size: None,
            read_banner_timeout: None,
            randomize: false,
        };

        let mut map = HashMap::new();

        let addr1 = IpAddr::from_str("10.0.0.1").unwrap();
        let addr2 = IpAddr::from_str("10.0.0.2").unwrap();

        let addresses = config::parse_addresses("10.0.0.1, 10.0.0.2").unwrap();

        let range = ScanRange::create(
            &addresses,
            &[],
            ports::PortRange::try_from("22,80").unwrap(),
        );

        map.insert(
            SocketAddr::new(addr1, 22),
            Ok(PortState::Open(Duration::from_millis(10), None)),
        );
        map.insert(
            SocketAddr::new(addr1, 80),
            Ok(PortState::Open(Duration::from_millis(10), None)),
        );
        map.insert(
            SocketAddr::new(addr2, 22),
            Ok(PortState::Closed(Duration::from_millis(10))),
        );
        map.insert(
            SocketAddr::new(addr2, 80),
            Ok(PortState::Closed(Duration::from_millis(20))),
        );

        let stop = Arc::new(AtomicBool::new(false));
        let scanner = Scanner::create_test(params, stop, map);

        let (tx, rx) = async_std::channel::bounded::<ScanInfo>(10);

        let reader_task = task::spawn(async move {
            let mut infos: Vec<ScanInfo> = Vec::new();
            while let Ok(data) = rx.recv().await {
                infos.push(data)
            }
            infos
        });

        let scan_result = scanner.scan(range, tx).await;
        assert!(scan_result.is_ok());

        let infos = reader_task.await;
        let mut addr1_scanned = false;
        let mut addr2_scanned = false;
        for info in infos {
            match info {
                ScanInfo::PortStatus(status) => match status.state {
                    PortState::Open(_, _) => {
                        assert_eq!(status.address, addr1);
                        assert!(status.port == 22 || status.port == 80);
                    }
                    PortState::Closed(_) => {
                        assert_eq!(status.address, addr2);
                        assert!(status.port == 80 || status.port == 22);
                    }
                    _ => panic!(
                        "Unexpected port state: {:?} for {}:{}",
                        status.state, status.address, status.port,
                    ),
                },
                ScanInfo::HostScanned(addr) => {
                    if addr == addr1 {
                        assert!(!addr1_scanned);
                        addr1_scanned = true
                    } else if addr == addr2 {
                        assert!(!addr2_scanned);
                        addr2_scanned = true
                    } else {
                        panic!("unexpected host {} scanned", addr);
                    }
                }
            }
        }
    }
}
