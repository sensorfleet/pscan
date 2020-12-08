use async_std::sync::{channel, Arc, Receiver, Sender};

/// Simple counting semaphore.
/// Use Semaphore::new() to get new instance with given capacity,
/// Semaphore::wait() returns SemHandle instance once access is granted and
/// SemHandle::signal() is used to signal the semaphore.
pub struct Semaphore {
    ch: Sender<u16>,
    sig: Arc<Receiver<u16>>,
}

impl Semaphore {
    /// Create new instance of the counting semaphore with given capacity
    pub fn new(capacity: usize) -> Self {
        let (s, r) = channel(capacity);
        Semaphore {
            ch: s,
            sig: Arc::new(r),
        }
    }
    /// Wait for access to resource. If there is no resources available
    /// waits until at least one has been signaled.
    /// Returns instance of SemHandle which needs to be signaled by
    /// calling SemHandle::signal() once resource is released.
    pub async fn wait(&self) -> SemHandle {
        self.ch.send(1).await;
        trace!("waited, c={}", self.ch.len());
        SemHandle {
            sig: self.sig.clone(),
        }
    }
}

/// Handle returned by Semaphore::wait().
pub struct SemHandle {
    sig: Arc<Receiver<u16>>,
}

impl SemHandle {
    /// Signal the semaphore that resource is free. This method consumes
    /// the handle.
    pub fn signal(self) {
        if self.sig.is_empty() {
            panic!("Signaling empty semaphore")
        }
        trace!("Signaling c={}", self.sig.len());
        if let Err(e) = self.sig.try_recv() {
            panic!(format!("Unexpected receive error on signal: {}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::future;
    use std::time::Duration;
    #[async_std::test]
    async fn test_sem() {
        let sem = Semaphore::new(1);
        let handle1 = future::timeout(Duration::from_secs(1), sem.wait())
            .await
            .unwrap();
        if let Ok(_) = future::timeout(Duration::from_secs(1), sem.wait()).await {
            assert!(false) // Expecting timeout as we already have one handle
        }
        handle1.signal();
        if let Err(_) = future::timeout(Duration::from_secs(1), sem.wait()).await {
            assert!(false) // now we should be able to take the semaphore
        }
    }
}
