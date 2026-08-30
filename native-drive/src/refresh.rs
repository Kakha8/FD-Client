use std::io::{self, Write};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Gate {
    enabled: bool,
    pending: bool,
    completed: Option<Instant>,
}

impl Gate {
    fn claim(&mut self, now: Instant) -> bool {
        if !self.enabled
            || self.pending
            || self
                .completed
                .is_some_and(|last| now.duration_since(last) < Duration::from_secs(2))
        {
            return false;
        }
        self.pending = true;
        true
    }
}

#[derive(Default)]
pub struct Refresh(Mutex<Gate>, Condvar);

impl Refresh {
    pub fn request(&self) {
        if self.0.lock().unwrap().claim(Instant::now()) {
            println!("REFRESH");
            let _ = io::stdout().flush();
        }
        // Return fresh metadata in THIS enumeration, rather than returning stale
        // data and depending on Explorer to perform a second scan after a notification.
        // Concurrent enumerators share the same request. Offline/slow backends
        // fall back to the cached snapshot after a bounded wait.
        let gate = self.0.lock().unwrap();
        let _ = self
            .1
            .wait_timeout_while(gate, Duration::from_secs(15), |g| g.pending)
            .unwrap();
    }

    pub fn completed(&self, success: bool) {
        let mut gate = self.0.lock().unwrap();
        gate.enabled |= success;
        gate.pending = false;
        gate.completed = Some(Instant::now());
        self.1.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enumeration_waits_for_inflight_refresh() {
        let refresh = std::sync::Arc::new(Refresh::default());
        refresh.0.lock().unwrap().pending = true;
        let worker_refresh = refresh.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            worker_refresh.request();
            tx.send(()).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        refresh.completed(true);
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn coalesces_requests_and_honors_cooldown() {
        let now = Instant::now();
        let mut gate = Gate::default();
        assert!(!gate.claim(now));
        gate.enabled = true;
        assert!(gate.claim(now));
        assert!(!gate.claim(now + Duration::from_secs(5)));
        gate.pending = false;
        gate.completed = Some(now);
        assert!(!gate.claim(now + Duration::from_secs(1)));
        assert!(gate.claim(now + Duration::from_secs(3)));
    }
}
