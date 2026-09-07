//! Correlated requests over the parent's private pipes. Never carries credentials.
use serde_json::Value;
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, mpsc};
use std::time::Duration;
use windows::Win32::Foundation::STATUS_IO_DEVICE_ERROR;

#[derive(Default)]
pub struct Transfers {
    next: AtomicU64,
    pending: Mutex<HashMap<u64, mpsc::Sender<Value>>>,
}

impl Transfers {
    pub fn request(&self, mut request: Value) -> winfsp::Result<Value> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        request["request"] = id.into();
        let (tx, rx) = mpsc::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let sent = {
            let mut out = io::stdout().lock();
            writeln!(out, "TRANSFER {request}").and_then(|_| out.flush())
        };
        let response = if sent.is_ok() {
            rx.recv_timeout(Duration::from_secs(240)).ok()
        } else {
            None
        };
        self.pending.lock().unwrap().remove(&id);
        match response {
            Some(value) if value["ok"] == true => Ok(value),
            _ => Err(STATUS_IO_DEVICE_ERROR.into()),
        }
    }

    pub fn complete(&self, line: &str) {
        if let Ok(value) = serde_json::from_str::<Value>(line) {
            if let Some(id) = value["request"].as_u64() {
                if let Some(tx) = self.pending.lock().unwrap().remove(&id) {
                    let _ = tx.send(value);
                }
            }
        }
    }

    pub fn stop(&self) {
        self.pending.lock().unwrap().clear();
    }
}
