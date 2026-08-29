use std::{env, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

static ACCOUNT_ID: AtomicU64 = AtomicU64::new(0);

pub fn set(account_id: u64) -> Result<(), &'static str> {
    if account_id == 0 { return Err("account ID must be positive"); }
    ACCOUNT_ID.store(account_id, Ordering::SeqCst);
    Ok(())
}

pub fn clear() {
    ACCOUNT_ID.store(0, Ordering::SeqCst);
}

pub fn account_directory() -> Result<PathBuf, &'static str> {
    let account_id = ACCOUNT_ID.load(Ordering::SeqCst);
    if account_id == 0 { return Err("no active account context"); }
    let local = env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not available")?;
    Ok(PathBuf::from(local)
        .join("FileDrive")
        .join("accounts")
        .join(account_id.to_string()))
}

pub fn key_directory() -> Result<PathBuf, &'static str> {
    Ok(account_directory()?.join("keys"))
}
