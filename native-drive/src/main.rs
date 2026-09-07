//! SSE drive with Java-owned HTTP transfers over private pipes.
mod changes;
mod drive;
mod refresh;
mod transfer;
mod tree;
use drive::MetadataDrive;
use std::io::{self, BufRead, Write};
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use tree::Tree;
use windows::Win32::Storage::FileSystem::GetLogicalDrives;
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::Win32::System::Registry::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_SZ, RRF_RT_REG_SZ,
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegGetValueW, RegSetValueExW,
};
use windows::Win32::UI::Shell::{
    SHCNE_DRIVEADD, SHCNE_DRIVEREMOVED, SHCNE_UPDATEDIR, SHCNF_PATHW, SHChangeNotify,
};
use windows::core::{HSTRING, w};
use winfsp::host::{FileSystemHost, FileSystemParams, VolumeParams};

fn choose_letter(used: u32) -> Option<String> {
    // Prefer F:, but never replace an existing drive (including Google Drive).
    (b'F'..=b'Z')
        .chain(b'D'..=b'E')
        .find(|letter| used & (1 << (letter - b'A')) == 0)
        .map(|letter| format!("{}:", letter as char))
}

fn configure_drive_icon(letter: &str) {
    let icon = std::env::var_os("FD_CLIENT_ICON").or_else(|| {
        let exe_icon = std::env::current_exe().ok()?.parent()?.join("fd-client.ico");
        if exe_icon.exists() { return Some(exe_icon.into_os_string()); }
        let build_icon = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fd-client.ico");
        if build_icon.exists() { return Some(build_icon.into_os_string()); }
        let source_icon = std::env::current_dir().ok()?.join(r"native-drive\fd-client.ico");
        source_icon.exists().then(|| source_icon.into_os_string())
    });
    let Some(icon) = icon else { return };
    let key_path = format!(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons\{}\DefaultIcon",
        letter.trim_end_matches(':')
    );
    let key_path = HSTRING::from(key_path);
    let icon = HSTRING::from(icon);
    let mut key = Default::default();
    unsafe {
        if RegCreateKeyExW(HKEY_CURRENT_USER, &key_path, Some(0), None, Default::default(), KEY_SET_VALUE, None, &mut key, None).is_ok() {
            let bytes = std::slice::from_raw_parts(icon.as_ptr().cast::<u8>(), (icon.len() + 1) * 2);
            let _ = RegSetValueExW(key, None, Some(0), REG_SZ, Some(bytes));
            let _ = RegCloseKey(key);
        }
    }
}

fn remove_drive_icon(letter: &str) {
    let key_path = HSTRING::from(format!(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons\{}",
        letter.trim_end_matches(':')
    ));
    unsafe { let _ = RegDeleteTreeW(HKEY_CURRENT_USER, &key_path); }
}

fn load_installed_winfsp() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Use bundled SDK headers at build time, but load the installed runtime by
    // absolute path instead of relying on the working directory or PATH.
    for subkey in [w!("SOFTWARE\\WOW6432Node\\WinFsp"), w!("SOFTWARE\\WinFsp")] {
        let mut directory = [0u16; 1024];
        let mut bytes = std::mem::size_of_val(&directory) as u32;
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                subkey,
                w!("InstallDir"),
                RRF_RT_REG_SZ,
                None,
                Some(directory.as_mut_ptr().cast()),
                Some(&mut bytes),
            )
        };
        if status.is_err() {
            continue;
        }
        let length = directory
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(directory.len());
        let path = PathBuf::from(std::ffi::OsString::from_wide(&directory[..length]))
            .join("bin")
            .join(if cfg!(target_arch = "x86_64") {
                "winfsp-x64.dll"
            } else if cfg!(target_arch = "aarch64") {
                "winfsp-a64.dll"
            } else {
                "winfsp-x86.dll"
            });
        unsafe {
            LoadLibraryW(&HSTRING::from(path.as_os_str()))?;
        }
        return Ok(());
    }
    Err("WinFsp is not installed. Install the WinFsp runtime and retry.".into())
}

fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    load_installed_winfsp()?;
    let _init = winfsp::winfsp_init()
        .map_err(|e| format!("WinFsp is unavailable. Install the WinFsp runtime first: {e}"))?;
    let used = unsafe { GetLogicalDrives() };
    if used == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let letter = choose_letter(used).ok_or("No free drive letter is available.")?;
    let mut params = VolumeParams::new();
    params
        .filesystem_name("FD-SSE")
        // Mount through WinFsp.Disk so Explorer treats this as a disk volume
        // and honors the per-drive custom icon registered below.
        .sector_size(512)
        .sectors_per_allocation_unit(8)
        .max_component_length(255)
        .volume_serial_number(0x46445353)
        .case_preserved_names(true)
        .unicode_on_disk(true)
        .persistent_acls(false)
        .read_only_volume(false)
        // The binding's DirInfoTimeout setter does not enable its Valid flag.
        // Set the base timeout to zero so restarted folder scans reach us.
        .file_info_timeout(0);
    let tree = Arc::new(RwLock::new(Arc::new(Tree::empty())));
    let refresh = Arc::new(refresh::Refresh::default());
    let notifications = Arc::new(Mutex::new(Vec::new()));
    let transfers = Arc::new(transfer::Transfers::default());
    let staging = std::env::var_os("FD_DRIVE_STAGING")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let mut host: FileSystemHost<MetadataDrive> = FileSystemHost::new_with_timer::<(), 100>(
        FileSystemParams::default_params(params),
        MetadataDrive(
            tree.clone(),
            refresh.clone(),
            notifications.clone(),
            transfers.clone(),
            staging,
        ),
    )?;
    host.mount(&letter)?;
    host.start()?;
    configure_drive_icon(&letter);
    let root = HSTRING::from(format!("{letter}\\"));
    // Make Explorer refresh its cached This PC / navigation-pane drive list.
    unsafe {
        SHChangeNotify(
            SHCNE_DRIVEADD,
            SHCNF_PATHW,
            Some(root.as_ptr().cast()),
            None,
        );
    }
    println!("MOUNTED {letter}");
    io::stdout().flush()?;

    // Java owns this pipe. EOF also handles a killed/crashed parent process.
    for command in io::stdin().lock().lines() {
        let command = command?;
        if command.is_empty() {
            break;
        }
        if command == "REFRESH_FAILED" {
            refresh.completed(false);
            continue;
        }
        if let Some(response) = command.strip_prefix("TRANSFER ") {
            transfers.complete(response);
            continue;
        }
        match Tree::parse(&command) {
            Ok(mut snapshot) => {
                let mut current = tree.write().unwrap();
                // An Explorer copy is visible while its data is still being staged.
                for (key, entry) in &current.0 {
                    if key != "\\" && entry.id == 0 {
                        snapshot
                            .0
                            .entry(key.clone())
                            .or_insert_with(|| entry.clone());
                    }
                }
                let count = snapshot.0.len() - 1;
                let previous = current.clone();
                let mut changed = std::collections::BTreeSet::new();
                for (key, entry) in previous.0.iter().chain(snapshot.0.iter()) {
                    if previous.0.get(key) != snapshot.0.get(key) {
                        changed.insert(tree::parent(&entry.path).to_string());
                    }
                }
                let events = changes::diff(&previous, &snapshot);
                *current = Arc::new(snapshot);
                drop(current);
                notifications.lock().unwrap().extend(events);
                refresh.completed(true);
                // Notify only changed directories, avoiding a refresh/notification loop.
                for path in changed {
                    let path = HSTRING::from(format!("{letter}{path}"));
                    unsafe {
                        SHChangeNotify(
                            SHCNE_UPDATEDIR,
                            SHCNF_PATHW,
                            Some(path.as_ptr().cast()),
                            None,
                        );
                    }
                }
                println!("UPDATED {count}");
            }
            Err(_) => {
                refresh.completed(false);
                println!("ERROR Invalid metadata snapshot");
            }
        }
        io::stdout().flush()?;
    }
    transfers.stop();
    host.unmount();
    remove_drive_icon(&letter);
    unsafe {
        SHChangeNotify(
            SHCNE_DRIVEREMOVED,
            SHCNF_PATHW,
            Some(root.as_ptr().cast()),
            None,
        );
    }
    host.stop();
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ERROR {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_f_when_available() {
        assert_eq!(choose_letter(1 << 2).as_deref(), Some("F:"));
    }

    #[test]
    fn skips_existing_drives() {
        assert_eq!(choose_letter((1 << 5) | (1 << 6)).as_deref(), Some("H:"));
    }

    #[test]
    fn fails_when_all_letters_are_occupied() {
        assert_eq!(choose_letter(u32::MAX), None);
    }
}
