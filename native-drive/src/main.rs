//! Read-only SSE metadata drive. File content reads are unsupported.
mod drive;
mod refresh;
mod tree;
use drive::MetadataDrive;
use std::io::{self, BufRead, Write};
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tree::Tree;
use windows::Win32::Storage::FileSystem::GetLogicalDrives;
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
use windows::Win32::UI::Shell::{
    SHCNE_DRIVEADD, SHCNE_DRIVEREMOVED, SHCNE_UPDATEDIR, SHCNF_PATHW, SHChangeNotify,
};
use windows::core::{HSTRING, w};
use winfsp::host::{FileSystemHost, VolumeParams};

fn choose_letter(used: u32) -> Option<String> {
    // Prefer F:, but never replace an existing drive (including Google Drive).
    (b'F'..=b'Z')
        .chain(b'D'..=b'E')
        .find(|letter| used & (1 << (letter - b'A')) == 0)
        .map(|letter| format!("{}:", letter as char))
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
        .sector_size(512)
        .sectors_per_allocation_unit(8)
        .max_component_length(255)
        .volume_serial_number(0x46445353)
        .case_preserved_names(true)
        .unicode_on_disk(true)
        .persistent_acls(false)
        .read_only_volume(true)
        .file_info_timeout(1000)
        .dir_info_timeout(0);
    let tree = Arc::new(RwLock::new(Arc::new(Tree::empty())));
    let refresh = Arc::new(refresh::Refresh::default());
    let mut host: FileSystemHost<MetadataDrive> =
        FileSystemHost::new(params, MetadataDrive(tree.clone(), refresh.clone()))?;
    host.mount(&letter)?;
    host.start()?;
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
        match Tree::parse(&command) {
            Ok(snapshot) => {
                let count = snapshot.0.len() - 1;
                let previous = tree.read().unwrap().clone();
                let mut changed = std::collections::BTreeSet::new();
                for (key, entry) in previous.0.iter().chain(snapshot.0.iter()) {
                    if previous.0.get(key) != snapshot.0.get(key) {
                        changed.insert(tree::parent(&entry.path).to_string());
                    }
                }
                *tree.write().unwrap() = Arc::new(snapshot);
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
    host.unmount();
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
