use crate::tree::{self, Tree};
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use windows::Win32::Foundation::{
    STATUS_ACCESS_DENIED, STATUS_DIRECTORY_NOT_EMPTY, STATUS_FILE_IS_A_DIRECTORY,
    STATUS_IO_DEVICE_ERROR, STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SHARING_VIOLATION,
};
use winfsp::filesystem::{
    DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo, VolumeInfo,
    WideNameInfo,
};
use winfsp::notify::{Notifier, NotifyInfo, NotifyingFileSystemContext};
use winfsp::{Result, U16CStr};

pub struct MetadataDrive(
    pub Arc<RwLock<Arc<Tree>>>,
    pub Arc<crate::refresh::Refresh>,
    pub Arc<Mutex<Vec<crate::changes::Change>>>,
    pub Arc<crate::transfer::Transfers>,
    pub PathBuf,
);

impl NotifyingFileSystemContext<()> for MetadataDrive {
    fn should_notify(&self) -> Option<()> {
        if self.2.lock().unwrap().is_empty() {
            None
        } else {
            Some(())
        }
    }

    fn notify(&self, _: (), notifier: &Notifier) {
        // Drain only after WinFsp has acquired its notification guard; a busy
        // guard must not lose pending events.
        let changes = std::mem::take(&mut *self.2.lock().unwrap());
        for change in changes {
            let mut info = NotifyInfo::<32760>::new();
            info.action = change.action;
            info.filter = change.filter;
            // Notify names are length-delimited, not NUL-terminated. set_name()
            // includes a trailing NUL, which prevents Windows matching watchers.
            let name: Vec<u16> = change.path.encode_utf16().collect();
            if info.set_name_raw(name.as_slice()).is_ok() {
                notifier.notify(&info);
            }
        }
    }
}
pub struct Handle {
    tree: Mutex<Arc<Tree>>,
    path: String,
    local: Mutex<Option<LocalFile>>,
    cancelled: AtomicBool,
    id: AtomicU64,
    directory: bool,
}

struct LocalFile {
    file: File,
    path: PathBuf,
    upload: bool,
    committed: bool,
    attempted: bool,
}

impl Drop for LocalFile {
    fn drop(&mut self) {
        // Failed uploads remain on disk for recovery; never discard their bytes.
        if !self.upload || self.committed {
            let _ = std::fs::remove_file(&self.path);
            if self.upload {
                let _ = std::fs::remove_file(self.path.with_extension("name.txt"));
            }
        }
    }
}

impl MetadataDrive {
    // Handles survive directory moves. Resolve by stable backend ID instead of
    // continuing to use the path that happened to be present at Open.
    fn current_path(&self, context: &Handle) -> String {
        let id = context.id.load(Ordering::Relaxed);
        if id == 0 {
            return context.path.clone();
        }
        let tree = self.0.read().unwrap();
        if tree
            .0
            .get(&context.path)
            .is_some_and(|e| e.id == id && e.directory == context.directory)
        {
            return context.path.clone();
        }
        tree.0
            .iter()
            .find(|(_, e)| e.id == id && e.directory == context.directory)
            .map(|(path, _)| path.clone())
            .unwrap_or_else(|| context.path.clone())
    }

    fn remove_entry(&self, path: &str, id: u64) {
        let mut current = self.0.write().unwrap();
        if !current.0.get(path).is_some_and(|entry| entry.id == id) {
            return;
        }
        let previous = current.clone();
        Arc::make_mut(&mut current).0.remove(path);
        self.2
            .lock()
            .unwrap()
            .extend(crate::changes::diff(&previous, &current));
    }

    fn commit(&self, context: &Handle) -> Result<()> {
        if context.cancelled.load(Ordering::Relaxed) {
            return Ok(());
        }
        let mut local = context.local.lock().unwrap();
        if let Some(local) = local.as_mut() {
            if local.upload && !local.committed {
                if local.attempted {
                    let _ = self.3.request(serde_json::json!({"op":"upload_failed",
                        "file":local.path.file_name().unwrap().to_string_lossy()}));
                    return Err(STATUS_IO_DEVICE_ERROR.into());
                }
                local.attempted = true; // Never retry an ambiguous POST automatically.
                local.file.sync_all().map_err(|_| STATUS_IO_DEVICE_ERROR)?;
                let tree = context.tree.lock().unwrap();
                let entry = &tree.0[&context.path];
                let parent = tree
                    .0
                    .get(tree::parent(&context.path))
                    .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
                let response = self.3.request(serde_json::json!({
                    "op":"upload", "file":local.path.file_name().unwrap().to_string_lossy(),
                    "name":entry.path.rsplit('\\').next().unwrap(), "parent":parent.id
                }))?;
                let mut current = self.0.write().unwrap();
                if let Some(entry) = Arc::make_mut(&mut current).0.get_mut(&context.path) {
                    entry.id = response["id"].as_u64().ok_or(STATUS_IO_DEVICE_ERROR)?;
                    context.id.store(entry.id, Ordering::Relaxed);
                }
                local.committed = true;
            }
        }
        Ok(())
    }
}

impl FileSystemContext for MetadataDrive {
    type FileContext = Handle;

    fn get_security_by_name(
        &self,
        name: &U16CStr,
        _descriptor: Option<&mut [c_void]>,
        _resolve: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> Result<FileSecurity> {
        let tree = self.0.read().unwrap();
        let key = name.to_string_lossy().to_lowercase();
        let entry = tree.0.get(&key).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes: entry.info().file_attributes,
        })
    }

    fn open(
        &self,
        name: &U16CStr,
        options: u32,
        access: u32,
        info: &mut OpenFileInfo,
    ) -> Result<Handle> {
        let tree = self.0.read().unwrap().clone();
        let key = name.to_string_lossy().to_lowercase();
        let entry = tree.0.get(&key).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        if !entry.directory && (entry.id == 0 || access & 6 != 0) {
            return Err(STATUS_ACCESS_DENIED.into());
        }
        if entry.directory && options & 0x40 != 0 {
            return Err(STATUS_FILE_IS_A_DIRECTORY.into());
        }
        if !entry.directory && options & 1 != 0 {
            return Err(STATUS_NOT_A_DIRECTORY.into());
        }
        *info.as_mut() = entry.info();
        let id = entry.id;
        let directory = entry.directory;
        let handle = Handle {
            tree: Mutex::new(tree),
            path: key,
            local: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            id: AtomicU64::new(id),
            directory,
        };
        if options & 0x1000 != 0 {
            self.set_delete(&handle, name, true)?;
        }
        Ok(handle)
    }

    fn close(&self, _context: Handle) {}

    fn create(
        &self,
        name: &U16CStr,
        options: u32,
        _access: u32,
        _attributes: u32,
        _security: Option<&[c_void]>,
        _allocation: u64,
        _extra: Option<&[u8]>,
        _reparse: bool,
        info: &mut OpenFileInfo,
    ) -> Result<Handle> {
        let path = name.to_string_lossy();
        let key = path.to_lowercase();
        let directory = options & 1 != 0;
        if directory && options & 0x1000 != 0 {
            return Err(STATUS_ACCESS_DENIED.into());
        }
        let parent = {
            let tree = self.0.read().unwrap();
            if tree.0.contains_key(&key) {
                return Err(STATUS_OBJECT_NAME_COLLISION.into());
            }
            let parent = tree
                .0
                .get(tree::parent(&key))
                .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
            if !parent.directory {
                return Err(STATUS_NOT_A_DIRECTORY.into());
            }
            parent.id
        };
        let leaf = path.rsplit('\\').next().unwrap_or("");
        if leaf.is_empty()
            || leaf.encode_utf16().count() > 255
            || leaf.ends_with(['.', ' '])
            || leaf.chars().any(|c| c < ' ' || "/:*?\"<>|".contains(c))
        {
            return Err(STATUS_ACCESS_DENIED.into());
        }
        let (id, local) = if directory {
            let result = self
                .3
                .request(serde_json::json!({"op":"mkdir","parent":parent,"name":leaf}))?;
            (result["id"].as_u64().ok_or(STATUS_IO_DEVICE_ERROR)?, None)
        } else {
            // Also checks that the parent session is authenticated before creating a file.
            self.3
                .request(serde_json::json!({"op":"ready", "name":leaf, "parent":parent}))?;
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let local_path = self.4.join(format!(
                "upload-{}.part",
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&local_path)
                .map_err(|_| STATUS_IO_DEVICE_ERROR)?;
            if std::fs::write(local_path.with_extension("name.txt"), &path).is_err() {
                drop(file);
                let _ = std::fs::remove_file(&local_path);
                return Err(STATUS_IO_DEVICE_ERROR.into());
            }
            (
                0,
                Some(LocalFile {
                    file,
                    path: local_path,
                    upload: true,
                    committed: false,
                    attempted: false,
                }),
            )
        };
        let entry = tree::Entry {
            id,
            path,
            directory,
            size: 0,
            created: 0,
            modified: 0,
        };
        *info.as_mut() = entry.info();
        let mut current = self.0.write().unwrap();
        Arc::make_mut(&mut current).0.insert(key.clone(), entry);
        Ok(Handle {
            tree: Mutex::new(current.clone()),
            path: key,
            local: Mutex::new(local),
            cancelled: AtomicBool::new(options & 0x1000 != 0),
            id: AtomicU64::new(id),
            directory,
        })
    }

    fn cleanup(&self, context: &Handle, _name: Option<&U16CStr>, _flags: u32) {
        let path = self.current_path(context);
        if context.cancelled.load(Ordering::Relaxed) {
            let id = context.id.load(Ordering::Relaxed);
            if id > 0 {
                // WinFsp requires deletion to happen here, never in SetDelete.
                // Keep the cached entry on HTTP failure; Java displays the error.
                if self
                    .3
                    .request(serde_json::json!({"op":"delete", "id":id,
                    "directory":context.directory, "path":path}))
                    .is_err()
                {
                    return;
                }
            }
            if let Some(local) = context.local.lock().unwrap().as_mut() {
                local.committed = true;
            }
            self.remove_entry(&path, id);
        } else if self.commit(context).is_err() {
            self.remove_entry(&path, context.id.load(Ordering::Relaxed));
        }
    }

    fn set_delete(&self, context: &Handle, _name: &U16CStr, delete: bool) -> Result<()> {
        let path = self.current_path(context);
        if path == "\\" {
            return Err(STATUS_ACCESS_DENIED.into());
        }
        if delete {
            let tree = self.0.read().unwrap();
            if context.directory
                && tree
                    .0
                    .keys()
                    .any(|key| key.starts_with(&format!("{path}\\")))
            {
                return Err(STATUS_DIRECTORY_NOT_EMPTY.into());
            }
        }
        let mut local = context.local.lock().unwrap();
        if let Some(local) = local.as_mut() {
            if local.upload && !local.committed {
                if local.attempted {
                    return Err(STATUS_SHARING_VIOLATION.into());
                }
            }
        }
        context.cancelled.store(delete, Ordering::Relaxed);
        Ok(())
    }

    fn rename(
        &self,
        context: &Handle,
        _name: &U16CStr,
        new_name: &U16CStr,
        _replace: bool,
    ) -> Result<()> {
        let old = self.current_path(context);
        let new = new_name.to_string_lossy();
        let key = new.to_lowercase();
        let (entry, parent, source_parent) = {
            let tree = self.0.read().unwrap();
            let entry = tree
                .0
                .get(&old)
                .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?
                .clone();
            if old == "\\" || entry.id == 0 || context.cancelled.load(Ordering::Relaxed) {
                return Err(STATUS_ACCESS_DENIED.into());
            }
            if tree
                .0
                .iter()
                .any(|(p, e)| e.id == 0 && p.starts_with(&format!("{old}\\")))
            {
                return Err(STATUS_SHARING_VIOLATION.into());
            }
            if key != old && tree.0.contains_key(&key) {
                return Err(STATUS_OBJECT_NAME_COLLISION.into());
            }
            let parent = tree
                .0
                .get(tree::parent(&key))
                .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
            if !parent.directory {
                return Err(STATUS_NOT_A_DIRECTORY.into());
            }
            let source_parent = tree
                .0
                .get(tree::parent(&old))
                .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?
                .id;
            // Validate the complete subtree before changing anything on the backend.
            let mut proposed = (**tree).clone();
            proposed
                .relocate(&old, &new)
                .map_err(|_| STATUS_ACCESS_DENIED)?;
            (entry, parent.id, source_parent)
        };
        let leaf = new.rsplit('\\').next().unwrap_or("");
        self.3.request(
            serde_json::json!({"op":"relocate", "id":entry.id, "directory":entry.directory,
            "parent":parent, "sourceParent":source_parent, "name":leaf,
            "oldName":entry.path.rsplit('\\').next().unwrap()}),
        )?;
        let mut current = self.0.write().unwrap();
        let previous = current.clone();
        // A refresh may already have observed the server's new location.
        if let Some(source) = current
            .0
            .iter()
            .find(|(_, e)| e.id == entry.id && e.directory == entry.directory)
            .map(|(path, _)| path.clone())
        {
            Arc::make_mut(&mut current)
                .relocate(&source, &new)
                .map_err(|_| STATUS_IO_DEVICE_ERROR)?;
        }
        self.2
            .lock()
            .unwrap()
            .extend(crate::changes::diff(&previous, &current));
        Ok(())
    }

    fn flush(&self, context: Option<&Handle>, info: &mut FileInfo) -> Result<()> {
        if let Some(context) = context {
            // Flush can occur midway through CopyFile. Publishing here would upload
            // a truncated file; publish once on cleanup after the writer finishes.
            if let Some(local) = context.local.lock().unwrap().as_mut() {
                if local.upload && local.file.sync_all().is_err() {
                    local.attempted = true;
                    return Err(STATUS_IO_DEVICE_ERROR.into());
                }
            }
            self.get_file_info(context, info)?;
        }
        Ok(())
    }

    fn get_file_info(&self, context: &Handle, info: &mut FileInfo) -> Result<()> {
        let path = self.current_path(context);
        if let Some(entry) = self.0.read().unwrap().0.get(&path).filter(|e| {
            e.id == context.id.load(Ordering::Relaxed) && e.directory == context.directory
        }) {
            *info = entry.info();
        } else {
            *info = context
                .tree
                .lock()
                .unwrap()
                .0
                .get(&context.path)
                .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?
                .info();
        }
        if let Some(local) = context.local.lock().unwrap().as_ref() {
            info.file_size = local
                .file
                .metadata()
                .map_err(|_| STATUS_IO_DEVICE_ERROR)?
                .len();
            info.allocation_size = info.file_size;
        }
        Ok(())
    }

    fn read_directory(
        &self,
        context: &Handle,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> Result<u32> {
        let path = self.current_path(context);
        let mut snapshot = context.tree.lock().unwrap();
        if marker.is_none() {
            // F5/restarted enumeration must not remain pinned to an old handle snapshot.
            self.1.request();
            *snapshot = self.0.read().unwrap().clone();
        }
        let entry = snapshot.0.get(&path).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        if !entry.directory {
            return Err(STATUS_NOT_A_DIRECTORY.into());
        }
        // Keep the snapshot stable between continuation markers of this scan.
        let mut children = Vec::new();
        // Win32 recursive deletion enumerates even empty directories. Without
        // dot entries FindFirstFile reports FILE_NOT_FOUND instead of an empty folder.
        if path != "\\" {
            children.push((".", entry.info()));
            if let Some(parent) = snapshot.0.get(tree::parent(&path)) {
                children.push(("..", parent.info()));
            }
        }
        children.extend(
            snapshot
                .0
                .iter()
                .filter(|(key, _)| key.as_str() != "\\" && tree::parent(key) == path)
                .map(|(_, entry)| (entry.path.rsplit('\\').next().unwrap(), entry.info())),
        );
        let start = marker
            .inner_as_cstr()
            .map(|name| {
                let name = name.to_string_lossy();
                children
                    .iter()
                    .position(|(entry, _)| entry.to_lowercase() == name.to_lowercase())
                    .map_or(children.len(), |index| index + 1)
            })
            .unwrap_or(0);
        let mut written = 0;
        for (name, metadata) in children.iter().skip(start) {
            let mut info = DirInfo::<255>::new();
            *info.file_info_mut() = metadata.clone();
            info.set_name(*name)?;
            if !info.append_to_buffer(buffer, &mut written) {
                return Ok(written);
            }
        }
        DirInfo::<255>::finalize_buffer(buffer, &mut written);
        Ok(written)
    }

    fn read(&self, context: &Handle, buffer: &mut [u8], offset: u64) -> Result<u32> {
        let mut local = context.local.lock().unwrap();
        if local.is_none() {
            let entry = context.tree.lock().unwrap().0[&context.path].clone();
            if entry.directory {
                return Err(STATUS_FILE_IS_A_DIRECTORY.into());
            }
            let response = self
                .3
                .request(serde_json::json!({"op":"download","id":entry.id}))?;
            let name = response["file"].as_str().ok_or(STATUS_IO_DEVICE_ERROR)?;
            if name.contains(['/', '\\']) {
                return Err(STATUS_ACCESS_DENIED.into());
            }
            let path = self.4.join(name);
            let file = File::open(&path).map_err(|_| STATUS_IO_DEVICE_ERROR)?;
            *local = Some(LocalFile {
                file,
                path,
                upload: false,
                committed: true,
                attempted: false,
            });
        }
        let file = &mut local.as_mut().unwrap().file;
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| STATUS_IO_DEVICE_ERROR)?;
        Ok(file.read(buffer).map_err(|_| STATUS_IO_DEVICE_ERROR)? as u32)
    }

    fn write(
        &self,
        context: &Handle,
        buffer: &[u8],
        offset: u64,
        eof: bool,
        constrained: bool,
        info: &mut FileInfo,
    ) -> Result<u32> {
        let mut guard = context.local.lock().unwrap();
        let local = guard
            .as_mut()
            .filter(|l| l.upload && !l.attempted)
            .ok_or(STATUS_ACCESS_DENIED)?;
        let size = local
            .file
            .metadata()
            .map_err(|_| STATUS_IO_DEVICE_ERROR)?
            .len();
        let offset = if eof { size } else { offset };
        let length = if constrained {
            buffer.len().min(size.saturating_sub(offset) as usize)
        } else {
            buffer.len()
        };
        if local
            .file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| local.file.write_all(&buffer[..length]))
            .is_err()
        {
            local.attempted = true;
            return Err(STATUS_IO_DEVICE_ERROR.into());
        }
        let size = local
            .file
            .metadata()
            .map_err(|_| STATUS_IO_DEVICE_ERROR)?
            .len();
        drop(guard);
        if let Some(entry) = Arc::make_mut(&mut self.0.write().unwrap())
            .0
            .get_mut(&context.path)
        {
            entry.size = size;
        }
        self.get_file_info(context, info)?;
        Ok(length as u32)
    }

    fn set_file_size(
        &self,
        context: &Handle,
        size: u64,
        allocation: bool,
        info: &mut FileInfo,
    ) -> Result<()> {
        let mut guard = context.local.lock().unwrap();
        let local = guard
            .as_mut()
            .filter(|l| l.upload && !l.attempted)
            .ok_or(STATUS_ACCESS_DENIED)?;
        if !allocation
            || size
                < local
                    .file
                    .metadata()
                    .map_err(|_| STATUS_IO_DEVICE_ERROR)?
                    .len()
        {
            if local.file.set_len(size).is_err() {
                local.attempted = true;
                return Err(STATUS_IO_DEVICE_ERROR.into());
            }
        }
        drop(guard);
        self.get_file_info(context, info)
    }

    fn set_basic_info(
        &self,
        context: &Handle,
        _attrs: u32,
        _created: u64,
        _accessed: u64,
        _written: u64,
        _changed: u64,
        info: &mut FileInfo,
    ) -> Result<()> {
        self.get_file_info(context, info)
    }

    fn get_volume_info(&self, info: &mut VolumeInfo) -> Result<()> {
        // Uploads need local staging space; the backend enforces its own quota.
        let path = windows::core::HSTRING::from(self.4.as_os_str());
        unsafe {
            windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                &path,
                Some(&mut info.free_size),
                Some(&mut info.total_size),
                None,
            )
            .map_err(|_| STATUS_IO_DEVICE_ERROR)?;
        }
        info.set_volume_label("FD Client");
        Ok(())
    }
}
