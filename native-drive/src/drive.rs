use crate::tree::{self, Tree};
use std::ffi::c_void;
use std::sync::{Arc, Mutex, RwLock};
use windows::Win32::Foundation::{
    STATUS_FILE_IS_A_DIRECTORY, STATUS_NOT_A_DIRECTORY, STATUS_NOT_SUPPORTED,
    STATUS_OBJECT_NAME_NOT_FOUND,
};
use winfsp::filesystem::{
    DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo, VolumeInfo,
    WideNameInfo,
};
use winfsp::{Result, U16CStr};

pub struct MetadataDrive(pub Arc<RwLock<Arc<Tree>>>, pub Arc<crate::refresh::Refresh>);
pub struct Handle {
    tree: Mutex<Arc<Tree>>,
    path: String,
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
        _access: u32,
        info: &mut OpenFileInfo,
    ) -> Result<Handle> {
        let tree = self.0.read().unwrap().clone();
        let key = name.to_string_lossy().to_lowercase();
        let entry = tree.0.get(&key).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        if entry.directory && options & 0x40 != 0 {
            return Err(STATUS_FILE_IS_A_DIRECTORY.into());
        }
        if !entry.directory && options & 1 != 0 {
            return Err(STATUS_NOT_A_DIRECTORY.into());
        }
        *info.as_mut() = entry.info();
        Ok(Handle {
            tree: Mutex::new(tree),
            path: key,
        })
    }

    fn close(&self, _context: Handle) {}

    fn get_file_info(&self, context: &Handle, info: &mut FileInfo) -> Result<()> {
        *info = context
            .tree
            .lock()
            .unwrap()
            .0
            .get(&context.path)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?
            .info();
        Ok(())
    }

    fn read_directory(
        &self,
        context: &Handle,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> Result<u32> {
        let mut snapshot = context.tree.lock().unwrap();
        if marker.is_none() {
            // F5/restarted enumeration must not remain pinned to an old handle snapshot.
            self.1.request();
            *snapshot = self.0.read().unwrap().clone();
        }
        let entry = snapshot
            .0
            .get(&context.path)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        if !entry.directory {
            return Err(STATUS_NOT_A_DIRECTORY.into());
        }
        // Keep the snapshot stable between continuation markers of this scan.
        let children: Vec<_> = snapshot
            .0
            .iter()
            .filter(|(path, _)| path.as_str() != "\\" && tree::parent(path) == context.path)
            .map(|(_, entry)| entry)
            .collect();
        let start = marker
            .inner_as_cstr()
            .map(|name| {
                let name = name.to_string_lossy();
                children
                    .iter()
                    .position(|entry| entry.path.rsplit('\\').next() == Some(name.as_str()))
                    .map_or(children.len(), |index| index + 1)
            })
            .unwrap_or(0);
        let mut written = 0;
        for entry in children.iter().skip(start) {
            let mut info = DirInfo::<255>::new();
            *info.file_info_mut() = entry.info();
            info.set_name(entry.path.rsplit('\\').next().unwrap())?;
            if !info.append_to_buffer(buffer, &mut written) {
                return Ok(written);
            }
        }
        DirInfo::<255>::finalize_buffer(buffer, &mut written);
        Ok(written)
    }

    fn read(&self, _context: &Handle, _buffer: &mut [u8], _offset: u64) -> Result<u32> {
        Err(STATUS_NOT_SUPPORTED.into())
    }

    fn get_volume_info(&self, info: &mut VolumeInfo) -> Result<()> {
        info.total_size = 0;
        info.free_size = 0;
        info.set_volume_label("FD Client");
        Ok(())
    }
}
