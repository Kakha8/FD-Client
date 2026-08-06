use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use thiserror::Error;

use crate::{dpapi, mldsa};

const PRIVATE_KEY_FILE_NAME: &str = "ml-dsa-87-private.dpapi";
const PUBLIC_KEY_FILE_NAME: &str = "ml-dsa-87-public.bin";

#[derive(Debug, Error)]
pub enum MlDsaKeystoreError {
    #[error("LOCALAPPDATA is not available")]
    MissingLocalAppData,
    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("DPAPI operation failed: {0}")]
    Dpapi(#[from] dpapi::DpapiError),
    #[error("ML-DSA-87 key material already exists")]
    AlreadyExists,
    #[error("stored ML-DSA-87 private seed is invalid")]
    InvalidPrivateSeed,
    #[error("stored ML-DSA-87 public key is invalid")]
    InvalidPublicKey,
    #[error("stored ML-DSA-87 public key does not match its private seed")]
    PublicKeyMismatch,
    #[error("ML-DSA operation failed: {0}")]
    MlDsa(#[from] mldsa::MlDsaError),
}

fn key_paths() -> Result<(PathBuf, PathBuf), MlDsaKeystoreError> {
    let local_app_data =
        env::var_os("LOCALAPPDATA").ok_or(MlDsaKeystoreError::MissingLocalAppData)?;
    let directory = PathBuf::from(local_app_data).join("CSE-ML-KEM");
    Ok((
        directory.join(PRIVATE_KEY_FILE_NAME),
        directory.join(PUBLIC_KEY_FILE_NAME),
    ))
}

pub fn ensure_keypair() -> Result<(), MlDsaKeystoreError> {
    let (private_path, public_path) = key_paths()?;

    if private_path.exists() && public_path.exists() {
        verify_keypair(&private_path, &public_path)?;
        return Ok(());
    }
    if private_path.exists() || public_path.exists() {
        return Err(MlDsaKeystoreError::PublicKeyMismatch);
    }

    let keypair = mldsa::generate_mldsa87_keypair();
    let protected_seed = dpapi::protect(keypair.private_seed())?;

    if let Some(parent) = private_path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_new_file(&private_path, &protected_seed)?;
    if let Err(error) = write_new_file(&public_path, keypair.public_key()) {
        let _ = fs::remove_file(private_path);
        return Err(error);
    }

    Ok(())
}

pub fn public_key() -> Result<Vec<u8>, MlDsaKeystoreError> {
    ensure_keypair()?;
    let (_, public_path) = key_paths()?;
    let public_key = fs::read(public_path)?;
    if public_key.len() != mldsa::ML_DSA_87_PUBLIC_KEY_LENGTH {
        return Err(MlDsaKeystoreError::InvalidPublicKey);
    }
    Ok(public_key)
}

pub fn sign(message: &[u8]) -> Result<Vec<u8>, MlDsaKeystoreError> {
    ensure_keypair()?;
    let (private_path, _) = key_paths()?;
    let protected_seed = fs::read(private_path)?;
    let seed = dpapi::unprotect(&protected_seed)?;
    let signature = mldsa::sign_mldsa87(seed.as_slice(), message)?;
    Ok(signature.to_vec())
}

fn verify_keypair(private_path: &Path, public_path: &Path) -> Result<(), MlDsaKeystoreError> {
    let protected_seed = fs::read(private_path)?;
    let seed = dpapi::unprotect(&protected_seed)?;
    if seed.len() != mldsa::ML_DSA_87_PRIVATE_SEED_LENGTH {
        return Err(MlDsaKeystoreError::InvalidPrivateSeed);
    }
    let stored_public = fs::read(public_path)?;
    if stored_public.len() != mldsa::ML_DSA_87_PUBLIC_KEY_LENGTH {
        return Err(MlDsaKeystoreError::InvalidPublicKey);
    }
    let test_message = b"FD-LOCKBOX-ML-DSA-87-KEY-CHECK\0";
    let signature = mldsa::sign_mldsa87(seed.as_slice(), test_message)?;
    mldsa::verify_mldsa87(&stored_public, test_message, &signature)
        .map_err(|_| MlDsaKeystoreError::PublicKeyMismatch)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), MlDsaKeystoreError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                MlDsaKeystoreError::AlreadyExists
            } else {
                error.into()
            }
        })?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
