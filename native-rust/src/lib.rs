mod dek_envelope;
mod account_context;
mod csemlk03;
mod content_crypto;
mod dpapi;
mod file_crypto;
mod kdf;
mod keystore;
mod key_id;
mod mldsa;
mod mldsa_keystore;
mod metadata_crypto;
mod metadata_view;
mod mlkem_keystore;
mod owner_envelope;
mod received_share;
mod share_envelope;
mod share_artifacts;
mod v3_artifacts;
mod v3_decrypt;

use jni::{
    EnvUnowned, jni_mangle,
    objects::{JByteArray, JString},
    strings::JNIString,
    sys::{jboolean, jbyteArray, jclass, jint, jlong, jstring},
};
use serde::Serialize;

use ml_kem::{
    EncapsulationKey1024, MlKem1024, TryKeyInit,
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
};

use std::fmt::Write;
use std::ptr::null_mut;

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "setAccountId")]
pub fn set_account_id<'local>(mut env: EnvUnowned<'local>, _class: jclass, account_id: jlong) {
    if account_id <= 0 || account_context::set(account_id as u64).is_err() {
        let _ = env.with_env(|env| env.throw_new(
            JNIString::from("java/lang/IllegalArgumentException"),
            JNIString::from("Account ID must be positive"),
        ));
    }
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "clearAccountId")]
pub fn clear_account_id<'local>(_env: EnvUnowned<'local>, _class: jclass) {
    account_context::clear();
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V3ArtifactsJson {
    client_file_id: String,
    container_path: String,
    manifest_path: String,
    signature_path: String,
    container_hash: String,
    container_size: u64,
    encryption_key_id: String,
    signing_key_id: String,
    revision: u64,
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        write!(&mut output, "{:02X}", *byte).expect("writing to a String should not fail");
    }

    output
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge")]
pub fn add<'local>(_env: EnvUnowned<'local>, _class: jclass, left: jint, right: jint) -> jint {
    left + right
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "generateAndPrintAes256Key")]
pub fn generate_and_print_aes256_key<'local>(_env: EnvUnowned<'local>, _class: jclass) {
    let mut key = [0u8; 32];

    if let Err(error) = getrandom::fill(&mut key) {
        eprintln!("Failed to generate AES-256 key: {error}");
        return;
    }

    println!("AES-256 key: {}", bytes_to_hex(&key));
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "generateAndPrintMlKem1024Keypair")]
pub fn generate_and_print_ml_kem_1024_keypair<'local>(_env: EnvUnowned<'local>, _class: jclass) {
    // Uses the operating system's cryptographically secure RNG.
    let (decapsulation_key, encapsulation_key) = MlKem1024::generate_keypair();

    // Public encapsulation key.
    let public_key_bytes = encapsulation_key.to_bytes();

    // The crate serializes the secret decapsulation key as a
    // 64-byte seed from which the complete private key is reconstructed.
    let private_key_seed = decapsulation_key.to_bytes();

    println!("ML-KEM-1024 PUBLIC KEY:");
    println!("{}", bytes_to_hex(public_key_bytes.as_ref()));

    println!("ML-KEM-1024 PRIVATE KEY SEED:");
    println!("{}", bytes_to_hex(private_key_seed.as_ref()));

    // Optional proof that the generated pair works:
    let (ciphertext, sender_shared_secret) = encapsulation_key.encapsulate();

    let receiver_shared_secret = decapsulation_key.decapsulate(&ciphertext);

    println!(
        "ML-KEM encapsulation test passed: {}",
        sender_shared_secret == receiver_shared_secret
    );

    println!(
        "ML-KEM shared secret: {}",
        bytes_to_hex(sender_shared_secret.as_ref())
    );
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "createStoredAes256Key")]
pub fn create_stored_aes256_key<'local>(_env: EnvUnowned<'local>, _class: jclass) -> jboolean {
    match keystore::generate_and_store_aes256_key() {
        Ok(path) => {
            println!("Created DPAPI-protected AES-256 key at: {}", path.display());
            true
        }

        Err(error) => {
            eprintln!("Could not create AES-256 key: {error}");
            false
        }
    }
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "verifyStoredAes256Key")]
pub fn verify_stored_aes256_key<'local>(_env: EnvUnowned<'local>, _class: jclass) -> jboolean {
    match keystore::load_aes256_key() {
        Ok(key) => {
            println!(
                "Successfully loaded a protected AES-256 key: {} bytes",
                key.len()
            );

            // `key` is zeroized when dropped.
            true
        }

        Err(error) => {
            eprintln!("Could not load AES-256 key: {error}");
            false
        }
    }
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "createStoredMlKem1024Keypair")]
pub fn create_stored_ml_kem1024_keypair<'local>(
    _env: EnvUnowned<'local>,
    _class: jclass,
) -> jboolean {
    match mlkem_keystore::generate_and_store_ml_kem1024_keypair() {
        Ok(paths) => {
            println!(
                "Created ML-KEM-1024 private key at: {}",
                paths.private_key_path.display()
            );

            println!(
                "Created ML-KEM-1024 public key at: {}",
                paths.public_key_path.display()
            );

            true
        }

        Err(error) => {
            eprintln!(
                "Could not create ML-KEM-1024 keypair: \
                 {error}"
            );

            false
        }
    }
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "verifyStoredMlKem1024Keypair")]
pub fn verify_stored_ml_kem1024_keypair<'local>(
    _env: EnvUnowned<'local>,
    _class: jclass,
) -> jboolean {
    match mlkem_keystore::verify_stored_ml_kem1024_keypair() {
        Ok(()) => {
            println!("Stored ML-KEM-1024 keypair verified");

            true
        }

        Err(error) => {
            eprintln!(
                "Could not verify ML-KEM-1024 keypair: \
                 {error}"
            );

            false
        }
    }
}
#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "testStoredMlKemDekEnvelope")]
pub fn test_stored_ml_kem_dek_envelope<'local>(
    _env: EnvUnowned<'local>,
    _class: jclass,
) -> jboolean {
    let private_key = match mlkem_keystore::load_stored_ml_kem1024_decapsulation_key() {
        Ok(key) => key,

        Err(error) => {
            eprintln!("Could not load stored ML-KEM keypair: {error}");
            return false;
        }
    };

    let original_dek = match dek_envelope::generate_dek() {
        Ok(dek) => dek,

        Err(error) => {
            eprintln!("Could not generate AES-256 DEK: {error}");
            return false;
        }
    };

    let envelope = match dek_envelope::wrap_dek(private_key.encapsulation_key(), &*original_dek) {
        Ok(envelope) => envelope,

        Err(error) => {
            eprintln!("Could not wrap AES-256 DEK: {error}");
            return false;
        }
    };

    let recovered_dek = match dek_envelope::unwrap_dek(&private_key, &envelope) {
        Ok(dek) => dek,

        Err(error) => {
            eprintln!("Could not unwrap AES-256 DEK: {error}");
            return false;
        }
    };

    let keys_match = original_dek.as_slice() == recovered_dek.as_slice();

    if keys_match {
        println!("AES-256 DEK wrapped and unwrapped successfully");

        println!(
            "ML-KEM ciphertext: {} bytes",
            envelope.ml_kem_ciphertext.len()
        );

        println!("Wrapped DEK: {} bytes", envelope.wrapped_dek.len());
    } else {
        eprintln!("Recovered AES-256 DEK did not match the original");
    }

    keys_match
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "encryptSelectedFile")]
pub fn encrypt_selected_file<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: jclass,
    input_path: JString<'local>,
) -> jboolean {
    unowned_env
        .with_env(|env| -> Result<jboolean, jni::errors::Error> {
            let input_path = input_path.try_to_string(env)?;

            let succeeded = match file_crypto::encrypt_file(std::path::Path::new(&input_path)) {
                Ok(output_path) => {
                    println!("File encrypted successfully");

                    println!("Encrypted output: {}", output_path.display());

                    true
                }

                Err(error) => {
                    eprintln!("File encryption failed: {error}");

                    false
                }
            };

            Ok(succeeded)
        })
        .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "decryptSelectedFile")]
pub fn decrypt_selected_file<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: jclass,
    input_path: JString<'local>,
) -> jboolean {
    unowned_env
        .with_env(|env| -> Result<jboolean, jni::errors::Error> {
            let input_path = input_path.try_to_string(env)?;

            let succeeded = match file_crypto::decrypt_file(std::path::Path::new(&input_path)) {
                Ok(output_path) => {
                    println!("File decrypted successfully");

                    println!("Decrypted output: {}", output_path.display());

                    true
                }

                Err(error) => {
                    eprintln!("File decryption failed: {error}");

                    false
                }
            };

            Ok(succeeded)
        })
        .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}


#[jni_mangle(
    "kakha.kudava.fdclient.crypto.NativeCryptoBridge",
    "decryptSelectedFileTo"
)]
pub fn decrypt_selected_file_to<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: jclass,
    input_path: JString<'local>,
    output_path: JString<'local>,
    overwrite: jboolean,
) -> jboolean {
    unowned_env
        .with_env(
            |env| -> Result<
                jboolean,
                jni::errors::Error,
            > {
                let input_path =
                    input_path.try_to_string(env)?;

                let output_path =
                    output_path.try_to_string(env)?;

                let succeeded =
                    match file_crypto::decrypt_file_to(
                        std::path::Path::new(
                            &input_path,
                        ),
                        std::path::Path::new(
                            &output_path,
                        ),
                        overwrite,
                    ) {
                        Ok(created_path) => {
                            println!(
                                "File decrypted successfully"
                            );

                            println!(
                                "Decrypted output: {}",
                                created_path.display()
                            );

                            true
                        }

                        Err(error) => {
                            eprintln!(
                                "File decryption failed: {error}"
                            );

                            false
                        }
                    };

                Ok(succeeded)
            },
        )
        .resolve::<
            jni::errors::ThrowRuntimeExAndDefault,
        >()
}

#[jni_mangle(
    "kakha.kudava.fdclient.crypto.NativeCryptoBridge",
    "getFileCryptoProgress"
)]
pub fn get_file_crypto_progress<'local>(
    _env: EnvUnowned<'local>,
    _class: jclass,
) -> jint {
    file_crypto::file_operation_progress() as jint
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "encryptFileV3")]
pub fn encrypt_file_v3_jni<'local>(
    mut unowned_env: EnvUnowned<'local>, _class: jclass,
    input_path: JString<'local>, output_directory: JString<'local>,
    original_file_name: JString<'local>, mime_type: JString<'local>,
    device_id: JByteArray<'local>, created_at: jlong, modified_at: jlong,
) -> jstring {
    unowned_env.with_env(|env| -> Result<jstring, jni::errors::Error> {
        let result = (|| -> Result<String, String> {
            let input_path = input_path.try_to_string(env).map_err(|e| e.to_string())?;
            let output_directory = output_directory.try_to_string(env).map_err(|e| e.to_string())?;
            let original_file_name = original_file_name.try_to_string(env).map_err(|e| e.to_string())?;
            let mime_type = mime_type.try_to_string(env).map_err(|e| e.to_string())?;
            let device_bytes = env.convert_byte_array(&device_id).map_err(|e| e.to_string())?;
            let device_id: [u8; 16] = device_bytes.try_into()
                .map_err(|_| "device ID must contain exactly 16 bytes".to_string())?;
            let encryption_key = mlkem_keystore::load_stored_ml_kem1024_encapsulation_key()
                .map_err(|e| e.to_string())?;
            let signing_key = mldsa_keystore::load_stored_signing_key()
                .map_err(|e| e.to_string())?;
            let artifacts = v3_artifacts::encrypt_file_v3(
                &v3_artifacts::EncryptV3Request {
                    input_path: input_path.into(), output_directory: output_directory.into(),
                    original_file_name, mime_type, device_id, revision: 1,
                    previous_manifest_hash: [0; 64], created_at_unix_millis: created_at,
                    modified_at_unix_millis: modified_at,
                },
                &v3_artifacts::V3EncryptionKeys {
                    encryption_public_key: &encryption_key,
                    signing_private_seed: signing_key.private_seed(),
                    signing_public_key: signing_key.public_key(),
                },
            ).map_err(|e| e.to_string())?;
            serde_json::to_string(&V3ArtifactsJson {
                client_file_id: v3_artifacts::format_uuid_public(&artifacts.client_file_id),
                container_path: artifacts.container_path.to_string_lossy().into_owned(),
                manifest_path: artifacts.manifest_path.to_string_lossy().into_owned(),
                signature_path: artifacts.signature_path.to_string_lossy().into_owned(),
                container_hash: bytes_to_hex(&artifacts.container_hash).to_lowercase(),
                container_size: artifacts.container_size,
                encryption_key_id: bytes_to_hex(&artifacts.encryption_key_id).to_lowercase(),
                signing_key_id: bytes_to_hex(&artifacts.signing_key_id).to_lowercase(),
                revision: artifacts.revision,
            }).map_err(|e| e.to_string())
        })();
        match result {
            Ok(json) => Ok(env.new_string(json)?.into_raw()),
            Err(error) => {
                eprintln!("CSEMLK03 encryption failed: {error}");
                env.throw_new(JNIString::from("java/lang/IllegalStateException"),
                    JNIString::from(format!("CSEMLK03 encryption failed: {error}")))?;
                Ok(null_mut())
            }
        }
    }).resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

fn native_bytes<'local>(
    mut unowned_env: EnvUnowned<'local>,
    operation: impl FnOnce() -> Result<Vec<u8>, String>,
) -> jbyteArray {
    unowned_env
        .with_env(|env| -> Result<jbyteArray, jni::errors::Error> {
            match operation() {
                Ok(bytes) => Ok(env.byte_array_from_slice(&bytes)?.into_raw()),
                Err(error) => {
                    eprintln!("Native Lockbox operation failed: {error}");
                    Ok(null_mut())
                }
            }
        })
        .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "getStoredMlKem1024PublicKey")]
pub fn get_stored_ml_kem1024_public_key<'local>(
    env: EnvUnowned<'local>,
    _class: jclass,
) -> jbyteArray {
    native_bytes(env, || {
        mlkem_keystore::stored_ml_kem1024_public_key().map_err(|e| e.to_string())
    })
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "getStoredMlDsa87PublicKey")]
pub fn get_stored_ml_dsa87_public_key<'local>(
    env: EnvUnowned<'local>,
    _class: jclass,
) -> jbyteArray {
    native_bytes(env, || mldsa_keystore::public_key().map_err(|e| e.to_string()))
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "getStoredMlDsa87KeyId")]
pub fn get_stored_ml_dsa87_key_id<'local>(
    env: EnvUnowned<'local>,
    _class: jclass,
) -> jbyteArray {
    native_bytes(env, || {
        let public_key = mldsa_keystore::public_key().map_err(|error| error.to_string())?;
        Ok(key_id::from_public_key(&public_key).to_vec())
    })
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "signWithStoredMlDsa87")]
pub fn sign_with_stored_ml_dsa87<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: jclass,
    message: JByteArray<'local>,
) -> jbyteArray {
    unowned_env
        .with_env(|env| -> Result<jbyteArray, jni::errors::Error> {
            let message = env.convert_byte_array(&message)?;
            match mldsa_keystore::sign(&message) {
                Ok(signature) => Ok(env.byte_array_from_slice(&signature)?.into_raw()),
                Err(error) => {
                    eprintln!("Native Lockbox signing failed: {error}");
                    Ok(null_mut())
                }
            }
        })
        .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[jni_mangle(
    "kakha.kudava.fdclient.crypto.NativeCryptoBridge",
    "createRecipientShareEnvelopeV1"
)]
pub fn create_recipient_share_envelope_v1<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: jclass,
    container_path: JString<'local>,
    manifest_path: JString<'local>,
    signature_path: JString<'local>,
    owner_public_uuid: JByteArray<'local>,
    recipient_public_uuid: JByteArray<'local>,
    recipient_ml_kem_public_key: JByteArray<'local>,
    expires_at_unix_seconds: jlong,
) -> jbyteArray {
    unowned_env
        .with_env(|env| -> Result<jbyteArray, jni::errors::Error> {
            let result = (|| -> Result<Vec<u8>, String> {
                if expires_at_unix_seconds < 0 {
                    return Err("expiry must be zero or a positive Unix timestamp".into());
                }

                let container_path = container_path
                    .try_to_string(env)
                    .map_err(|error| error.to_string())?;
                let manifest_path = manifest_path
                    .try_to_string(env)
                    .map_err(|error| error.to_string())?;
                let signature_path = signature_path
                    .try_to_string(env)
                    .map_err(|error| error.to_string())?;
                let owner_public_uuid: [u8; 16] = env
                    .convert_byte_array(&owner_public_uuid)
                    .map_err(|error| error.to_string())?
                    .try_into()
                    .map_err(|_| "owner public UUID must contain exactly 16 bytes")?;
                let recipient_public_uuid: [u8; 16] = env
                    .convert_byte_array(&recipient_public_uuid)
                    .map_err(|error| error.to_string())?
                    .try_into()
                    .map_err(|_| "recipient public UUID must contain exactly 16 bytes")?;
                let recipient_public_key_bytes = env
                    .convert_byte_array(&recipient_ml_kem_public_key)
                    .map_err(|error| error.to_string())?;
                let recipient_public_key = EncapsulationKey1024::new_from_slice(
                    &recipient_public_key_bytes,
                )
                .map_err(|_| "recipient ML-KEM-1024 public key is invalid")?;
                let owner_encryption_private =
                    mlkem_keystore::load_stored_ml_kem1024_decapsulation_key()
                        .map_err(|error| error.to_string())?;
                let owner_signing_public = mldsa_keystore::public_key()
                    .map_err(|error| error.to_string())?;

                share_artifacts::create_recipient_envelope_package(
                    &share_artifacts::CreateRecipientEnvelopeRequest {
                        container_path: std::path::Path::new(&container_path),
                        manifest_path: std::path::Path::new(&manifest_path),
                        signature_path: std::path::Path::new(&signature_path),
                        owner_account_id: owner_public_uuid,
                        recipient_account_id: recipient_public_uuid,
                        recipient_public_key: &recipient_public_key,
                        expires_at_unix_seconds: expires_at_unix_seconds as u64,
                    },
                    &share_artifacts::OwnerShareKeys {
                        encryption_private_key: &owner_encryption_private,
                        signing_public_key: &owner_signing_public,
                    },
                )
                .map_err(|error| error.to_string())
            })();

            match result {
                Ok(package) => Ok(env.byte_array_from_slice(&package)?.into_raw()),
                Err(error) => {
                    env.throw_new(
                        JNIString::from("java/lang/IllegalStateException"),
                        JNIString::from(format!(
                            "Could not create recipient share envelope: {error}"
                        )),
                    )?;
                    Ok(null_mut())
                }
            }
        })
        .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "decryptPrivateMetadataV3")]
pub fn decrypt_private_metadata_v3<'local>(
    mut unowned_env: EnvUnowned<'local>, _class: jclass,
    manifest: JByteArray<'local>, signature: JByteArray<'local>, header: JByteArray<'local>,
) -> jstring {
    unowned_env.with_env(|env| -> Result<jstring, jni::errors::Error> {
        let result = (|| -> Result<String, String> {
            let manifest = env.convert_byte_array(&manifest).map_err(|e| e.to_string())?;
            let signature = env.convert_byte_array(&signature).map_err(|e| e.to_string())?;
            let header = env.convert_byte_array(&header).map_err(|e| e.to_string())?;
            let signing_public = mldsa_keystore::public_key().map_err(|e| e.to_string())?;
            let encryption_private = mlkem_keystore::load_stored_ml_kem1024_decapsulation_key()
                .map_err(|e| e.to_string())?;
            let view = metadata_view::decrypt_private_metadata(
                &manifest, &signature, &header, &signing_public, &encryption_private,
            ).map_err(|e| e.to_string())?;
            serde_json::to_string(&view).map_err(|e| e.to_string())
        })();
        match result {
            Ok(json) => Ok(env.new_string(json)?.into_raw()),
            Err(error) => {
                eprintln!("Private Lockbox metadata failed: {error}");
                env.throw_new(JNIString::from("java/lang/IllegalStateException"),
                    JNIString::from(format!("Private Lockbox metadata failed: {error}")))?;
                Ok(null_mut())
            }
        }
    }).resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[jni_mangle(
    "kakha.kudava.fdclient.crypto.NativeCryptoBridge",
    "decryptReceivedShareMetadataV1"
)]
pub fn decrypt_received_share_metadata_v1<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: jclass,
    recipient_envelope: JByteArray<'local>,
    owner_share_signature: JByteArray<'local>,
    owner_signing_key_id: JByteArray<'local>,
    owner_signing_public_key: JByteArray<'local>,
    manifest: JByteArray<'local>,
    file_signature: JByteArray<'local>,
    encrypted_header: JByteArray<'local>,
    expected_share_uuid: JByteArray<'local>,
    expected_recipient_public_uuid: JByteArray<'local>,
    expected_client_file_uuid: JByteArray<'local>,
    expected_revision: jlong,
) -> jstring {
    unowned_env.with_env(|env| -> Result<jstring, jni::errors::Error> {
        let result = (|| -> Result<String, String> {
            if expected_revision < 1 {
                return Err("expected revision must be positive".into());
            }
            let as_uuid = |bytes: Vec<u8>, name: &str| -> Result<[u8; 16], String> {
                bytes.try_into().map_err(|_| format!("{name} must contain exactly 16 bytes"))
            };
            let recipient_envelope = env.convert_byte_array(&recipient_envelope)
                .map_err(|e| e.to_string())?;
            let owner_share_signature = env.convert_byte_array(&owner_share_signature)
                .map_err(|e| e.to_string())?;
            let owner_signing_key_id = env.convert_byte_array(&owner_signing_key_id)
                .map_err(|e| e.to_string())?;
            let owner_signing_public_key = env.convert_byte_array(&owner_signing_public_key)
                .map_err(|e| e.to_string())?;
            let manifest = env.convert_byte_array(&manifest).map_err(|e| e.to_string())?;
            let file_signature = env.convert_byte_array(&file_signature)
                .map_err(|e| e.to_string())?;
            let encrypted_header = env.convert_byte_array(&encrypted_header)
                .map_err(|e| e.to_string())?;
            let request = received_share::ReceivedShareRequest {
                envelope_package: &recipient_envelope,
                owner_share_signature: &owner_share_signature,
                owner_signing_key_id: &owner_signing_key_id,
                owner_signing_public_key: &owner_signing_public_key,
                manifest: &manifest,
                file_signature: &file_signature,
                encrypted_header: &encrypted_header,
                expected_share_id: as_uuid(
                    env.convert_byte_array(&expected_share_uuid).map_err(|e| e.to_string())?,
                    "expected share UUID",
                )?,
                expected_recipient_account_id: as_uuid(
                    env.convert_byte_array(&expected_recipient_public_uuid)
                        .map_err(|e| e.to_string())?,
                    "expected recipient public UUID",
                )?,
                expected_client_file_id: as_uuid(
                    env.convert_byte_array(&expected_client_file_uuid).map_err(|e| e.to_string())?,
                    "expected client file UUID",
                )?,
                expected_revision: expected_revision as u64,
            };
            let recipient_private = mlkem_keystore::load_stored_ml_kem1024_decapsulation_key()
                .map_err(|e| e.to_string())?;
            let view = received_share::decrypt_received_metadata(&request, &recipient_private)
                .map_err(|e| e.to_string())?;
            serde_json::to_string(&view).map_err(|e| e.to_string())
        })();
        match result {
            Ok(json) => Ok(env.new_string(json)?.into_raw()),
            Err(error) => {
                eprintln!("Received Lockbox share metadata failed: {error}");
                env.throw_new(
                    JNIString::from("java/lang/IllegalStateException"),
                    JNIString::from(format!("Received Lockbox share metadata failed: {error}")),
                )?;
                Ok(null_mut())
            }
        }
    }).resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[jni_mangle("kakha.kudava.fdclient.crypto.NativeCryptoBridge", "decryptOwnedFileV3")]
pub fn decrypt_owned_file_v3<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: jclass,
    container_path: JString<'local>,
    manifest: JByteArray<'local>,
    signature: JByteArray<'local>,
    output_path: JString<'local>,
) -> jboolean {
    unowned_env.with_env(|env| -> Result<jboolean, jni::errors::Error> {
        let result = (|| -> Result<(), String> {
            let container_path = container_path.try_to_string(env).map_err(|e| e.to_string())?;
            let output_path = output_path.try_to_string(env).map_err(|e| e.to_string())?;
            let manifest = env.convert_byte_array(&manifest).map_err(|e| e.to_string())?;
            let signature = env.convert_byte_array(&signature).map_err(|e| e.to_string())?;
            let signing_public = mldsa_keystore::public_key().map_err(|e| e.to_string())?;
            let encryption_private = mlkem_keystore::load_stored_ml_kem1024_decapsulation_key()
                .map_err(|e| e.to_string())?;
            v3_decrypt::decrypt_owned_to(
                std::path::Path::new(&container_path), &manifest, &signature,
                std::path::Path::new(&output_path), &signing_public, &encryption_private,
            ).map_err(|e| e.to_string())
        })();
        match result {
            Ok(()) => Ok(true),
            Err(error) => {
                env.throw_new(
                    JNIString::from("java/lang/IllegalStateException"),
                    JNIString::from(format!("Lockbox decrypt and export failed: {error}")),
                )?;
                Ok(false)
            }
        }
    }).resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[jni_mangle(
    "kakha.kudava.fdclient.crypto.NativeCryptoBridge",
    "decryptReceivedShareFileV1"
)]
pub fn decrypt_received_share_file_v1<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: jclass,
    container_path: JString<'local>,
    output_path: JString<'local>,
    recipient_envelope: JByteArray<'local>,
    owner_share_signature: JByteArray<'local>,
    owner_signing_key_id: JByteArray<'local>,
    owner_signing_public_key: JByteArray<'local>,
    manifest: JByteArray<'local>,
    file_signature: JByteArray<'local>,
    encrypted_header: JByteArray<'local>,
    expected_share_uuid: JByteArray<'local>,
    expected_recipient_public_uuid: JByteArray<'local>,
    expected_client_file_uuid: JByteArray<'local>,
    expected_revision: jlong,
) -> jboolean {
    unowned_env.with_env(|env| -> Result<jboolean, jni::errors::Error> {
        let result = (|| -> Result<(), String> {
            if expected_revision < 1 { return Err("expected revision must be positive".into()); }
            let uuid = |value: &JByteArray<'local>, name: &str| -> Result<[u8; 16], String> {
                env.convert_byte_array(value).map_err(|e| e.to_string())?.try_into()
                    .map_err(|_| format!("{name} must contain exactly 16 bytes"))
            };
            let container_path = container_path.try_to_string(env).map_err(|e| e.to_string())?;
            let output_path = output_path.try_to_string(env).map_err(|e| e.to_string())?;
            let envelope = env.convert_byte_array(&recipient_envelope).map_err(|e| e.to_string())?;
            let share_signature = env.convert_byte_array(&owner_share_signature).map_err(|e| e.to_string())?;
            let signing_key_id = env.convert_byte_array(&owner_signing_key_id).map_err(|e| e.to_string())?;
            let signing_public = env.convert_byte_array(&owner_signing_public_key).map_err(|e| e.to_string())?;
            let manifest = env.convert_byte_array(&manifest).map_err(|e| e.to_string())?;
            let file_signature = env.convert_byte_array(&file_signature).map_err(|e| e.to_string())?;
            let header = env.convert_byte_array(&encrypted_header).map_err(|e| e.to_string())?;
            let request = received_share::ReceivedShareRequest {
                envelope_package: &envelope,
                owner_share_signature: &share_signature,
                owner_signing_key_id: &signing_key_id,
                owner_signing_public_key: &signing_public,
                manifest: &manifest,
                file_signature: &file_signature,
                encrypted_header: &header,
                expected_share_id: uuid(&expected_share_uuid, "share UUID")?,
                expected_recipient_account_id: uuid(&expected_recipient_public_uuid, "recipient UUID")?,
                expected_client_file_id: uuid(&expected_client_file_uuid, "client file UUID")?,
                expected_revision: expected_revision as u64,
            };
            let recipient_private = mlkem_keystore::load_stored_ml_kem1024_decapsulation_key()
                .map_err(|e| e.to_string())?;
            v3_decrypt::decrypt_shared_to(
                std::path::Path::new(&container_path), std::path::Path::new(&output_path),
                &request, &recipient_private,
            ).map_err(|e| e.to_string())
        })();
        match result {
            Ok(()) => Ok(true),
            Err(error) => {
                env.throw_new(
                    JNIString::from("java/lang/IllegalStateException"),
                    JNIString::from(format!("Shared Lockbox decrypt and export failed: {error}")),
                )?;
                Ok(false)
            }
        }
    }).resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}
