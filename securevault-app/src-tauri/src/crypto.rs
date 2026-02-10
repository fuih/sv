//! Cryptographic utilities for SecureVault
//! Implements Argon2id key derivation and AES-256-GCM encryption

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroizing;

/// Size constants
pub const SALT_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const KEY_SIZE: usize = 32;

/// Argon2id parameters (memory-hard for brute-force resistance)
const ARGON2_MEMORY_KB: u32 = 65536; // 64 MB
const ARGON2_ITERATIONS: u32 = 4;
const ARGON2_PARALLELISM: u32 = 4;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Invalid data format")]
    InvalidFormat,
}

/// Generate a cryptographically secure random salt
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a cryptographically secure random nonce
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Derive a 256-bit encryption key from master password using Argon2id
/// 
/// # Security
/// - Uses Argon2id (winner of Password Hashing Competition)
/// - Memory-hard to resist GPU/ASIC attacks
/// - Returns Zeroizing wrapper for automatic memory clearing
pub fn derive_key(
    master_password: &str,
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_SIZE]>, CryptoError> {
    let params = Params::new(
        ARGON2_MEMORY_KB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(KEY_SIZE),
    )
    .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    argon2
        .hash_password_into(master_password.as_bytes(), salt, key.as_mut())
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;

    Ok(key)
}

/// Encrypt plaintext using AES-256-GCM
/// 
/// # Returns
/// Concatenated: nonce (12 bytes) || ciphertext || auth_tag (16 bytes)
pub fn encrypt(key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend(ciphertext);

    Ok(result)
}

/// Decrypt ciphertext using AES-256-GCM
/// 
/// # Arguments
/// * `encrypted_data` - nonce (12 bytes) || ciphertext || auth_tag (16 bytes)
pub fn decrypt(key: &[u8; KEY_SIZE], encrypted_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if encrypted_data.len() < NONCE_SIZE + 16 {
        // 16 = auth tag size
        return Err(CryptoError::InvalidFormat);
    }

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::Decryption(e.to_string()))
}

/// Encrypt a string and return base64-encoded result
pub fn encrypt_string(key: &[u8; KEY_SIZE], plaintext: &str) -> Result<String, CryptoError> {
    let encrypted = encrypt(key, plaintext.as_bytes())?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        encrypted,
    ))
}

/// Decrypt a base64-encoded string
pub fn decrypt_string(key: &[u8; KEY_SIZE], encrypted_b64: &str) -> Result<String, CryptoError> {
    let encrypted = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encrypted_b64)
        .map_err(|_| CryptoError::InvalidFormat)?;
    let decrypted = decrypt(key, &encrypted)?;
    String::from_utf8(decrypted).map_err(|_| CryptoError::InvalidFormat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let salt = generate_salt();
        let key = derive_key("test_password_123", &salt).unwrap();
        assert_eq!(key.len(), KEY_SIZE);
        
        // Same password + salt = same key
        let key2 = derive_key("test_password_123", &salt).unwrap();
        assert_eq!(key.as_ref(), key2.as_ref());
        
        // Different password = different key
        let key3 = derive_key("different_password", &salt).unwrap();
        assert_ne!(key.as_ref(), key3.as_ref());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let salt = generate_salt();
        let key = derive_key("master_password", &salt).unwrap();
        
        let plaintext = b"My secret password!";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_string_encrypt_decrypt() {
        let salt = generate_salt();
        let key = derive_key("master_password", &salt).unwrap();
        
        let secret = "MySecretPassword123!";
        let encrypted = encrypt_string(&key, secret).unwrap();
        let decrypted = decrypt_string(&key, &encrypted).unwrap();
        
        assert_eq!(secret, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let salt = generate_salt();
        let key1 = derive_key("password1", &salt).unwrap();
        let key2 = derive_key("password2", &salt).unwrap();
        
        let encrypted = encrypt(&key1, b"secret").unwrap();
        let result = decrypt(&key2, &encrypted);
        
        assert!(result.is_err());
    }
}
