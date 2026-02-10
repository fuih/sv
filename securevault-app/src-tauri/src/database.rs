//! Database module for SecureVault
//! Handles encrypted SQLite storage of password entries

use crate::crypto::{self, CryptoError, KEY_SIZE, SALT_SIZE};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Vault is locked")]
    VaultLocked,
    #[error("Invalid master password")]
    InvalidPassword,
    #[error("Entry not found")]
    NotFound,
}

/// A password entry stored in the vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    pub id: i64,
    pub site_name: String,
    pub site_url: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password: String, // Decrypted password (never serialized)
    pub notes: String,
    pub created_at: String,
    pub updated_at: String,
}

/// A new password entry to be created
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewPasswordEntry {
    pub site_name: String,
    pub site_url: String,
    pub username: String,
    pub password: String,
    pub notes: String,
}

/// Encrypted password entry for storage
#[derive(Debug)]
struct EncryptedEntry {
    id: i64,
    site_name: String,
    site_url: String,
    username_encrypted: String,
    password_encrypted: String,
    notes_encrypted: String,
    created_at: String,
    updated_at: String,
}

/// The secure vault database
pub struct Vault {
    conn: Connection,
    encryption_key: Option<Zeroizing<[u8; KEY_SIZE]>>,
}

impl Vault {
    /// Create or open a vault at the specified path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, DatabaseError> {
        let conn = Connection::open(path)?;
        
        // Create tables if they don't exist
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS vault_config (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_name TEXT NOT NULL,
                site_url TEXT NOT NULL,
                username_encrypted TEXT NOT NULL,
                password_encrypted TEXT NOT NULL,
                notes_encrypted TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            
            CREATE INDEX IF NOT EXISTS idx_site_name ON passwords(site_name);
            CREATE INDEX IF NOT EXISTS idx_site_url ON passwords(site_url);
            ",
        )?;

        Ok(Self {
            conn,
            encryption_key: None,
        })
    }

    /// Check if the vault has been initialized (has a master password set)
    pub fn is_initialized(&self) -> Result<bool, DatabaseError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM vault_config WHERE key = 'salt'",
            [],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Initialize the vault with a new master password
    pub fn initialize(&mut self, master_password: &str) -> Result<(), DatabaseError> {
        if self.is_initialized()? {
            return Err(DatabaseError::Crypto(CryptoError::InvalidFormat));
        }

        // Generate and store salt
        let salt = crypto::generate_salt();
        self.conn.execute(
            "INSERT INTO vault_config (key, value) VALUES ('salt', ?)",
            params![salt.as_slice()],
        )?;

        // Derive encryption key
        let key = crypto::derive_key(master_password, &salt)?;

        // Store a verification token (encrypted known value)
        let verification_token = crypto::encrypt_string(&key, "SECUREVAULT_VERIFIED")?;
        self.conn.execute(
            "INSERT INTO vault_config (key, value) VALUES ('verification', ?)",
            params![verification_token.as_bytes()],
        )?;

        self.encryption_key = Some(key);
        Ok(())
    }

    /// Unlock the vault with the master password
    pub fn unlock(&mut self, master_password: &str) -> Result<(), DatabaseError> {
        // Get salt
        let salt: Vec<u8> = self.conn.query_row(
            "SELECT value FROM vault_config WHERE key = 'salt'",
            [],
            |row| row.get(0),
        )?;

        if salt.len() != SALT_SIZE {
            return Err(DatabaseError::Crypto(CryptoError::InvalidFormat));
        }

        // Derive key
        let key = crypto::derive_key(master_password, &salt)?;

        // Verify password by decrypting verification token
        let verification: Vec<u8> = self.conn.query_row(
            "SELECT value FROM vault_config WHERE key = 'verification'",
            [],
            |row| row.get(0),
        )?;

        let verification_str = String::from_utf8(verification)
            .map_err(|_| DatabaseError::Crypto(CryptoError::InvalidFormat))?;

        match crypto::decrypt_string(&key, &verification_str) {
            Ok(decrypted) if decrypted == "SECUREVAULT_VERIFIED" => {
                self.encryption_key = Some(key);
                Ok(())
            }
            _ => Err(DatabaseError::InvalidPassword),
        }
    }

    /// Lock the vault (clear encryption key from memory)
    pub fn lock(&mut self) {
        self.encryption_key = None;
    }

    /// Check if vault is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.encryption_key.is_some()
    }

    /// Get the encryption key or return an error
    fn get_key(&self) -> Result<&[u8; KEY_SIZE], DatabaseError> {
        self.encryption_key
            .as_ref()
            .map(|k| &**k)
            .ok_or(DatabaseError::VaultLocked)
    }

    /// Add a new password entry
    pub fn add_entry(&self, entry: NewPasswordEntry) -> Result<i64, DatabaseError> {
        let key = self.get_key()?;

        let username_encrypted = crypto::encrypt_string(key, &entry.username)?;
        let password_encrypted = crypto::encrypt_string(key, &entry.password)?;
        let notes_encrypted = crypto::encrypt_string(key, &entry.notes)?;

        self.conn.execute(
            "INSERT INTO passwords (site_name, site_url, username_encrypted, password_encrypted, notes_encrypted)
             VALUES (?, ?, ?, ?, ?)",
            params![
                entry.site_name,
                entry.site_url,
                username_encrypted,
                password_encrypted,
                notes_encrypted,
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Get all password entries (decrypted)
    pub fn get_all_entries(&self) -> Result<Vec<PasswordEntry>, DatabaseError> {
        let key = self.get_key()?;

        let mut stmt = self.conn.prepare(
            "SELECT id, site_name, site_url, username_encrypted, password_encrypted, 
                    notes_encrypted, created_at, updated_at 
             FROM passwords ORDER BY site_name",
        )?;

        let entries = stmt.query_map([], |row| {
            Ok(EncryptedEntry {
                id: row.get(0)?,
                site_name: row.get(1)?,
                site_url: row.get(2)?,
                username_encrypted: row.get(3)?,
                password_encrypted: row.get(4)?,
                notes_encrypted: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })?;

        let mut result = Vec::new();
        for entry in entries {
            let e = entry?;
            result.push(PasswordEntry {
                id: e.id,
                site_name: e.site_name,
                site_url: e.site_url,
                username: crypto::decrypt_string(key, &e.username_encrypted)?,
                password: crypto::decrypt_string(key, &e.password_encrypted)?,
                notes: crypto::decrypt_string(key, &e.notes_encrypted)?,
                created_at: e.created_at,
                updated_at: e.updated_at,
            });
        }

        Ok(result)
    }

    /// Get password entries matching a URL
    pub fn get_entries_by_url(&self, url: &str) -> Result<Vec<PasswordEntry>, DatabaseError> {
        let key = self.get_key()?;

        // Extract domain from URL for matching
        let domain = extract_domain(url);

        let mut stmt = self.conn.prepare(
            "SELECT id, site_name, site_url, username_encrypted, password_encrypted, 
                    notes_encrypted, created_at, updated_at 
             FROM passwords 
             WHERE site_url LIKE ?",
        )?;

        let pattern = format!("%{}%", domain);
        let entries = stmt.query_map([pattern], |row| {
            Ok(EncryptedEntry {
                id: row.get(0)?,
                site_name: row.get(1)?,
                site_url: row.get(2)?,
                username_encrypted: row.get(3)?,
                password_encrypted: row.get(4)?,
                notes_encrypted: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })?;

        let mut result = Vec::new();
        for entry in entries {
            let e = entry?;
            result.push(PasswordEntry {
                id: e.id,
                site_name: e.site_name,
                site_url: e.site_url,
                username: crypto::decrypt_string(key, &e.username_encrypted)?,
                password: crypto::decrypt_string(key, &e.password_encrypted)?,
                notes: crypto::decrypt_string(key, &e.notes_encrypted)?,
                created_at: e.created_at,
                updated_at: e.updated_at,
            });
        }

        Ok(result)
    }

    /// Update a password entry
    pub fn update_entry(&self, id: i64, entry: NewPasswordEntry) -> Result<(), DatabaseError> {
        let key = self.get_key()?;

        let username_encrypted = crypto::encrypt_string(key, &entry.username)?;
        let password_encrypted = crypto::encrypt_string(key, &entry.password)?;
        let notes_encrypted = crypto::encrypt_string(key, &entry.notes)?;

        let rows_affected = self.conn.execute(
            "UPDATE passwords 
             SET site_name = ?, site_url = ?, username_encrypted = ?, 
                 password_encrypted = ?, notes_encrypted = ?, updated_at = datetime('now')
             WHERE id = ?",
            params![
                entry.site_name,
                entry.site_url,
                username_encrypted,
                password_encrypted,
                notes_encrypted,
                id,
            ],
        )?;

        if rows_affected == 0 {
            return Err(DatabaseError::NotFound);
        }

        Ok(())
    }

    /// Delete a password entry
    pub fn delete_entry(&self, id: i64) -> Result<(), DatabaseError> {
        let rows_affected = self.conn.execute("DELETE FROM passwords WHERE id = ?", params![id])?;

        if rows_affected == 0 {
            return Err(DatabaseError::NotFound);
        }

        Ok(())
    }

    /// Search entries by site name
    pub fn search(&self, query: &str) -> Result<Vec<PasswordEntry>, DatabaseError> {
        let key = self.get_key()?;

        let mut stmt = self.conn.prepare(
            "SELECT id, site_name, site_url, username_encrypted, password_encrypted, 
                    notes_encrypted, created_at, updated_at 
             FROM passwords 
             WHERE site_name LIKE ? OR site_url LIKE ?
             ORDER BY site_name",
        )?;

        let pattern = format!("%{}%", query);
        let entries = stmt.query_map([&pattern, &pattern], |row| {
            Ok(EncryptedEntry {
                id: row.get(0)?,
                site_name: row.get(1)?,
                site_url: row.get(2)?,
                username_encrypted: row.get(3)?,
                password_encrypted: row.get(4)?,
                notes_encrypted: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })?;

        let mut result = Vec::new();
        for entry in entries {
            let e = entry?;
            result.push(PasswordEntry {
                id: e.id,
                site_name: e.site_name,
                site_url: e.site_url,
                username: crypto::decrypt_string(key, &e.username_encrypted)?,
                password: crypto::decrypt_string(key, &e.password_encrypted)?,
                notes: crypto::decrypt_string(key, &e.notes_encrypted)?,
                created_at: e.created_at,
                updated_at: e.updated_at,
            });
        }

        Ok(result)
    }
}

/// Extract domain from a URL
fn extract_domain(url: &str) -> String {
    let url = url.trim().to_lowercase();
    let url = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(&url);
    
    url.split('/').next().unwrap_or(&url).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_vault_lifecycle() {
        let path = "/tmp/test_vault.db";
        let _ = fs::remove_file(path);

        let mut vault = Vault::open(path).unwrap();
        assert!(!vault.is_initialized().unwrap());

        // Initialize with master password
        vault.initialize("MyMasterPassword123!").unwrap();
        assert!(vault.is_initialized().unwrap());
        assert!(vault.is_unlocked());

        // Lock and unlock
        vault.lock();
        assert!(!vault.is_unlocked());

        // Wrong password should fail
        assert!(vault.unlock("wrong_password").is_err());

        // Correct password should work
        vault.unlock("MyMasterPassword123!").unwrap();
        assert!(vault.is_unlocked());

        fs::remove_file(path).ok();
    }

    #[test]
    fn test_password_entries() {
        let path = "/tmp/test_entries.db";
        let _ = fs::remove_file(path);

        let mut vault = Vault::open(path).unwrap();
        vault.initialize("master").unwrap();

        // Add entry
        let id = vault
            .add_entry(NewPasswordEntry {
                site_name: "GitHub".to_string(),
                site_url: "https://github.com".to_string(),
                username: "user@example.com".to_string(),
                password: "secret123".to_string(),
                notes: "My GitHub account".to_string(),
            })
            .unwrap();

        // Retrieve entry
        let entries = vault.get_all_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].site_name, "GitHub");
        assert_eq!(entries[0].password, "secret123");

        // Search by URL
        let results = vault.get_entries_by_url("github.com").unwrap();
        assert_eq!(results.len(), 1);

        // Delete entry
        vault.delete_entry(id).unwrap();
        assert!(vault.get_all_entries().unwrap().is_empty());

        fs::remove_file(path).ok();
    }
}
