//! Tauri commands for SecureVault
//! IPC commands exposed to the frontend

use crate::database::{DatabaseError, NewPasswordEntry, PasswordEntry, Vault};
use crate::password::{self, PasswordOptions, PasswordStrength};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Global vault instance
static VAULT: Lazy<Arc<Mutex<Option<Vault>>>> = Lazy::new(|| Arc::new(Mutex::new(None)));

/// Last activity timestamp for auto-lock
static LAST_ACTIVITY: Lazy<Mutex<Instant>> = Lazy::new(|| Mutex::new(Instant::now()));

/// Auto-lock timeout (5 minutes)
const AUTO_LOCK_TIMEOUT: Duration = Duration::from_secs(300);

/// Update activity timestamp
fn update_activity() {
    *LAST_ACTIVITY.lock() = Instant::now();
}

/// Check if auto-lock should trigger
fn check_auto_lock() {
    let last_activity = *LAST_ACTIVITY.lock();
    if last_activity.elapsed() > AUTO_LOCK_TIMEOUT {
        if let Some(vault) = VAULT.lock().as_mut() {
            vault.lock();
        }
    }
}

/// Response type for commands
#[derive(Serialize)]
pub struct CommandResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> CommandResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

/// Vault status info
#[derive(Serialize)]
pub struct VaultStatus {
    pub initialized: bool,
    pub unlocked: bool,
}

/// Password entry response (without raw password)
#[derive(Serialize)]
pub struct PasswordEntryResponse {
    pub id: i64,
    pub site_name: String,
    pub site_url: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<PasswordEntry> for PasswordEntryResponse {
    fn from(entry: PasswordEntry) -> Self {
        Self {
            id: entry.id,
            site_name: entry.site_name,
            site_url: entry.site_url,
            username: entry.username,
            password: entry.password,
            notes: entry.notes,
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        }
    }
}

/// Generated password response
#[derive(Serialize)]
pub struct GeneratedPassword {
    pub password: String,
    pub strength: PasswordStrength,
    pub entropy: f64,
}

/// Get the database path
fn get_db_path() -> std::path::PathBuf {
    let data_dir = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("SecureVault");
    
    std::fs::create_dir_all(&data_dir).ok();
    data_dir.join("vault.db")
}

/// Initialize vault on app startup
#[tauri::command]
pub fn init_vault() -> CommandResponse<VaultStatus> {
    let db_path = get_db_path();
    
    match Vault::open(&db_path) {
        Ok(vault) => {
            let initialized = vault.is_initialized().unwrap_or(false);
            let unlocked = vault.is_unlocked();
            *VAULT.lock() = Some(vault);
            
            CommandResponse::ok(VaultStatus { initialized, unlocked })
        }
        Err(e) => CommandResponse::err(e.to_string()),
    }
}

/// Get vault status
#[tauri::command]
pub fn get_vault_status() -> CommandResponse<VaultStatus> {
    check_auto_lock();
    
    let vault_guard = VAULT.lock();
    match vault_guard.as_ref() {
        Some(vault) => {
            let initialized = vault.is_initialized().unwrap_or(false);
            let unlocked = vault.is_unlocked();
            CommandResponse::ok(VaultStatus { initialized, unlocked })
        }
        None => CommandResponse::err("Vault not initialized".to_string()),
    }
}

/// Set up vault with new master password
#[tauri::command]
pub fn setup_vault(master_password: String) -> CommandResponse<bool> {
    let mut vault_guard = VAULT.lock();
    
    match vault_guard.as_mut() {
        Some(vault) => {
            match vault.initialize(&master_password) {
                Ok(_) => {
                    update_activity();
                    CommandResponse::ok(true)
                }
                Err(e) => CommandResponse::err(e.to_string()),
            }
        }
        None => CommandResponse::err("Vault not opened".to_string()),
    }
}

/// Unlock vault with master password
#[tauri::command]
pub fn unlock_vault(master_password: String) -> CommandResponse<bool> {
    let mut vault_guard = VAULT.lock();
    
    match vault_guard.as_mut() {
        Some(vault) => {
            match vault.unlock(&master_password) {
                Ok(_) => {
                    update_activity();
                    CommandResponse::ok(true)
                }
                Err(DatabaseError::InvalidPassword) => {
                    CommandResponse::err("Invalid master password".to_string())
                }
                Err(e) => CommandResponse::err(e.to_string()),
            }
        }
        None => CommandResponse::err("Vault not opened".to_string()),
    }
}

/// Lock the vault
#[tauri::command]
pub fn lock_vault() -> CommandResponse<bool> {
    let mut vault_guard = VAULT.lock();
    
    match vault_guard.as_mut() {
        Some(vault) => {
            vault.lock();
            CommandResponse::ok(true)
        }
        None => CommandResponse::err("Vault not opened".to_string()),
    }
}

/// Get all password entries
#[tauri::command]
pub fn get_passwords() -> CommandResponse<Vec<PasswordEntryResponse>> {
    check_auto_lock();
    update_activity();
    
    let vault_guard = VAULT.lock();
    
    match vault_guard.as_ref() {
        Some(vault) => {
            match vault.get_all_entries() {
                Ok(entries) => {
                    let responses: Vec<PasswordEntryResponse> = 
                        entries.into_iter().map(|e| e.into()).collect();
                    CommandResponse::ok(responses)
                }
                Err(e) => CommandResponse::err(e.to_string()),
            }
        }
        None => CommandResponse::err("Vault not opened".to_string()),
    }
}

/// Search passwords
#[tauri::command]
pub fn search_passwords(query: String) -> CommandResponse<Vec<PasswordEntryResponse>> {
    check_auto_lock();
    update_activity();
    
    let vault_guard = VAULT.lock();
    
    match vault_guard.as_ref() {
        Some(vault) => {
            match vault.search(&query) {
                Ok(entries) => {
                    let responses: Vec<PasswordEntryResponse> = 
                        entries.into_iter().map(|e| e.into()).collect();
                    CommandResponse::ok(responses)
                }
                Err(e) => CommandResponse::err(e.to_string()),
            }
        }
        None => CommandResponse::err("Vault not opened".to_string()),
    }
}

/// Get passwords for a specific URL
#[tauri::command]
pub fn get_passwords_for_url(url: String) -> CommandResponse<Vec<PasswordEntryResponse>> {
    check_auto_lock();
    update_activity();
    
    let vault_guard = VAULT.lock();
    
    match vault_guard.as_ref() {
        Some(vault) => {
            match vault.get_entries_by_url(&url) {
                Ok(entries) => {
                    let responses: Vec<PasswordEntryResponse> = 
                        entries.into_iter().map(|e| e.into()).collect();
                    CommandResponse::ok(responses)
                }
                Err(e) => CommandResponse::err(e.to_string()),
            }
        }
        None => CommandResponse::err("Vault not opened".to_string()),
    }
}

/// Add a new password entry
#[tauri::command]
pub fn add_password(
    site_name: String,
    site_url: String,
    username: String,
    password: String,
    notes: String,
) -> CommandResponse<i64> {
    check_auto_lock();
    update_activity();
    
    let vault_guard = VAULT.lock();
    
    match vault_guard.as_ref() {
        Some(vault) => {
            let entry = NewPasswordEntry {
                site_name,
                site_url,
                username,
                password,
                notes,
            };
            
            match vault.add_entry(entry) {
                Ok(id) => CommandResponse::ok(id),
                Err(e) => CommandResponse::err(e.to_string()),
            }
        }
        None => CommandResponse::err("Vault not opened".to_string()),
    }
}

/// Update a password entry
#[tauri::command]
pub fn update_password(
    id: i64,
    site_name: String,
    site_url: String,
    username: String,
    password: String,
    notes: String,
) -> CommandResponse<bool> {
    check_auto_lock();
    update_activity();
    
    let vault_guard = VAULT.lock();
    
    match vault_guard.as_ref() {
        Some(vault) => {
            let entry = NewPasswordEntry {
                site_name,
                site_url,
                username,
                password,
                notes,
            };
            
            match vault.update_entry(id, entry) {
                Ok(_) => CommandResponse::ok(true),
                Err(e) => CommandResponse::err(e.to_string()),
            }
        }
        None => CommandResponse::err("Vault not opened".to_string()),
    }
}

/// Delete a password entry
#[tauri::command]
pub fn delete_password(id: i64) -> CommandResponse<bool> {
    check_auto_lock();
    update_activity();
    
    let vault_guard = VAULT.lock();
    
    match vault_guard.as_ref() {
        Some(vault) => {
            match vault.delete_entry(id) {
                Ok(_) => CommandResponse::ok(true),
                Err(e) => CommandResponse::err(e.to_string()),
            }
        }
        None => CommandResponse::err("Vault not opened".to_string()),
    }
}

/// Generate a secure password
#[tauri::command]
pub fn generate_password(
    length: Option<usize>,
    lowercase: Option<bool>,
    uppercase: Option<bool>,
    digits: Option<bool>,
    special: Option<bool>,
    exclude_ambiguous: Option<bool>,
) -> CommandResponse<GeneratedPassword> {
    let options = PasswordOptions {
        length: length.unwrap_or(24),
        lowercase: lowercase.unwrap_or(true),
        uppercase: uppercase.unwrap_or(true),
        digits: digits.unwrap_or(true),
        special: special.unwrap_or(true),
        exclude_ambiguous: exclude_ambiguous.unwrap_or(true),
    };
    
    let password = password::generate_password(&options);
    let strength = password::evaluate_strength(&password);
    let entropy = password::calculate_entropy(&password);
    
    CommandResponse::ok(GeneratedPassword {
        password,
        strength,
        entropy,
    })
}

/// Evaluate password strength
#[tauri::command]
pub fn check_password_strength(password: String) -> CommandResponse<GeneratedPassword> {
    let strength = password::evaluate_strength(&password);
    let entropy = password::calculate_entropy(&password);
    
    CommandResponse::ok(GeneratedPassword {
        password,
        strength,
        entropy,
    })
}
