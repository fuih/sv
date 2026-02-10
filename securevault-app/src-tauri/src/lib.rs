//! SecureVault - A secure password manager
//! 
//! This crate provides the Rust backend for SecureVault,
//! handling encryption, database operations, and password generation.

pub mod commands;
pub mod crypto;
pub mod database;
pub mod password;

use commands::*;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            // Vault management
            init_vault,
            get_vault_status,
            setup_vault,
            unlock_vault,
            lock_vault,
            // Password entries
            get_passwords,
            search_passwords,
            get_passwords_for_url,
            add_password,
            update_password,
            delete_password,
            // Password generation
            generate_password,
            check_password_strength,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
