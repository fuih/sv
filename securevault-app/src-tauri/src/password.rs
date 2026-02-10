//! Password generator for SecureVault
//! Generates cryptographically secure passwords with configurable complexity

use rand::{seq::SliceRandom, rngs::OsRng};
use serde::{Deserialize, Serialize};

/// Character sets for password generation
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SPECIAL: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";
const AMBIGUOUS: &[u8] = b"0O1lI";

/// Password generation options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordOptions {
    /// Password length (16-128)
    pub length: usize,
    /// Include lowercase letters
    pub lowercase: bool,
    /// Include uppercase letters
    pub uppercase: bool,
    /// Include digits
    pub digits: bool,
    /// Include special characters
    pub special: bool,
    /// Exclude ambiguous characters (0, O, 1, l, I)
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 24,
            lowercase: true,
            uppercase: true,
            digits: true,
            special: true,
            exclude_ambiguous: true,
        }
    }
}

impl PasswordOptions {
    /// Create maximum security options
    pub fn max_security() -> Self {
        Self {
            length: 32,
            lowercase: true,
            uppercase: true,
            digits: true,
            special: true,
            exclude_ambiguous: false,
        }
    }
}

/// Password strength rating
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PasswordStrength {
    Weak,
    Fair,
    Strong,
    VeryStrong,
}

/// Calculate password entropy in bits
pub fn calculate_entropy(password: &str) -> f64 {
    let mut charset_size = 0usize;
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_special = false;

    for c in password.chars() {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            has_special = true;
        }
    }

    if has_lower {
        charset_size += 26;
    }
    if has_upper {
        charset_size += 26;
    }
    if has_digit {
        charset_size += 10;
    }
    if has_special {
        charset_size += 32;
    }

    if charset_size == 0 {
        return 0.0;
    }

    password.len() as f64 * (charset_size as f64).log2()
}

/// Evaluate password strength based on entropy
pub fn evaluate_strength(password: &str) -> PasswordStrength {
    let entropy = calculate_entropy(password);
    
    if entropy < 40.0 {
        PasswordStrength::Weak
    } else if entropy < 60.0 {
        PasswordStrength::Fair
    } else if entropy < 80.0 {
        PasswordStrength::Strong
    } else {
        PasswordStrength::VeryStrong
    }
}

/// Generate a cryptographically secure password
/// 
/// # Panics
/// Panics if no character types are enabled
pub fn generate_password(options: &PasswordOptions) -> String {
    let length = options.length.clamp(8, 128);
    
    // Build character pool
    let mut pool: Vec<u8> = Vec::new();
    let mut required: Vec<u8> = Vec::new();

    if options.lowercase {
        let chars: Vec<u8> = if options.exclude_ambiguous {
            LOWERCASE.iter().filter(|c| !AMBIGUOUS.contains(c)).copied().collect()
        } else {
            LOWERCASE.to_vec()
        };
        if let Some(&c) = chars.choose(&mut OsRng) {
            required.push(c);
        }
        pool.extend(&chars);
    }

    if options.uppercase {
        let chars: Vec<u8> = if options.exclude_ambiguous {
            UPPERCASE.iter().filter(|c| !AMBIGUOUS.contains(c)).copied().collect()
        } else {
            UPPERCASE.to_vec()
        };
        if let Some(&c) = chars.choose(&mut OsRng) {
            required.push(c);
        }
        pool.extend(&chars);
    }

    if options.digits {
        let chars: Vec<u8> = if options.exclude_ambiguous {
            DIGITS.iter().filter(|c| !AMBIGUOUS.contains(c)).copied().collect()
        } else {
            DIGITS.to_vec()
        };
        if let Some(&c) = chars.choose(&mut OsRng) {
            required.push(c);
        }
        pool.extend(&chars);
    }

    if options.special {
        if let Some(&c) = SPECIAL.choose(&mut OsRng) {
            required.push(c);
        }
        pool.extend(SPECIAL);
    }

    if pool.is_empty() {
        // Fallback to alphanumeric if nothing selected
        pool.extend(LOWERCASE);
        pool.extend(UPPERCASE);
        pool.extend(DIGITS);
    }

    // Generate password
    let remaining_length = length.saturating_sub(required.len());
    let mut password: Vec<u8> = required;
    
    for _ in 0..remaining_length {
        if let Some(&c) = pool.choose(&mut OsRng) {
            password.push(c);
        }
    }

    // Shuffle to randomize positions of required characters
    password.shuffle(&mut OsRng);

    String::from_utf8(password).unwrap_or_else(|_| "ERROR".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_password() {
        let options = PasswordOptions::default();
        let password = generate_password(&options);
        
        assert_eq!(password.len(), 24);
        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_max_security_password() {
        let options = PasswordOptions::max_security();
        let password = generate_password(&options);
        
        assert_eq!(password.len(), 32);
        let strength = evaluate_strength(&password);
        assert_eq!(strength, PasswordStrength::VeryStrong);
    }

    #[test]
    fn test_password_uniqueness() {
        let options = PasswordOptions::default();
        let passwords: Vec<String> = (0..100).map(|_| generate_password(&options)).collect();
        
        // All passwords should be unique
        let mut unique = passwords.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), passwords.len());
    }

    #[test]
    fn test_exclude_ambiguous() {
        let options = PasswordOptions {
            length: 100,
            lowercase: true,
            uppercase: true,
            digits: true,
            special: false,
            exclude_ambiguous: true,
        };
        
        let password = generate_password(&options);
        assert!(!password.contains('0'));
        assert!(!password.contains('O'));
        assert!(!password.contains('1'));
        assert!(!password.contains('l'));
        assert!(!password.contains('I'));
    }

    #[test]
    fn test_entropy_calculation() {
        // All lowercase, 8 chars = 8 * log2(26) ≈ 37.6 bits
        let entropy = calculate_entropy("abcdefgh");
        assert!(entropy > 37.0 && entropy < 38.0);
        
        // Mixed case + digits + special, 16 chars = high entropy
        let entropy = calculate_entropy("Abc123!@#XyzQwe!");
        assert!(entropy > 90.0);
    }
}
