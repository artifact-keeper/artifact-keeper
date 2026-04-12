//! Configurable password policy validation for local user accounts.
//!
//! All validation logic lives in a single pure function
//! [`validate_password`] so it can be tested exhaustively without
//! database or application state.

/// Configuration for password policy checks, extracted from [`crate::config::Config`].
#[derive(Debug, Clone)]
pub struct PasswordPolicyConfig {
    pub min_length: usize,
    pub max_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    /// 0 = disabled, 1-4 maps to zxcvbn scores.
    pub min_strength: u8,
}

impl Default for PasswordPolicyConfig {
    fn default() -> Self {
        Self {
            min_length: 8,
            max_length: 128,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            min_strength: 0,
        }
    }
}

impl PasswordPolicyConfig {
    /// Build a policy config from the application config.
    pub fn from_config(config: &crate::config::Config) -> Self {
        Self {
            min_length: config.password_min_length,
            max_length: config.password_max_length,
            require_uppercase: config.password_require_uppercase,
            require_lowercase: config.password_require_lowercase,
            require_digit: config.password_require_digit,
            require_special: config.password_require_special,
            min_strength: config.password_min_strength,
        }
    }
}

/// Characters considered "special" for the `require_special` policy.
const SPECIAL_CHARS: &str = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\";

/// Validate a password against the given policy configuration.
///
/// Returns `Ok(())` when the password satisfies every enabled rule.
/// On failure, returns a `Vec<String>` with one human-readable message
/// per violated rule, so the caller can present all problems at once
/// rather than making users fix them one by one.
pub fn validate_password(password: &str, config: &PasswordPolicyConfig) -> Result<(), Vec<String>> {
    // Common passwords list (checked regardless of policy settings).
    const COMMON_PASSWORDS: &[&str] = &[
        "password",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty123",
        "qwertyui",
        "password1",
        "iloveyou",
        "12341234",
        "00000000",
        "abc12345",
        "11111111",
        "password123",
        "admin123",
        "letmein1",
        "welcome1",
        "monkey12",
        "dragon12",
        "baseball1",
        "trustno1",
    ];

    let mut violations: Vec<String> = Vec::new();

    // Length checks
    if password.len() < config.min_length {
        violations.push(format!(
            "Password must be at least {} characters",
            config.min_length
        ));
    }
    if password.len() > config.max_length {
        violations.push(format!(
            "Password must be at most {} characters",
            config.max_length
        ));
    }

    // Character class checks
    if config.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
        violations.push("Password must contain at least one uppercase letter".to_string());
    }
    if config.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
        violations.push("Password must contain at least one lowercase letter".to_string());
    }
    if config.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        violations.push("Password must contain at least one digit".to_string());
    }
    if config.require_special && !password.chars().any(|c| SPECIAL_CHARS.contains(c)) {
        violations.push("Password must contain at least one special character".to_string());
    }

    // Common password check
    let lower = password.to_lowercase();
    if COMMON_PASSWORDS.contains(&lower.as_str()) {
        violations.push("Password is too common; choose a stronger password".to_string());
    }

    // zxcvbn strength check (only when enabled)
    if config.min_strength > 0 {
        if let Ok(min_score) = zxcvbn::Score::try_from(config.min_strength) {
            let estimate = zxcvbn::zxcvbn(password, &[]);
            if estimate.score() < min_score {
                let label = match config.min_strength {
                    1 => "very weak",
                    2 => "weak",
                    3 => "moderate",
                    4 => "strong",
                    _ => "sufficient",
                };
                violations.push(format!(
                    "Password is not strong enough (minimum strength: {label})"
                ));
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> PasswordPolicyConfig {
        PasswordPolicyConfig::default()
    }

    // -----------------------------------------------------------------------
    // Length checks
    // -----------------------------------------------------------------------

    #[test]
    fn accepts_valid_password_with_defaults() {
        let cfg = default_config();
        assert!(validate_password("a-fine-pass", &cfg).is_ok());
    }

    #[test]
    fn rejects_too_short() {
        let cfg = PasswordPolicyConfig {
            min_length: 12,
            ..default_config()
        };
        let errs = validate_password("short", &cfg).unwrap_err();
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("at least 12 characters"));
    }

    #[test]
    fn rejects_too_long() {
        let cfg = PasswordPolicyConfig {
            max_length: 16,
            ..default_config()
        };
        let long = "a".repeat(17);
        let errs = validate_password(&long, &cfg).unwrap_err();
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("at most 16 characters"));
    }

    // -----------------------------------------------------------------------
    // Character class checks
    // -----------------------------------------------------------------------

    #[test]
    fn requires_uppercase() {
        let cfg = PasswordPolicyConfig {
            require_uppercase: true,
            ..default_config()
        };
        let errs = validate_password("alllowercase1", &cfg).unwrap_err();
        assert!(errs[0].contains("uppercase"));

        assert!(validate_password("hasUppercase1", &cfg).is_ok());
    }

    #[test]
    fn requires_lowercase() {
        let cfg = PasswordPolicyConfig {
            require_lowercase: true,
            ..default_config()
        };
        let errs = validate_password("ALLUPPERCASE1", &cfg).unwrap_err();
        assert!(errs[0].contains("lowercase"));

        assert!(validate_password("HASLOWERa1234", &cfg).is_ok());
    }

    #[test]
    fn requires_digit() {
        let cfg = PasswordPolicyConfig {
            require_digit: true,
            ..default_config()
        };
        let errs = validate_password("noDigitsHere", &cfg).unwrap_err();
        assert!(errs[0].contains("digit"));

        assert!(validate_password("hasDigit7xx", &cfg).is_ok());
    }

    #[test]
    fn requires_special() {
        let cfg = PasswordPolicyConfig {
            require_special: true,
            ..default_config()
        };
        let errs = validate_password("NoSpecials123", &cfg).unwrap_err();
        assert!(errs[0].contains("special"));

        assert!(validate_password("has$pecial1", &cfg).is_ok());
    }

    // -----------------------------------------------------------------------
    // Combined rules
    // -----------------------------------------------------------------------

    #[test]
    fn reports_all_violations_at_once() {
        let cfg = PasswordPolicyConfig {
            min_length: 12,
            require_uppercase: true,
            require_digit: true,
            require_special: true,
            ..default_config()
        };
        // "short" violates length, uppercase, digit, and special
        let errs = validate_password("short", &cfg).unwrap_err();
        assert!(errs.len() >= 4, "Expected >= 4 violations, got {errs:?}");
    }

    #[test]
    fn all_rules_enabled_and_satisfied() {
        let cfg = PasswordPolicyConfig {
            min_length: 10,
            max_length: 64,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            min_strength: 0,
        };
        assert!(validate_password("Str0ng!Pass", &cfg).is_ok());
    }

    // -----------------------------------------------------------------------
    // Common password check
    // -----------------------------------------------------------------------

    #[test]
    fn rejects_common_passwords() {
        let cfg = default_config();
        let errs = validate_password("password", &cfg).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("too common")));
    }

    #[test]
    fn common_password_check_is_case_insensitive() {
        let cfg = default_config();
        let errs = validate_password("Password", &cfg).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("too common")));
    }

    // -----------------------------------------------------------------------
    // zxcvbn strength scoring
    // -----------------------------------------------------------------------

    #[test]
    fn strength_check_disabled_by_default() {
        let cfg = default_config();
        // "aaaaaaaa" is weak but should pass when min_strength = 0
        assert!(validate_password("aaaaaaaa", &cfg).is_ok());
    }

    #[test]
    fn strength_check_rejects_weak_password() {
        let cfg = PasswordPolicyConfig {
            min_strength: 3,
            ..default_config()
        };
        let errs = validate_password("aaaaaaaa", &cfg).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("not strong enough")));
    }

    #[test]
    fn strength_check_accepts_strong_password() {
        let cfg = PasswordPolicyConfig {
            min_strength: 3,
            ..default_config()
        };
        // A sufficiently complex passphrase should score >= 3
        assert!(validate_password("correct-horse-battery-staple-xyz", &cfg).is_ok());
    }

    #[test]
    fn strength_check_level_4() {
        let cfg = PasswordPolicyConfig {
            min_strength: 4,
            ..default_config()
        };
        // Simple passwords should fail at level 4
        let result = validate_password("Summer2024", &cfg);
        assert!(result.is_err());

        // A long random-looking password should pass
        assert!(validate_password("j7$Kx!2mQ9@pLw4#rV6&nF8", &cfg).is_ok());
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn empty_password_fails_length_check() {
        let cfg = default_config();
        let errs = validate_password("", &cfg).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("at least")));
    }

    #[test]
    fn unicode_characters_counted_by_byte_length() {
        // Rust's str::len() returns bytes, not chars, so a short
        // string of multi-byte characters can pass the length check.
        let cfg = PasswordPolicyConfig {
            min_length: 4,
            ..default_config()
        };
        // 4 emoji = 16 bytes, well above min_length of 4
        let emoji_pwd = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}";
        assert!(validate_password(emoji_pwd, &cfg).is_ok());
    }

    #[test]
    fn exact_min_length_accepted() {
        let cfg = PasswordPolicyConfig {
            min_length: 8,
            ..default_config()
        };
        // Use a non-common 8-character password
        assert!(validate_password("xK9!mZ2q", &cfg).is_ok());
    }

    #[test]
    fn exact_max_length_accepted() {
        let cfg = PasswordPolicyConfig {
            max_length: 10,
            ..default_config()
        };
        // Use a non-common 10-character password
        assert!(validate_password("aB3!xYz9kL", &cfg).is_ok());
    }
}
