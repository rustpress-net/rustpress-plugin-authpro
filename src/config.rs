//! Authentication Configuration
//!
//! All configuration values are loaded from environment variables.
//! No hardcoded secrets or sensitive data.

use crate::error::AuthError;
use std::env;

/// Authentication configuration loaded from environment
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// JWT secret key for signing tokens (from JWT_SECRET env var)
    pub jwt_secret: String,

    /// JWT access token expiration in seconds (from JWT_ACCESS_EXPIRATION env var)
    pub access_token_expiration: i64,

    /// JWT refresh token expiration in seconds (from JWT_REFRESH_EXPIRATION env var)
    pub refresh_token_expiration: i64,

    /// JWT issuer (from JWT_ISSUER env var)
    pub jwt_issuer: String,

    /// JWT audience (from JWT_AUDIENCE env var)
    pub jwt_audience: String,

    /// Argon2 memory cost in KiB (from ARGON2_MEMORY_COST env var)
    pub argon2_memory_cost: u32,

    /// Argon2 time cost (iterations) (from ARGON2_TIME_COST env var)
    pub argon2_time_cost: u32,

    /// Argon2 parallelism (from ARGON2_PARALLELISM env var)
    pub argon2_parallelism: u32,

    /// Maximum failed login attempts before lockout (from MAX_LOGIN_ATTEMPTS env var)
    pub max_login_attempts: i32,

    /// Account lockout duration in seconds (from LOCKOUT_DURATION env var)
    pub lockout_duration: i64,

    /// Password reset token expiration in seconds (from PASSWORD_RESET_EXPIRATION env var)
    pub password_reset_expiration: i64,

    /// Email verification token expiration in seconds (from EMAIL_VERIFICATION_EXPIRATION env var)
    pub email_verification_expiration: i64,

    /// Minimum password length (from MIN_PASSWORD_LENGTH env var)
    pub min_password_length: usize,

    /// Require email verification before login (from REQUIRE_EMAIL_VERIFICATION env var)
    pub require_email_verification: bool,
}

impl AuthConfig {
    /// Load configuration from environment variables
    ///
    /// # Panics
    /// Panics if JWT_SECRET environment variable is not set
    pub fn from_env() -> Self {
        Self {
            jwt_secret: env::var("JWT_SECRET")
                .expect("JWT_SECRET environment variable must be set"),

            access_token_expiration: env::var("JWT_ACCESS_EXPIRATION")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(900), // 15 minutes default

            refresh_token_expiration: env::var("JWT_REFRESH_EXPIRATION")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(604800), // 7 days default

            jwt_issuer: env::var("JWT_ISSUER").unwrap_or_else(|_| "rustpress".to_string()),

            jwt_audience: env::var("JWT_AUDIENCE").unwrap_or_else(|_| "rustpress-api".to_string()),

            argon2_memory_cost: env::var("ARGON2_MEMORY_COST")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(65536), // 64 MiB

            argon2_time_cost: env::var("ARGON2_TIME_COST")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3),

            argon2_parallelism: env::var("ARGON2_PARALLELISM")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4),

            max_login_attempts: env::var("MAX_LOGIN_ATTEMPTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),

            lockout_duration: env::var("LOCKOUT_DURATION")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(900), // 15 minutes

            password_reset_expiration: env::var("PASSWORD_RESET_EXPIRATION")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600), // 1 hour

            email_verification_expiration: env::var("EMAIL_VERIFICATION_EXPIRATION")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(86400), // 24 hours

            min_password_length: env::var("MIN_PASSWORD_LENGTH")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8),

            require_email_verification: env::var("REQUIRE_EMAIL_VERIFICATION")
                .ok()
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(false),
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), AuthError> {
        if self.jwt_secret.len() < 32 {
            return Err(AuthError::Config(
                "JWT_SECRET must be at least 32 characters".to_string(),
            ));
        }

        if self.access_token_expiration <= 0 {
            return Err(AuthError::Config(
                "JWT_ACCESS_EXPIRATION must be positive".to_string(),
            ));
        }

        if self.refresh_token_expiration <= self.access_token_expiration {
            return Err(AuthError::Config(
                "JWT_REFRESH_EXPIRATION must be greater than JWT_ACCESS_EXPIRATION".to_string(),
            ));
        }

        if self.min_password_length < 8 {
            return Err(AuthError::Config(
                "MIN_PASSWORD_LENGTH must be at least 8".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = AuthConfig {
            jwt_secret: "a".repeat(32),
            access_token_expiration: 900,
            refresh_token_expiration: 604800,
            jwt_issuer: "test".to_string(),
            jwt_audience: "test".to_string(),
            argon2_memory_cost: 65536,
            argon2_time_cost: 3,
            argon2_parallelism: 4,
            max_login_attempts: 5,
            lockout_duration: 900,
            password_reset_expiration: 3600,
            email_verification_expiration: 86400,
            min_password_length: 8,
            require_email_verification: false,
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_short_secret() {
        let config = AuthConfig {
            jwt_secret: "short".to_string(),
            access_token_expiration: 900,
            refresh_token_expiration: 604800,
            jwt_issuer: "test".to_string(),
            jwt_audience: "test".to_string(),
            argon2_memory_cost: 65536,
            argon2_time_cost: 3,
            argon2_parallelism: 4,
            max_login_attempts: 5,
            lockout_duration: 900,
            password_reset_expiration: 3600,
            email_verification_expiration: 86400,
            min_password_length: 8,
            require_email_verification: false,
        };

        assert!(config.validate().is_err());
    }
}
