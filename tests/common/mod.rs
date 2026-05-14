//! Shared test fixtures for the integration suite.
//!
//! Most tests in this suite exercise pure-crypto code paths (Argon2id, JWT
//! sign/verify, token hashing) that do not touch the database. We construct
//! an `AuthService` using `PgPool::connect_lazy`, which never opens a real
//! connection unless a query is executed — perfect for unit-style coverage
//! without a Postgres testcontainer.
//!
//! For tests that need actual DB-backed behaviour (refresh-token rotation,
//! lockout state transitions), see the `TODO` comments in the relevant test
//! files. Those require a live Postgres and are gated for the
//! integration-suite phase.

#![allow(dead_code)]

use rustpress_auth::{AuthConfig, AuthService};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Build a deterministic test config. 32-char secret to satisfy validation.
pub fn test_config() -> AuthConfig {
    AuthConfig {
        jwt_secret: "test-secret-key-32-characters-long!".to_string(),
        access_token_expiration: 900,
        refresh_token_expiration: 604800,
        jwt_issuer: "rustpress-test".to_string(),
        jwt_audience: "rustpress-test-api".to_string(),
        // Use Argon2 params on the low end to keep the test suite fast.
        // The production default is 65536 KiB / 3 iterations / parallelism 4.
        argon2_memory_cost: 19_456, // ~19 MiB — minimum recommended
        argon2_time_cost: 2,
        argon2_parallelism: 1,
        max_login_attempts: 5,
        lockout_duration: 900,
        password_reset_expiration: 3600,
        email_verification_expiration: 86400,
        min_password_length: 8,
        require_email_verification: false,
    }
}

/// Build a config with a different JWT secret — used to verify that tokens
/// signed by one key are rejected by a service initialised with another.
pub fn test_config_with_secret(secret: &str) -> AuthConfig {
    let mut cfg = test_config();
    cfg.jwt_secret = secret.to_string();
    cfg
}

/// Build a lazy Postgres pool. No network round-trip happens until a query
/// is executed against it, so pure-crypto tests can use this freely.
pub fn lazy_pool() -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        // A clearly-bogus URL — tests that touch the DB will fail loudly,
        // tests that don't will pass without ever connecting.
        .connect_lazy("postgres://test:test@127.0.0.1:1/test_authpro_unused")
        .expect("lazy pool construction is infallible for a valid URL")
}

/// Build an `AuthService` with the standard test config and a lazy DB pool.
pub fn auth_service() -> AuthService {
    AuthService::new(lazy_pool(), test_config())
}

/// Build an `AuthService` with a custom config.
pub fn auth_service_with(cfg: AuthConfig) -> AuthService {
    AuthService::new(lazy_pool(), cfg)
}

/// Build a synthetic `User` record for token-generation tests.
pub fn test_user() -> rustpress_auth::User {
    use chrono::Utc;
    use uuid::Uuid;
    rustpress_auth::User {
        id: Uuid::new_v4(),
        email: "alice@example.com".into(),
        password_hash: "$argon2id$placeholder".into(),
        name: "Alice".into(),
        role: rustpress_auth::UserRole::User,
        status: rustpress_auth::UserStatus::Active,
        avatar: None,
        bio: None,
        website: None,
        email_verified_at: Some(Utc::now()),
        last_login_at: None,
        last_login_ip: None,
        failed_login_attempts: 0,
        locked_until: None,
        password_changed_at: Utc::now(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}
