//! RustPress Authentication Plugin
//!
//! Core authentication system for RustPress providing:
//! - User registration and login
//! - JWT access and refresh token management
//! - Argon2id password hashing
//! - Refresh token rotation
//! - Password reset flow
//! - Email verification
//! - Account lockout protection
//! - Role-based access control
//!
//! # Configuration
//!
//! All configuration is loaded from environment variables:
//! - `JWT_SECRET` - Secret key for signing JWTs (required, min 32 chars)
//! - `JWT_ACCESS_EXPIRATION` - Access token expiration in seconds (default: 900)
//! - `JWT_REFRESH_EXPIRATION` - Refresh token expiration in seconds (default: 604800)
//! - `JWT_ISSUER` - JWT issuer claim (default: "rustpress")
//! - `JWT_AUDIENCE` - JWT audience claim (default: "rustpress-api")
//! - `DATABASE_URL` - PostgreSQL connection string (required)
//!
//! # Usage
//!
//! ```rust,ignore
//! use rustpress_auth::{AuthPlugin, AuthService};
//!
//! // Initialize plugin
//! let plugin = AuthPlugin::new();
//! plugin.activate(&db_pool).await?;
//!
//! // Use auth service
//! let auth = plugin.auth_service().await.unwrap();
//! let response = auth.login(login_request, ip, user_agent).await?;
//! ```

pub mod config;
pub mod error;
pub mod extractors;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod service;

// Re-export commonly used types
pub use config::AuthConfig;
pub use error::AuthError;
pub use extractors::{AuthUser, ClientInfo};
pub use handlers::AuthState;
pub use models::*;
pub use service::AuthService;

use async_trait::async_trait;
use axum::Router;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;

// ============================================
// Plugin Types (Standalone - no external deps)
// ============================================

/// Plugin state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginState {
    Inactive,
    Active,
    Error,
}

/// Plugin metadata
#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
}

/// Plugin lifecycle trait
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Get plugin information
    fn info(&self) -> &PluginInfo;

    /// Get current plugin state
    async fn state(&self) -> PluginState;

    /// Activate the plugin
    async fn activate(&self, db: PgPool) -> Result<(), AuthError>;

    /// Deactivate the plugin
    async fn deactivate(&self) -> Result<(), AuthError>;

    /// Get plugin routes
    fn routes(&self) -> Option<Router>;
}

// ============================================
// Auth Plugin Implementation
// ============================================

/// RustPress Authentication Plugin
///
/// Provides complete authentication functionality as a standalone plugin.
pub struct AuthPlugin {
    info: PluginInfo,
    state: RwLock<PluginState>,
    config: RwLock<Option<AuthConfig>>,
    auth_service: RwLock<Option<Arc<AuthService>>>,
    db: RwLock<Option<PgPool>>,
}

impl AuthPlugin {
    /// Create a new auth plugin instance
    pub fn new() -> Self {
        Self {
            info: PluginInfo {
                id: "rustpress-auth".into(),
                name: "RustPress Authentication".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                description: "Core authentication system for RustPress".into(),
            },
            state: RwLock::new(PluginState::Inactive),
            config: RwLock::new(None),
            auth_service: RwLock::new(None),
            db: RwLock::new(None),
        }
    }

    /// Get the authentication configuration
    pub async fn config(&self) -> Option<AuthConfig> {
        self.config.read().await.clone()
    }

    /// Get the authentication service
    pub async fn auth_service(&self) -> Option<Arc<AuthService>> {
        self.auth_service.read().await.clone()
    }

    /// Run database migrations
    async fn run_migrations(&self, db: &PgPool) -> Result<(), AuthError> {
        tracing::info!("Running authentication database migrations");

        // Create user role enum
        sqlx::query(
            r#"
            DO $$ BEGIN
                CREATE TYPE user_role AS ENUM ('user', 'author', 'editor', 'admin');
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
            "#,
        )
        .execute(db)
        .await?;

        // Create user status enum
        sqlx::query(
            r#"
            DO $$ BEGIN
                CREATE TYPE user_status AS ENUM ('pending', 'active', 'suspended', 'deleted');
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
            "#,
        )
        .execute(db)
        .await?;

        // Create users table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                email VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                name VARCHAR(100) NOT NULL,
                role user_role DEFAULT 'user',
                status user_status DEFAULT 'pending',
                avatar VARCHAR(500),
                bio TEXT,
                website VARCHAR(500),
                email_verified_at TIMESTAMPTZ,
                last_login_at TIMESTAMPTZ,
                last_login_ip VARCHAR(45),
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMPTZ,
                password_changed_at TIMESTAMPTZ DEFAULT NOW(),
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );
            "#,
        )
        .execute(db)
        .await?;

        // Create indexes for users
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            .execute(db)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);")
            .execute(db)
            .await?;

        // Create refresh tokens table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash VARCHAR(255) NOT NULL UNIQUE,
                expires_at TIMESTAMPTZ NOT NULL,
                issued_at TIMESTAMPTZ DEFAULT NOW(),
                revoked_at TIMESTAMPTZ,
                replaced_by UUID REFERENCES refresh_tokens(id),
                user_agent TEXT,
                ip_address VARCHAR(45),
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            "#,
        )
        .execute(db)
        .await?;

        // Create indexes for refresh tokens
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);")
            .execute(db)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);",
        )
        .execute(db)
        .await?;

        // Create password reset tokens table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash VARCHAR(255) NOT NULL UNIQUE,
                expires_at TIMESTAMPTZ NOT NULL,
                used_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            "#,
        )
        .execute(db)
        .await?;

        // Create email verification tokens table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS email_verification_tokens (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash VARCHAR(255) NOT NULL UNIQUE,
                expires_at TIMESTAMPTZ NOT NULL,
                used_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            "#,
        )
        .execute(db)
        .await?;

        tracing::info!("Authentication migrations completed successfully");
        Ok(())
    }
}

impl Default for AuthPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for AuthPlugin {
    fn info(&self) -> &PluginInfo {
        &self.info
    }

    async fn state(&self) -> PluginState {
        *self.state.read().await
    }

    async fn activate(&self, db: PgPool) -> Result<(), AuthError> {
        tracing::info!("Activating RustPress Authentication plugin");

        // Run migrations
        self.run_migrations(&db).await?;

        // Load configuration from environment
        let config = AuthConfig::from_env();
        config.validate()?;

        // Initialize auth service
        let auth_service = Arc::new(AuthService::new(db.clone(), config.clone()));

        // Store state
        *self.db.write().await = Some(db);
        *self.config.write().await = Some(config);
        *self.auth_service.write().await = Some(auth_service);
        *self.state.write().await = PluginState::Active;

        tracing::info!("RustPress Authentication plugin activated successfully");
        Ok(())
    }

    async fn deactivate(&self) -> Result<(), AuthError> {
        tracing::info!("Deactivating RustPress Authentication plugin");

        *self.auth_service.write().await = None;
        *self.config.write().await = None;
        *self.db.write().await = None;
        *self.state.write().await = PluginState::Inactive;

        tracing::info!("RustPress Authentication plugin deactivated");
        Ok(())
    }

    fn routes(&self) -> Option<Router> {
        // Routes are created dynamically when auth_service is available
        // Use create_routes() function instead
        None
    }
}

/// Create authentication routes
///
/// Call this after activating the plugin to get the router with all auth endpoints.
pub fn create_routes(auth_service: Arc<AuthService>) -> Router {
    handlers::create_routes(auth_service)
}

// ============================================
// Module Tests
// ============================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_info() {
        let plugin = AuthPlugin::new();
        assert_eq!(plugin.info.id, "rustpress-auth");
        assert_eq!(plugin.info.name, "RustPress Authentication");
    }

    #[tokio::test]
    async fn test_plugin_initial_state() {
        let plugin = AuthPlugin::new();
        assert_eq!(plugin.state().await, PluginState::Inactive);
    }
}
