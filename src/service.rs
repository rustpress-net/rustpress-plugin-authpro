//! Authentication Service
//!
//! Core authentication logic including password hashing, JWT generation,
//! and token management.

use crate::config::AuthConfig;
use crate::error::AuthError;
use crate::models::*;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use sqlx::PgPool;
use uuid::Uuid;

/// Authentication service
pub struct AuthService {
    db: PgPool,
    config: AuthConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl AuthService {
    /// Create a new authentication service
    pub fn new(db: PgPool, config: AuthConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

        Self {
            db,
            config,
            encoding_key,
            decoding_key,
        }
    }

    /// Get reference to the database pool
    pub fn db(&self) -> &PgPool {
        &self.db
    }

    /// Get reference to config
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    // ============================================
    // Password Hashing
    // ============================================

    /// Hash a password using Argon2id
    pub fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);

        let params = Params::new(
            self.config.argon2_memory_cost,
            self.config.argon2_time_cost,
            self.config.argon2_parallelism,
            None,
        )
        .map_err(|_| AuthError::Internal)?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let hash = argon2
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

        Ok(hash)
    }

    /// Verify a password against a hash
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool, AuthError> {
        let parsed_hash = PasswordHash::new(hash).map_err(|_| AuthError::Internal)?;

        let params = Params::new(
            self.config.argon2_memory_cost,
            self.config.argon2_time_cost,
            self.config.argon2_parallelism,
            None,
        )
        .map_err(|_| AuthError::Internal)?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        Ok(argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Validate password strength
    pub fn validate_password(&self, password: &str) -> Result<(), AuthError> {
        if password.len() < self.config.min_password_length {
            return Err(AuthError::WeakPassword);
        }

        // Check for at least one uppercase, lowercase, and digit
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());

        if !has_upper || !has_lower || !has_digit {
            return Err(AuthError::WeakPassword);
        }

        Ok(())
    }

    // ============================================
    // JWT Token Generation
    // ============================================

    /// Generate an access token for a user
    pub fn generate_access_token(&self, user: &User) -> Result<String, AuthError> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.config.access_token_expiration);

        let claims = AccessTokenClaims {
            sub: user.id,
            email: user.email.clone(),
            name: user.name.clone(),
            role: user.role.to_string(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
            iss: self.config.jwt_issuer.clone(),
            aud: self.config.jwt_audience.clone(),
            jti: Uuid::new_v4(),
        };

        let token = encode(&Header::default(), &claims, &self.encoding_key)?;
        Ok(token)
    }

    /// Generate a refresh token
    pub async fn generate_refresh_token(
        &self,
        user_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<String, AuthError> {
        let token_id = Uuid::new_v4();
        let now = Utc::now();
        let exp = now + Duration::seconds(self.config.refresh_token_expiration);

        // Generate random token string
        let token_bytes: [u8; 32] = rand::thread_rng().gen();
        let token_string = base64_url_encode(&token_bytes);

        // Hash the token for storage
        let token_hash = self.hash_token(&token_string);

        // Store in database
        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(token_id)
        .bind(user_id)
        .bind(&token_hash)
        .bind(exp)
        .bind(&ip_address)
        .bind(&user_agent)
        .execute(&self.db)
        .await?;

        // Create JWT containing token ID
        let claims = RefreshTokenClaims {
            sub: user_id,
            tid: token_id,
            iat: now.timestamp(),
            exp: exp.timestamp(),
            iss: self.config.jwt_issuer.clone(),
        };

        let jwt = encode(&Header::default(), &claims, &self.encoding_key)?;

        // Return combined token (JWT + random string for extra verification)
        Ok(format!("{}.{}", jwt, token_string))
    }

    /// Validate an access token
    pub fn validate_access_token(&self, token: &str) -> Result<AccessTokenClaims, AuthError> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.config.jwt_issuer]);
        validation.set_audience(&[&self.config.jwt_audience]);

        let token_data = decode::<AccessTokenClaims>(token, &self.decoding_key, &validation)?;

        Ok(token_data.claims)
    }

    /// Hash a token for secure storage
    fn hash_token(&self, token: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        token.hash(&mut hasher);
        self.config.jwt_secret.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    // ============================================
    // User Registration
    // ============================================

    /// Register a new user
    pub async fn register(&self, req: RegisterRequest) -> Result<User, AuthError> {
        // Validate password strength
        self.validate_password(&req.password)?;

        // Check if email exists
        let existing: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM users WHERE email = $1")
                .bind(&req.email)
                .fetch_optional(&self.db)
                .await?;

        if existing.is_some() {
            return Err(AuthError::EmailExists);
        }

        // Hash password
        let password_hash = self.hash_password(&req.password)?;

        // Insert user
        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (email, password_hash, name, status)
            VALUES ($1, $2, $3, 'active')
            RETURNING *
            "#,
        )
        .bind(&req.email)
        .bind(&password_hash)
        .bind(&req.name)
        .fetch_one(&self.db)
        .await?;

        Ok(user)
    }

    // ============================================
    // Login / Logout
    // ============================================

    /// Attempt to login a user
    pub async fn login(
        &self,
        req: LoginRequest,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<AuthResponse, AuthError> {
        // Find user by email
        let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE email = $1")
            .bind(&req.email)
            .fetch_optional(&self.db)
            .await?;

        let user = user.ok_or(AuthError::InvalidCredentials)?;

        // Check if account is locked
        if user.is_locked() {
            return Err(AuthError::AccountLocked);
        }

        // Check if account is active
        if user.status != UserStatus::Active {
            return Err(AuthError::AccountNotActive);
        }

        // Verify password
        if !self.verify_password(&req.password, &user.password_hash)? {
            // Increment failed attempts
            self.increment_failed_attempts(user.id).await?;
            return Err(AuthError::InvalidCredentials);
        }

        // Check email verification if required
        if self.config.require_email_verification && !user.is_email_verified() {
            return Err(AuthError::EmailNotVerified);
        }

        // Reset failed attempts and update last login
        self.record_successful_login(user.id, ip_address.clone())
            .await?;

        // Generate tokens
        let access_token = self.generate_access_token(&user)?;
        let refresh_token = self
            .generate_refresh_token(user.id, ip_address, user_agent)
            .await?;

        Ok(AuthResponse {
            user: UserResponse::from(user),
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.access_token_expiration,
        })
    }

    /// Logout by revoking refresh token
    pub async fn logout(&self, refresh_token: &str) -> Result<(), AuthError> {
        // Parse the refresh token
        let parts: Vec<&str> = refresh_token.rsplitn(2, '.').collect();
        if parts.len() != 2 {
            return Err(AuthError::InvalidToken);
        }

        let jwt_part = parts[1];

        // Decode JWT to get token ID
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.config.jwt_issuer]);
        validation.insecure_disable_signature_validation();

        let token_data = decode::<RefreshTokenClaims>(jwt_part, &self.decoding_key, &validation)?;

        // Revoke the token
        sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1")
            .bind(token_data.claims.tid)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    // ============================================
    // Token Refresh
    // ============================================

    /// Refresh access token using refresh token (with rotation)
    pub async fn refresh_tokens(
        &self,
        refresh_token: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<TokenResponse, AuthError> {
        // Parse the refresh token
        let parts: Vec<&str> = refresh_token.rsplitn(2, '.').collect();
        if parts.len() != 2 {
            return Err(AuthError::InvalidToken);
        }

        let (token_string, jwt_part) = (parts[0], parts[1]);

        // Validate JWT
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.config.jwt_issuer]);

        let token_data = decode::<RefreshTokenClaims>(jwt_part, &self.decoding_key, &validation)?;
        let claims = token_data.claims;

        // Verify token in database
        let token_hash = self.hash_token(token_string);
        let stored_token: Option<RefreshToken> = sqlx::query_as(
            "SELECT * FROM refresh_tokens WHERE id = $1 AND token_hash = $2",
        )
        .bind(claims.tid)
        .bind(&token_hash)
        .fetch_optional(&self.db)
        .await?;

        let stored_token = stored_token.ok_or(AuthError::InvalidToken)?;

        if !stored_token.is_valid() {
            // Token reuse detected - revoke all tokens for this user
            if stored_token.is_revoked() {
                tracing::warn!(
                    user_id = %claims.sub,
                    "Refresh token reuse detected, revoking all tokens"
                );
                self.revoke_all_tokens(claims.sub).await?;
            }
            return Err(AuthError::TokenRevoked);
        }

        // Get user
        let user: User = sqlx::query_as("SELECT * FROM users WHERE id = $1")
            .bind(claims.sub)
            .fetch_optional(&self.db)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        if !user.can_login() {
            return Err(AuthError::AccountNotActive);
        }

        // Generate new tokens
        let new_access_token = self.generate_access_token(&user)?;
        let new_refresh_token = self
            .generate_refresh_token(user.id, ip_address, user_agent)
            .await?;

        // Revoke old refresh token (rotation)
        sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1")
            .bind(claims.tid)
            .execute(&self.db)
            .await?;

        Ok(TokenResponse {
            access_token: new_access_token,
            refresh_token: new_refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.access_token_expiration,
        })
    }

    /// Revoke all refresh tokens for a user
    async fn revoke_all_tokens(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    // ============================================
    // Password Management
    // ============================================

    /// Initiate password reset
    pub async fn forgot_password(&self, email: &str) -> Result<String, AuthError> {
        // Find user
        let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.db)
            .await?;

        // Always return success to prevent email enumeration
        let user = match user {
            Some(u) => u,
            None => return Ok(String::new()),
        };

        // Generate reset token
        let token_bytes: [u8; 32] = rand::thread_rng().gen();
        let token = base64_url_encode(&token_bytes);
        let token_hash = self.hash_token(&token);

        let expires_at = Utc::now() + Duration::seconds(self.config.password_reset_expiration);

        // Invalidate existing tokens
        sqlx::query("UPDATE password_reset_tokens SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL")
            .bind(user.id)
            .execute(&self.db)
            .await?;

        // Store new token
        sqlx::query(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(user.id)
        .bind(&token_hash)
        .bind(expires_at)
        .execute(&self.db)
        .await?;

        Ok(token)
    }

    /// Complete password reset
    pub async fn reset_password(&self, req: ResetPasswordRequest) -> Result<(), AuthError> {
        // Validate new password
        self.validate_password(&req.password)?;

        let token_hash = self.hash_token(&req.token);

        // Find valid token
        let token_record: Option<(Uuid, Uuid)> = sqlx::query_as(
            r#"
            SELECT id, user_id FROM password_reset_tokens
            WHERE token_hash = $1 AND expires_at > NOW() AND used_at IS NULL
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&self.db)
        .await?;

        let (token_id, user_id) = token_record.ok_or(AuthError::InvalidToken)?;

        // Hash new password
        let password_hash = self.hash_password(&req.password)?;

        // Update user password
        sqlx::query(
            "UPDATE users SET password_hash = $1, password_changed_at = NOW(), updated_at = NOW() WHERE id = $2",
        )
        .bind(&password_hash)
        .bind(user_id)
        .execute(&self.db)
        .await?;

        // Mark token as used
        sqlx::query("UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1")
            .bind(token_id)
            .execute(&self.db)
            .await?;

        // Revoke all refresh tokens
        self.revoke_all_tokens(user_id).await?;

        Ok(())
    }

    /// Change password for authenticated user
    pub async fn change_password(
        &self,
        user_id: Uuid,
        req: ChangePasswordRequest,
    ) -> Result<(), AuthError> {
        // Get user
        let user: User = sqlx::query_as("SELECT * FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&self.db)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // Verify current password
        if !self.verify_password(&req.current_password, &user.password_hash)? {
            return Err(AuthError::InvalidCredentials);
        }

        // Validate new password
        self.validate_password(&req.new_password)?;

        // Hash new password
        let password_hash = self.hash_password(&req.new_password)?;

        // Update password
        sqlx::query(
            "UPDATE users SET password_hash = $1, password_changed_at = NOW(), updated_at = NOW() WHERE id = $2",
        )
        .bind(&password_hash)
        .bind(user_id)
        .execute(&self.db)
        .await?;

        // Revoke all refresh tokens
        self.revoke_all_tokens(user_id).await?;

        Ok(())
    }

    // ============================================
    // Email Verification
    // ============================================

    /// Create email verification token
    pub async fn create_email_verification(&self, user_id: Uuid) -> Result<String, AuthError> {
        let token_bytes: [u8; 32] = rand::thread_rng().gen();
        let token = base64_url_encode(&token_bytes);
        let token_hash = self.hash_token(&token);

        let expires_at =
            Utc::now() + Duration::seconds(self.config.email_verification_expiration);

        // Invalidate existing tokens
        sqlx::query(
            "UPDATE email_verification_tokens SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL",
        )
        .bind(user_id)
        .execute(&self.db)
        .await?;

        // Store new token
        sqlx::query(
            "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(user_id)
        .bind(&token_hash)
        .bind(expires_at)
        .execute(&self.db)
        .await?;

        Ok(token)
    }

    /// Verify email with token
    pub async fn verify_email(&self, token: &str) -> Result<User, AuthError> {
        let token_hash = self.hash_token(token);

        // Find valid token
        let token_record: Option<(Uuid, Uuid)> = sqlx::query_as(
            r#"
            SELECT id, user_id FROM email_verification_tokens
            WHERE token_hash = $1 AND expires_at > NOW() AND used_at IS NULL
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&self.db)
        .await?;

        let (token_id, user_id) = token_record.ok_or(AuthError::InvalidToken)?;

        // Update user
        let user: User = sqlx::query_as(
            "UPDATE users SET email_verified_at = NOW(), status = 'active', updated_at = NOW() WHERE id = $1 RETURNING *",
        )
        .bind(user_id)
        .fetch_one(&self.db)
        .await?;

        // Mark token as used
        sqlx::query("UPDATE email_verification_tokens SET used_at = NOW() WHERE id = $1")
            .bind(token_id)
            .execute(&self.db)
            .await?;

        Ok(user)
    }

    // ============================================
    // User Management Helpers
    // ============================================

    /// Get user by ID
    pub async fn get_user(&self, user_id: Uuid) -> Result<Option<User>, AuthError> {
        let user = sqlx::query_as("SELECT * FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&self.db)
            .await?;
        Ok(user)
    }

    /// Get user by email
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let user = sqlx::query_as("SELECT * FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.db)
            .await?;
        Ok(user)
    }

    /// Increment failed login attempts
    async fn increment_failed_attempts(&self, user_id: Uuid) -> Result<(), AuthError> {
        let result = sqlx::query(
            r#"
            UPDATE users SET
                failed_login_attempts = failed_login_attempts + 1,
                locked_until = CASE
                    WHEN failed_login_attempts + 1 >= $2
                    THEN NOW() + INTERVAL '1 second' * $3
                    ELSE locked_until
                END,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(self.config.max_login_attempts)
        .bind(self.config.lockout_duration)
        .execute(&self.db)
        .await?;

        if result.rows_affected() == 0 {
            tracing::warn!(user_id = %user_id, "Failed to increment login attempts");
        }

        Ok(())
    }

    /// Record successful login
    async fn record_successful_login(
        &self,
        user_id: Uuid,
        ip_address: Option<String>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE users SET
                failed_login_attempts = 0,
                locked_until = NULL,
                last_login_at = NOW(),
                last_login_ip = $2,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(ip_address)
        .execute(&self.db)
        .await?;

        Ok(())
    }
}

/// URL-safe base64 encoding
fn base64_url_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::new();
    for byte in data {
        write!(result, "{:02x}", byte).unwrap();
    }
    result
}
