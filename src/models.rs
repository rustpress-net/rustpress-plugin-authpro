//! Authentication Models
//!
//! Data structures for authentication requests, responses, and database entities.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

// ============================================
// Database Entities
// ============================================

/// User role enum matching database type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    User,
    Author,
    Editor,
    Admin,
}

impl UserRole {
    pub fn is_admin(&self) -> bool {
        matches!(self, UserRole::Admin)
    }

    pub fn can_publish(&self) -> bool {
        matches!(self, UserRole::Author | UserRole::Editor | UserRole::Admin)
    }

    pub fn can_moderate(&self) -> bool {
        matches!(self, UserRole::Editor | UserRole::Admin)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            UserRole::User => "user",
            UserRole::Author => "author",
            UserRole::Editor => "editor",
            UserRole::Admin => "admin",
        }
    }
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// User status enum matching database type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    Pending,
    Active,
    Suspended,
    Deleted,
}

/// User entity from database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub name: String,
    pub role: UserRole,
    pub status: UserStatus,
    pub avatar: Option<String>,
    pub bio: Option<String>,
    pub website: Option<String>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub last_login_ip: Option<String>,
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub password_changed_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Check if user account is locked
    pub fn is_locked(&self) -> bool {
        if let Some(locked_until) = self.locked_until {
            locked_until > Utc::now()
        } else {
            false
        }
    }

    /// Check if user email is verified
    pub fn is_email_verified(&self) -> bool {
        self.email_verified_at.is_some()
    }

    /// Check if user is active and can login
    pub fn can_login(&self) -> bool {
        self.status == UserStatus::Active && !self.is_locked()
    }

    /// Check if user is admin
    pub fn is_admin(&self) -> bool {
        self.role.is_admin()
    }
}

/// Refresh token entity from database
#[derive(Debug, Clone, FromRow)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub issued_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub replaced_by: Option<Uuid>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl RefreshToken {
    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Check if token is revoked
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Check if token is valid
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_revoked()
    }
}

// ============================================
// Request DTOs
// ============================================

/// Login request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

/// Registration request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,

    #[validate(must_match(other = "password", message = "Passwords do not match"))]
    pub password_confirm: String,

    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: String,
}

/// Refresh token request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct RefreshTokenRequest {
    #[validate(length(min = 1, message = "Refresh token is required"))]
    pub refresh_token: String,
}

/// Password reset request (initiate)
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ForgotPasswordRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
}

/// Password reset request (complete)
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ResetPasswordRequest {
    #[validate(length(min = 1, message = "Token is required"))]
    pub token: String,

    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,

    #[validate(must_match(other = "password", message = "Passwords do not match"))]
    pub password_confirm: String,
}

/// Change password request (for authenticated users)
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 1, message = "Current password is required"))]
    pub current_password: String,

    #[validate(length(min = 8, message = "New password must be at least 8 characters"))]
    pub new_password: String,

    #[validate(must_match(other = "new_password", message = "Passwords do not match"))]
    pub new_password_confirm: String,
}

/// Email verification request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct VerifyEmailRequest {
    #[validate(length(min = 1, message = "Token is required"))]
    pub token: String,
}

// ============================================
// Response DTOs
// ============================================

/// User response (public user data without sensitive fields)
#[derive(Debug, Clone, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub role: UserRole,
    pub avatar: Option<String>,
    pub bio: Option<String>,
    pub website: Option<String>,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        let email_verified = user.is_email_verified();
        Self {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            avatar: user.avatar,
            bio: user.bio,
            website: user.website,
            email_verified,
            created_at: user.created_at,
        }
    }
}

impl From<&User> for UserResponse {
    fn from(user: &User) -> Self {
        Self {
            id: user.id,
            email: user.email.clone(),
            name: user.name.clone(),
            role: user.role.clone(),
            avatar: user.avatar.clone(),
            bio: user.bio.clone(),
            website: user.website.clone(),
            email_verified: user.is_email_verified(),
            created_at: user.created_at,
        }
    }
}

/// Authentication response with tokens
#[derive(Debug, Clone, Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// Token refresh response
#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// Simple message response
#[derive(Debug, Clone, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

impl MessageResponse {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

// ============================================
// JWT Claims
// ============================================

/// JWT claims for access tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject (user ID)
    pub sub: Uuid,
    /// User email
    pub email: String,
    /// User name
    pub name: String,
    /// User role
    pub role: String,
    /// Issued at timestamp
    pub iat: i64,
    /// Expiration timestamp
    pub exp: i64,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// JWT ID (unique identifier)
    pub jti: Uuid,
}

/// JWT claims for refresh tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    /// Subject (user ID)
    pub sub: Uuid,
    /// Token ID (references refresh_tokens table)
    pub tid: Uuid,
    /// Issued at timestamp
    pub iat: i64,
    /// Expiration timestamp
    pub exp: i64,
    /// Issuer
    pub iss: String,
}
