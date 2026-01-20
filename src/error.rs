//! Authentication Error Types
//!
//! Centralized error handling for all authentication operations.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

/// Authentication errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Account is locked. Try again later")]
    AccountLocked,

    #[error("Account is not active")]
    AccountNotActive,

    #[error("Email not verified")]
    EmailNotVerified,

    #[error("Invalid or expired token")]
    InvalidToken,

    #[error("Token has been revoked")]
    TokenRevoked,

    #[error("User not found")]
    UserNotFound,

    #[error("Email already registered")]
    EmailExists,

    #[error("Password does not meet requirements")]
    WeakPassword,

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Internal error")]
    Internal,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match &self {
            AuthError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                self.to_string(),
            ),
            AuthError::AccountLocked => (
                StatusCode::FORBIDDEN,
                "account_locked",
                self.to_string(),
            ),
            AuthError::AccountNotActive => (
                StatusCode::FORBIDDEN,
                "account_not_active",
                self.to_string(),
            ),
            AuthError::EmailNotVerified => (
                StatusCode::FORBIDDEN,
                "email_not_verified",
                self.to_string(),
            ),
            AuthError::InvalidToken | AuthError::TokenRevoked => (
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                self.to_string(),
            ),
            AuthError::UserNotFound => (
                StatusCode::NOT_FOUND,
                "user_not_found",
                self.to_string(),
            ),
            AuthError::EmailExists => (
                StatusCode::CONFLICT,
                "email_exists",
                self.to_string(),
            ),
            AuthError::WeakPassword => (
                StatusCode::BAD_REQUEST,
                "weak_password",
                self.to_string(),
            ),
            AuthError::Validation(msg) => (
                StatusCode::BAD_REQUEST,
                "validation_error",
                msg.clone(),
            ),
            AuthError::Config(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "configuration_error",
                msg.clone(),
            ),
            AuthError::Database(_) | AuthError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "An internal error occurred".to_string(),
            ),
        };

        (
            status,
            Json(serde_json::json!({
                "error": error_code,
                "message": message
            })),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for AuthError {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!("Database error: {:?}", err);
        AuthError::Database(err.to_string())
    }
}

impl From<argon2::password_hash::Error> for AuthError {
    fn from(err: argon2::password_hash::Error) -> Self {
        tracing::error!("Password hashing error: {:?}", err);
        AuthError::Internal
    }
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        tracing::debug!("JWT error: {:?}", err);
        AuthError::InvalidToken
    }
}
