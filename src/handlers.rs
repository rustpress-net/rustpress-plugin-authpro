//! Authentication HTTP Handlers
//!
//! REST API endpoints for authentication operations.

use crate::error::AuthError;
use crate::extractors::{AuthUser, ClientInfo};
use crate::middleware;
use crate::models::*;
use crate::service::AuthService;

use axum::{
    extract::State,
    http::StatusCode,
    middleware as axum_middleware,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use validator::Validate;

/// Shared auth service state
pub type AuthState = Arc<AuthService>;

// ============================================
// Route Builder
// ============================================

/// Create authentication routes
pub fn create_routes(auth_service: Arc<AuthService>) -> Router {
    // Public routes (no authentication required)
    let public = Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/refresh", post(refresh_token))
        .route("/auth/forgot-password", post(forgot_password))
        .route("/auth/reset-password", post(reset_password))
        .route("/auth/verify-email", post(verify_email));

    // Protected routes (require authentication)
    let protected = Router::new()
        .route("/auth/me", get(get_current_user))
        .route("/auth/change-password", post(change_password))
        .route("/auth/resend-verification", post(resend_verification))
        .layer(axum_middleware::from_fn(middleware::require_auth));

    Router::new()
        .merge(public)
        .merge(protected)
        .with_state(auth_service)
}

// ============================================
// Registration
// ============================================

/// POST /auth/register
///
/// Register a new user account
pub async fn register(
    State(auth): State<AuthState>,
    Json(req): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AuthError> {
    // Validate request
    req.validate()
        .map_err(|e| AuthError::Validation(e.to_string()))?;

    // Register user
    let user = auth.register(req).await?;

    // Create email verification token
    let verification_token = auth.create_email_verification(user.id).await?;

    tracing::info!(
        user_id = %user.id,
        "User registered, verification token created"
    );

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Registration successful. Please verify your email.",
            "user": UserResponse::from(user),
            // In production, don't return this - send via email
            "verification_token": verification_token
        })),
    ))
}

// ============================================
// Login / Logout
// ============================================

/// POST /auth/login
///
/// Authenticate user and return access/refresh tokens
pub async fn login(
    State(auth): State<AuthState>,
    ClientInfo { ip, user_agent }: ClientInfo,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthError> {
    // Validate request
    req.validate()
        .map_err(|e| AuthError::Validation(e.to_string()))?;

    // Attempt login
    let response = auth.login(req, ip, user_agent).await?;

    Ok(Json(response))
}

/// POST /auth/logout
///
/// Revoke refresh token and logout user
pub async fn logout(
    State(auth): State<AuthState>,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, AuthError> {
    auth.logout(&req.refresh_token).await?;

    Ok(Json(MessageResponse::new("Logged out successfully")))
}

// ============================================
// Token Refresh
// ============================================

/// POST /auth/refresh
///
/// Refresh access token using refresh token
pub async fn refresh_token(
    State(auth): State<AuthState>,
    ClientInfo { ip, user_agent }: ClientInfo,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, AuthError> {
    req.validate()
        .map_err(|e| AuthError::Validation(e.to_string()))?;

    let response = auth.refresh_tokens(&req.refresh_token, ip, user_agent).await?;

    Ok(Json(response))
}

// ============================================
// Password Management
// ============================================

/// POST /auth/forgot-password
///
/// Initiate password reset process
pub async fn forgot_password(
    State(auth): State<AuthState>,
    Json(req): Json<ForgotPasswordRequest>,
) -> Result<impl IntoResponse, AuthError> {
    req.validate()
        .map_err(|e| AuthError::Validation(e.to_string()))?;

    // Generate reset token
    let token = auth.forgot_password(&req.email).await?;

    // In production, send token via email, don't return it
    // Always return success to prevent email enumeration

    Ok(Json(serde_json::json!({
        "message": "If an account with that email exists, a password reset link has been sent.",
        // In production, remove this line - send via email
        "reset_token": if !token.is_empty() { Some(token) } else { None }
    })))
}

/// POST /auth/reset-password
///
/// Complete password reset with token
pub async fn reset_password(
    State(auth): State<AuthState>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<impl IntoResponse, AuthError> {
    req.validate()
        .map_err(|e| AuthError::Validation(e.to_string()))?;

    auth.reset_password(req).await?;

    Ok(Json(MessageResponse::new(
        "Password reset successful. Please login with your new password.",
    )))
}

/// POST /auth/change-password
///
/// Change password for authenticated user
pub async fn change_password(
    State(auth): State<AuthState>,
    user: AuthUser,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, AuthError> {
    req.validate()
        .map_err(|e| AuthError::Validation(e.to_string()))?;

    auth.change_password(user.id, req).await?;

    Ok(Json(MessageResponse::new(
        "Password changed successfully. Please login again on all devices.",
    )))
}

// ============================================
// Email Verification
// ============================================

/// POST /auth/verify-email
///
/// Verify email address with token
pub async fn verify_email(
    State(auth): State<AuthState>,
    Json(req): Json<VerifyEmailRequest>,
) -> Result<impl IntoResponse, AuthError> {
    req.validate()
        .map_err(|e| AuthError::Validation(e.to_string()))?;

    let user = auth.verify_email(&req.token).await?;

    Ok(Json(serde_json::json!({
        "message": "Email verified successfully",
        "user": UserResponse::from(user)
    })))
}

/// POST /auth/resend-verification
///
/// Resend email verification token
pub async fn resend_verification(
    State(auth): State<AuthState>,
    user: AuthUser,
) -> Result<impl IntoResponse, AuthError> {
    // Get full user to check email verification status
    let full_user = auth
        .get_user(user.id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    if full_user.email_verified_at.is_some() {
        return Ok(Json(serde_json::json!({
            "message": "Email is already verified"
        })));
    }

    let token = auth.create_email_verification(user.id).await?;

    // In production, send via email
    Ok(Json(serde_json::json!({
        "message": "Verification email sent",
        // In production, remove this - send via email
        "verification_token": token
    })))
}

// ============================================
// User Profile
// ============================================

/// GET /auth/me
///
/// Get current user profile
pub async fn get_current_user(user: AuthUser) -> Result<impl IntoResponse, AuthError> {
    Ok(Json(serde_json::json!({
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "role": user.role
        }
    })))
}
