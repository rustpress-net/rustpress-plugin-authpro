//! Rate limiting for authentication endpoints.
//!
//! Wraps [`tower_governor`] to provide per-IP token-bucket limits on sensitive
//! routes (`/auth/login`, `/auth/register`, `/auth/refresh`,
//! `/auth/forgot-password`, `/auth/reset-password`). Returns HTTP 429
//! `Too Many Requests` with a standard `Retry-After` header when callers
//! exceed the configured budget.
//!
//! ## Configuration
//!
//! All knobs are loaded from environment variables, with sane defaults:
//!
//! | Env var                          | Default | Meaning                                    |
//! |----------------------------------|---------|--------------------------------------------|
//! | `AUTHPRO_LOGIN_RATE_PER_MIN`     | 10      | Sustained requests per minute per IP       |
//! | `AUTHPRO_LOGIN_BURST`            | 5       | Maximum burst above the sustained rate     |
//! | `AUTHPRO_RATE_LIMIT_DISABLED`    | unset   | If "true"/"1", disables the limiter        |
//!
//! The sustained rate is converted to a per-request replenishment interval:
//! `per_request_ms = 60_000 / AUTHPRO_LOGIN_RATE_PER_MIN`. So the default
//! 10/min means one new token every 6 seconds, with a burst pool of 5.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    http::{header, HeaderValue, Response, StatusCode},
    Router,
};
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorError,
    GovernorLayer,
};

/// Configuration knobs for the auth rate limiter.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Sustained requests per minute, per client key (IP).
    pub per_minute: u32,
    /// Burst size — extra tokens available above the sustained rate.
    pub burst: u32,
    /// If true, the limiter is bypassed entirely (returns no layer).
    pub disabled: bool,
}

impl RateLimitConfig {
    /// Load config from environment variables, falling back to defaults.
    pub fn from_env() -> Self {
        let per_minute = env::var("AUTHPRO_LOGIN_RATE_PER_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|v: &u32| *v > 0)
            .unwrap_or(10);

        let burst = env::var("AUTHPRO_LOGIN_BURST")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|v: &u32| *v > 0)
            .unwrap_or(5);

        let disabled = env::var("AUTHPRO_RATE_LIMIT_DISABLED")
            .ok()
            .map(|v| {
                let v = v.to_lowercase();
                v == "true" || v == "1" || v == "yes"
            })
            .unwrap_or(false);

        Self {
            per_minute,
            burst,
            disabled,
        }
    }

    /// Convert per-minute rate to a per-request replenishment interval.
    ///
    /// Floors at 1ms to avoid a zero-duration spam loop and avoids `None`
    /// from `GovernorConfigBuilder::finish` if the math underflows.
    pub fn replenish_interval(&self) -> Duration {
        if self.per_minute == 0 {
            return Duration::from_secs(60);
        }
        let millis = 60_000u64 / u64::from(self.per_minute.max(1));
        Duration::from_millis(millis.max(1))
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_minute: 10,
            burst: 5,
            disabled: false,
        }
    }
}

/// Custom error handler that converts a `GovernorError::TooManyRequests`
/// into a 429 response with both the standard `Retry-After` header and the
/// non-standard `x-ratelimit-after` header (so existing clients of either
/// convention work).
fn rate_limit_error_handler(err: GovernorError) -> Response<Body> {
    match err {
        GovernorError::TooManyRequests { wait_time, .. } => {
            let mut resp = Response::new(Body::from(format!(
                "Too Many Requests. Retry after {wait_time}s."
            )));
            *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            let headers = resp.headers_mut();
            // Standard HTTP Retry-After header (RFC 9110 §10.2.3).
            if let Ok(v) = HeaderValue::from_str(&wait_time.to_string()) {
                headers.insert(header::RETRY_AFTER, v);
            }
            // tower_governor's non-standard companion.
            if let Ok(v) = HeaderValue::from_str(&wait_time.to_string()) {
                headers.insert("x-ratelimit-after", v);
            }
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            resp
        }
        GovernorError::UnableToExtractKey => {
            let mut resp = Response::new(Body::from("Unable to extract client identifier"));
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            resp
        }
        GovernorError::Other { code, msg, .. } => {
            let body = msg.unwrap_or_else(|| "Rate limit error".to_string());
            let mut resp = Response::new(Body::from(body));
            *resp.status_mut() = code;
            resp
        }
    }
}

/// Apply the auth rate limiter to a router.
///
/// Reads configuration from the supplied `RateLimitConfig` and either layers a
/// `tower_governor` limiter on top of the supplied router, or returns the
/// router unchanged if the limiter is disabled. The limiter uses
/// `SmartIpKeyExtractor` (X-Forwarded-For / X-Real-IP / peer address) so
/// callers behind a reverse proxy still get per-client limits.
///
/// When a client exceeds the budget, the layer short-circuits the request
/// with HTTP 429 and a `Retry-After` header.
pub fn apply_auth_rate_limit<S>(router: Router<S>, cfg: RateLimitConfig) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    if cfg.disabled {
        return router;
    }

    let interval = cfg.replenish_interval();

    // `key_extractor(...)` returns a new builder by value, so we bind the
    // initial builder, swap its extractor, and then run the remaining
    // `&mut self`-style setters on the new binding.
    let mut initial = GovernorConfigBuilder::default();
    let mut builder = initial.key_extractor(SmartIpKeyExtractor);
    builder
        .period(interval)
        .burst_size(cfg.burst)
        .error_handler(rate_limit_error_handler);

    let governor_conf = match builder.finish() {
        Some(c) => c,
        None => {
            tracing::warn!(
                per_minute = cfg.per_minute,
                burst = cfg.burst,
                "Rate limit config invalid; skipping rate limiter"
            );
            return router;
        }
    };

    router.layer(GovernorLayer {
        config: Arc::new(governor_conf),
    })
}

/// Build a 429 response with `Retry-After` set.
///
/// Used in tests and as a reference shape for what the governor produces.
pub fn too_many_requests_response(retry_after_secs: u64) -> Response<Body> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(header::RETRY_AFTER, retry_after_secs.to_string())
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from("Too Many Requests"))
        .expect("static response is well-formed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let cfg = RateLimitConfig::default();
        assert_eq!(cfg.per_minute, 10);
        assert_eq!(cfg.burst, 5);
        assert!(!cfg.disabled);
    }

    #[test]
    fn replenish_interval_matches_per_minute() {
        let cfg = RateLimitConfig {
            per_minute: 60,
            burst: 5,
            disabled: false,
        };
        // 60/min -> one token every second
        assert_eq!(cfg.replenish_interval(), Duration::from_secs(1));
    }

    #[test]
    fn replenish_interval_handles_low_rates() {
        let cfg = RateLimitConfig {
            per_minute: 10,
            burst: 5,
            disabled: false,
        };
        // 10/min -> 6s interval
        assert_eq!(cfg.replenish_interval(), Duration::from_millis(6000));
    }

    #[test]
    fn replenish_interval_never_zero() {
        // Even an absurdly high per_minute should not produce a zero interval.
        let cfg = RateLimitConfig {
            per_minute: u32::MAX,
            burst: 5,
            disabled: false,
        };
        assert!(cfg.replenish_interval() >= Duration::from_millis(1));
    }

    #[test]
    fn too_many_requests_has_retry_after() {
        let resp = too_many_requests_response(42);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers().get(header::RETRY_AFTER).and_then(|v| v.to_str().ok()),
            Some("42")
        );
    }

    #[test]
    fn error_handler_produces_429_with_retry_after() {
        let err = GovernorError::TooManyRequests {
            wait_time: 7,
            headers: None,
        };
        let resp = rate_limit_error_handler(err);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers().get(header::RETRY_AFTER).and_then(|v| v.to_str().ok()),
            Some("7")
        );
    }

    #[test]
    fn error_handler_unable_to_extract_key_is_500() {
        let err = GovernorError::UnableToExtractKey;
        let resp = rate_limit_error_handler(err);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
