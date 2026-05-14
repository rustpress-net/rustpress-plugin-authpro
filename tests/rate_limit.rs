//! Rate-limit integration test.
//!
//! Spins up a minimal Axum router with the same `tower_governor` layer the
//! plugin mounts on `/auth/login` etc., then fires more requests than the
//! burst budget allows and asserts the limiter responds 429 with a
//! `Retry-After` header.
//!
//! We test the limiter directly (against a stub handler) rather than
//! the full auth router, because the auth endpoints require a Postgres
//! pool we don't have here. The behaviour under test is the rate-limit
//! layer itself, which is identical in both cases.

mod common;

use axum::{routing::post, Router};
use http_body_util::BodyExt;
use hyper::{Request, StatusCode};
use rustpress_auth::{apply_auth_rate_limit, RateLimitConfig};
use tower::ServiceExt;

/// Helper: stand up a router wrapping a no-op handler behind the auth
/// rate-limit layer, configured for a tight `per_minute` + `burst`.
fn limited_router(per_minute: u32, burst: u32) -> Router {
    let inner = Router::new().route("/auth/login", post(|| async { "ok" }));
    let cfg = RateLimitConfig {
        per_minute,
        burst,
        disabled: false,
    };
    apply_auth_rate_limit(inner, cfg)
}

/// Build a `POST /auth/login` request from a synthetic client IP.
///
/// The IP is set via `X-Forwarded-For` since `tower_governor`'s
/// `SmartIpKeyExtractor` (used by `apply_auth_rate_limit`'s
/// `use_headers()`) prefers that header.
fn login_request(ip: &str) -> Request<axum::body::Body> {
    Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("X-Forwarded-For", ip)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(
            r#"{"email":"a@b.c","password":"x"}"#,
        ))
        .unwrap()
}

#[tokio::test]
async fn requests_within_burst_succeed() {
    let app = limited_router(60, 5); // 60/min = 1/s, burst 5
    for i in 0..5 {
        let resp = app
            .clone()
            .oneshot(login_request("10.0.0.1"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "request {i} in burst window should succeed"
        );
    }
}

#[tokio::test]
async fn over_budget_returns_429() {
    // Tight budget: 6/min (one every 10s), burst 3 — the 4th request must
    // get rate-limited.
    let app = limited_router(6, 3);
    for _ in 0..3 {
        let resp = app
            .clone()
            .oneshot(login_request("10.0.0.2"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let resp = app
        .clone()
        .oneshot(login_request("10.0.0.2"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "4th request in burst window must be throttled"
    );
}

#[tokio::test]
async fn limiter_returns_retry_after_header() {
    let app = limited_router(6, 2);
    // Burn through the budget.
    for _ in 0..2 {
        let _ = app
            .clone()
            .oneshot(login_request("10.0.0.3"))
            .await
            .unwrap();
    }
    let resp = app
        .clone()
        .oneshot(login_request("10.0.0.3"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    // `tower_governor` with `use_headers()` writes Retry-After and the
    // governor rate-limit headers.
    let retry_after = resp.headers().get("retry-after");
    assert!(
        retry_after.is_some(),
        "Retry-After header must be present on 429"
    );
}

#[tokio::test]
async fn different_ips_have_independent_budgets() {
    // Each IP gets its own bucket. If client A burns through, client B
    // must still be served.
    let app = limited_router(6, 2);
    for _ in 0..2 {
        let resp = app
            .clone()
            .oneshot(login_request("10.0.0.10"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let throttled = app
        .clone()
        .oneshot(login_request("10.0.0.10"))
        .await
        .unwrap();
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);

    // Different IP — should still get served.
    let resp_b = app
        .clone()
        .oneshot(login_request("10.0.0.11"))
        .await
        .unwrap();
    assert_eq!(
        resp_b.status(),
        StatusCode::OK,
        "fresh client IP must not be throttled by another IP's overuse"
    );
}

#[tokio::test]
async fn disabled_config_skips_limiter_entirely() {
    let inner = Router::new().route("/auth/login", post(|| async { "ok" }));
    let cfg = RateLimitConfig {
        per_minute: 1,
        burst: 1,
        disabled: true,
    };
    let app = apply_auth_rate_limit(inner, cfg);

    // Fire many more requests than the (tight) budget would have allowed.
    for _ in 0..20 {
        let resp = app
            .clone()
            .oneshot(login_request("10.0.0.20"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "disabled limiter must never throttle"
        );
    }
}

#[tokio::test]
async fn throttled_response_body_is_non_empty() {
    let app = limited_router(6, 1);
    let _ = app.clone().oneshot(login_request("10.0.0.30")).await.unwrap();
    let resp = app
        .clone()
        .oneshot(login_request("10.0.0.30"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(!body.is_empty(), "429 should carry an explanatory body");
}
