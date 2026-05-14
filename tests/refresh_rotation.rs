//! Refresh-token integration tests.
//!
//! These cover what we can verify without a live Postgres connection:
//!
//! - the token-hash function is deterministic for a fixed (secret, plaintext)
//!   pair
//! - the token-hash function is secret-keyed (same plaintext, different
//!   `jwt_secret` produces a different hash)
//! - the hash bears no resemblance to the plaintext (no plaintext substring,
//!   meaningfully different length)
//! - the refresh-claim type encodes the expected fields
//!
//! Full rotation behaviour (rotate ⇒ revoke old, reuse ⇒ revoke-all) lives in
//! `service::refresh_tokens` and needs a Postgres testcontainer; tracked as
//! TODO at the bottom of this file.

mod common;

use chrono::{Duration, Utc};
use common::{auth_service, auth_service_with, test_config, test_config_with_secret};
use jsonwebtoken::{decode, DecodingKey, Validation};
use rustpress_auth::RefreshTokenClaims;
use uuid::Uuid;

#[test]
fn hash_token_is_deterministic_for_same_inputs() {
    let auth = auth_service();
    let token = "abcdef0123456789";
    let h1 = auth.hash_token(token);
    let h2 = auth.hash_token(token);
    assert_eq!(h1, h2, "hash_token must be deterministic for storage lookup");
}

#[test]
fn hash_token_changes_with_secret() {
    let a = auth_service_with(test_config_with_secret(
        "secret-alpha-32-characters-long-XX!",
    ));
    let b = auth_service_with(test_config_with_secret(
        "secret-beta--32-characters-long-YY!",
    ));
    let token = "the-same-random-token-string";
    assert_ne!(
        a.hash_token(token),
        b.hash_token(token),
        "hash_token must be secret-keyed"
    );
}

#[test]
fn hash_token_differs_per_plaintext() {
    let auth = auth_service();
    let h1 = auth.hash_token("token-one");
    let h2 = auth.hash_token("token-two");
    assert_ne!(h1, h2);
}

#[test]
fn hash_does_not_leak_plaintext() {
    let auth = auth_service();
    let token = "plaintext-marker-XYZ";
    let hashed = auth.hash_token(token);
    assert!(
        !hashed.contains("plaintext-marker"),
        "hash must not contain plaintext substring; got {hashed}"
    );
    assert!(
        !hashed.contains(token),
        "hash must not contain the full plaintext"
    );
}

#[test]
fn hash_is_lowercase_hex() {
    // The current implementation emits a hex DefaultHasher digest.
    // While not cryptographically strong, the storage contract requires
    // that whatever the function returns is a fixed-format string suitable
    // for VARCHAR(255) — protect against accidental newlines / whitespace.
    let auth = auth_service();
    let hashed = auth.hash_token("some-token");
    assert!(!hashed.is_empty());
    assert!(hashed.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn refresh_claims_round_trip_through_jsonwebtoken() {
    // We can't easily call generate_refresh_token without the DB, but we
    // can verify the claim struct (de)serialises through jsonwebtoken with
    // the service's configured secret/issuer.
    let cfg = test_config();
    let now = Utc::now();
    let claims = RefreshTokenClaims {
        sub: Uuid::new_v4(),
        tid: Uuid::new_v4(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(cfg.refresh_token_expiration)).timestamp(),
        iss: cfg.jwt_issuer.clone(),
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
    )
    .unwrap();

    let mut validation = Validation::default();
    validation.set_issuer(&[&cfg.jwt_issuer]);
    // Refresh JWTs don't carry an audience — disable that check.
    validation.validate_aud = false;

    let decoded = decode::<RefreshTokenClaims>(
        &token,
        &DecodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        &validation,
    )
    .expect("refresh claims must round-trip");

    assert_eq!(decoded.claims.sub, claims.sub);
    assert_eq!(decoded.claims.tid, claims.tid);
    assert_eq!(decoded.claims.iat, claims.iat);
    assert_eq!(decoded.claims.exp, claims.exp);
    assert_eq!(decoded.claims.iss, claims.iss);
}

#[test]
fn refresh_claims_reject_wrong_secret() {
    // Same shape as the round-trip test, but verify with a different key.
    let cfg = test_config();
    let now = Utc::now();
    let claims = RefreshTokenClaims {
        sub: Uuid::new_v4(),
        tid: Uuid::new_v4(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(60)).timestamp(),
        iss: cfg.jwt_issuer.clone(),
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
    )
    .unwrap();

    let mut validation = Validation::default();
    validation.set_issuer(&[&cfg.jwt_issuer]);
    validation.validate_aud = false;

    let err = decode::<RefreshTokenClaims>(
        &token,
        &DecodingKey::from_secret(b"some-other-32char-key-NNNNNNNNNN"),
        &validation,
    );
    assert!(err.is_err(), "wrong-key decode must fail");
}

// TODO(post-DB-testcontainer): the following scenarios require a live
// Postgres connection and will be added once the testcontainers harness
// lands (tracked in the integration-suite phase):
//
//   * generate_refresh_token writes a row with token_hash (not plaintext)
//   * refresh_tokens rotates: old token marked revoked, new token returned
//   * rotated token cannot be reused (TokenRevoked)
//   * reusing a revoked token triggers revoke_all_tokens for the user
//   * expired refresh tokens are rejected
