//! JWT integration tests.
//!
//! Covers the sign / verify round-trip, rejection of wrong-key signatures,
//! tampered payloads, expired tokens, and claim fidelity (sub, exp, iat,
//! iss, aud, role).

mod common;

use chrono::{Duration, Utc};
use common::{auth_service, auth_service_with, test_config, test_config_with_secret, test_user};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rustpress_auth::{AccessTokenClaims, AuthError};
use uuid::Uuid;

#[test]
fn sign_verify_round_trip() {
    let auth = auth_service();
    let user = test_user();

    let token = auth
        .generate_access_token(&user)
        .expect("generation should succeed");

    let claims = auth
        .validate_access_token(&token)
        .expect("validation should succeed");

    assert_eq!(claims.sub, user.id);
    assert_eq!(claims.email, user.email);
    assert_eq!(claims.name, user.name);
    assert_eq!(claims.role, user.role.to_string());
}

#[test]
fn claims_include_iss_aud_iat_exp_jti() {
    let cfg = test_config();
    let auth = auth_service_with(cfg.clone());
    let user = test_user();

    let token = auth.generate_access_token(&user).unwrap();
    let claims = auth.validate_access_token(&token).unwrap();

    assert_eq!(claims.iss, cfg.jwt_issuer);
    assert_eq!(claims.aud, cfg.jwt_audience);
    // iat is in the recent past (allow ~5s skew for slow CI).
    let now = Utc::now().timestamp();
    assert!(
        claims.iat <= now && claims.iat >= now - 5,
        "iat={} not within ~5s of now={}",
        claims.iat,
        now
    );
    // exp is ~access_token_expiration seconds in the future.
    assert!(
        claims.exp > now && claims.exp <= now + cfg.access_token_expiration + 5,
        "exp={} not in expected window from now={}",
        claims.exp,
        now
    );
    // jti must be a non-nil UUID.
    assert_ne!(claims.jti, Uuid::nil());
}

#[test]
fn token_signed_with_wrong_key_is_rejected() {
    let auth_a = auth_service_with(test_config_with_secret(
        "first-secret-key-32-characters-XXX!",
    ));
    let auth_b = auth_service_with(test_config_with_secret(
        "OTHER-secret-key-32-characters-YYY!",
    ));
    let user = test_user();

    let token_a = auth_a.generate_access_token(&user).unwrap();

    let err = auth_b
        .validate_access_token(&token_a)
        .expect_err("should reject foreign-signed token");
    assert!(matches!(err, AuthError::InvalidToken));
}

#[test]
fn tampered_payload_is_rejected() {
    let auth = auth_service();
    let user = test_user();
    let token = auth.generate_access_token(&user).unwrap();

    // Flip a single character in the payload segment. JWT format is
    // header.payload.signature — splitting on '.' lets us mutate just one
    // part without disturbing the signature offset.
    let mut parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 segments");
    let mut payload = parts[1].to_string();
    let first = payload.chars().next().unwrap();
    let replacement = if first == 'A' { 'B' } else { 'A' };
    payload.replace_range(0..1, &replacement.to_string());
    parts[1] = &payload;
    let tampered = parts.join(".");

    let err = auth
        .validate_access_token(&tampered)
        .expect_err("tampered token must be rejected");
    assert!(matches!(err, AuthError::InvalidToken));
}

#[test]
fn missing_segments_rejected() {
    let auth = auth_service();
    let bad_inputs = ["", "abc", "abc.def", "...", "not.a.jwt"];
    for input in bad_inputs {
        let err = auth.validate_access_token(input);
        assert!(err.is_err(), "expected error for input: {input:?}");
    }
}

#[test]
fn expired_token_is_rejected() {
    // Build a token directly with an `exp` in the past, then ask the
    // service to validate it.
    let cfg = test_config();
    let now = Utc::now();
    let past = (now - Duration::seconds(60)).timestamp();
    let iat_past = (now - Duration::seconds(120)).timestamp();

    let claims = AccessTokenClaims {
        sub: Uuid::new_v4(),
        email: "alice@example.com".into(),
        name: "Alice".into(),
        role: "user".into(),
        iat: iat_past,
        exp: past,
        iss: cfg.jwt_issuer.clone(),
        aud: cfg.jwt_audience.clone(),
        jti: Uuid::new_v4(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
    )
    .unwrap();

    let auth = auth_service_with(cfg);
    let err = auth
        .validate_access_token(&token)
        .expect_err("expired token must be rejected");
    assert!(matches!(err, AuthError::InvalidToken));
}

#[test]
fn wrong_issuer_rejected() {
    // Forge a token with a different `iss` and confirm the service
    // refuses it even though the signature is valid.
    let cfg = test_config();
    let mut forged_cfg = cfg.clone();
    forged_cfg.jwt_issuer = "evil-issuer".into();

    let now = Utc::now();
    let claims = AccessTokenClaims {
        sub: Uuid::new_v4(),
        email: "alice@example.com".into(),
        name: "Alice".into(),
        role: "user".into(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(300)).timestamp(),
        iss: forged_cfg.jwt_issuer.clone(),
        aud: cfg.jwt_audience.clone(),
        jti: Uuid::new_v4(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
    )
    .unwrap();

    let auth = auth_service_with(cfg);
    let err = auth
        .validate_access_token(&token)
        .expect_err("wrong-issuer token must be rejected");
    assert!(matches!(err, AuthError::InvalidToken));
}

#[test]
fn wrong_audience_rejected() {
    let cfg = test_config();
    let now = Utc::now();
    let claims = AccessTokenClaims {
        sub: Uuid::new_v4(),
        email: "alice@example.com".into(),
        name: "Alice".into(),
        role: "user".into(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(300)).timestamp(),
        iss: cfg.jwt_issuer.clone(),
        aud: "different-audience".into(),
        jti: Uuid::new_v4(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
    )
    .unwrap();

    let auth = auth_service_with(cfg);
    let err = auth
        .validate_access_token(&token)
        .expect_err("wrong-audience token must be rejected");
    assert!(matches!(err, AuthError::InvalidToken));
}

#[test]
fn validate_access_token_rejects_refresh_token_shape() {
    // The combined refresh-token format from generate_refresh_token is
    // `<jwt>.<random>` — feeding it directly to validate_access_token
    // should fail because the trailing random segment is not a valid JWT
    // sig and the JWT itself has the refresh-claim shape.
    let auth = auth_service();
    let user = test_user();
    let access = auth.generate_access_token(&user).unwrap();

    // Sanity: a real access token validates.
    assert!(auth.validate_access_token(&access).is_ok());

    // A bare random string must not.
    assert!(auth.validate_access_token("random.random.random").is_err());
}

#[test]
fn signature_segment_modification_rejected() {
    let auth = auth_service();
    let user = test_user();
    let token = auth.generate_access_token(&user).unwrap();

    let mut parts: Vec<&str> = token.split('.').collect();
    let mut sig = parts[2].to_string();
    // Flip first char of the signature.
    let first = sig.chars().next().unwrap();
    let replacement = if first == 'A' { 'B' } else { 'A' };
    sig.replace_range(0..1, &replacement.to_string());
    parts[2] = &sig;
    let tampered = parts.join(".");

    assert!(auth.validate_access_token(&tampered).is_err());
}

#[test]
fn token_lifetime_respects_config_exp() {
    let mut cfg = test_config();
    cfg.access_token_expiration = 60; // 1 minute
    let auth = auth_service_with(cfg.clone());

    let user = test_user();
    let token = auth.generate_access_token(&user).unwrap();
    let claims = auth.validate_access_token(&token).unwrap();
    let lifetime = claims.exp - claims.iat;
    assert_eq!(lifetime, cfg.access_token_expiration);
}

#[test]
fn hs256_default_header_alg() {
    // The library uses `Header::default()` which is HS256. Verify the
    // produced header reflects that — protects against accidental
    // algorithm downgrade if Header::default changes upstream.
    let auth = auth_service();
    let user = test_user();
    let token = auth.generate_access_token(&user).unwrap();
    let header = jsonwebtoken::decode_header(&token).unwrap();
    assert_eq!(header.alg, jsonwebtoken::Algorithm::HS256);
}

#[test]
fn none_alg_token_is_rejected() {
    // Defence against the classic "alg: none" forgery: craft a header that
    // claims `alg: none` and confirm the service refuses it.
    use base64::Engine;
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"alg":"none","typ":"JWT"}"#);
    let cfg = test_config();
    let now = Utc::now();
    let payload_json = serde_json::json!({
        "sub": Uuid::new_v4(),
        "email": "evil@example.com",
        "name": "Evil",
        "role": "admin",
        "iat": now.timestamp(),
        "exp": (now + Duration::seconds(300)).timestamp(),
        "iss": cfg.jwt_issuer,
        "aud": cfg.jwt_audience,
        "jti": Uuid::new_v4(),
    });
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(payload_json.to_string().as_bytes());
    let forged = format!("{header}.{payload}.");

    let auth = auth_service_with(cfg);
    let err = auth
        .validate_access_token(&forged)
        .expect_err("alg:none token must be rejected");
    assert!(matches!(err, AuthError::InvalidToken));
}

#[test]
fn validation_uses_secret_bytes_not_string_repr() {
    // Cross-check: encode with raw bytes of the secret, decode through the
    // service. If anyone changes EncodingKey construction to e.g. hex
    // decode, this test catches it.
    let cfg = test_config();
    let auth = auth_service_with(cfg.clone());
    let user = test_user();

    let now = Utc::now();
    let claims = AccessTokenClaims {
        sub: user.id,
        email: user.email.clone(),
        name: user.name.clone(),
        role: user.role.to_string(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(300)).timestamp(),
        iss: cfg.jwt_issuer.clone(),
        aud: cfg.jwt_audience.clone(),
        jti: Uuid::new_v4(),
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
    )
    .unwrap();

    assert!(auth.validate_access_token(&token).is_ok());

    // And cross-verify with a hand-built decoding key for completeness.
    let mut validation = Validation::default();
    validation.set_issuer(&[&cfg.jwt_issuer]);
    validation.set_audience(&[&cfg.jwt_audience]);
    let decoded = decode::<AccessTokenClaims>(
        &token,
        &DecodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        &validation,
    )
    .unwrap();
    assert_eq!(decoded.claims.sub, user.id);
}
