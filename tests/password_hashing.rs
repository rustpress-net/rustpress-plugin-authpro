//! Integration tests for Argon2id password hashing.
//!
//! Covers round-trips, rejection of wrong passwords, malformed-hash handling,
//! non-determinism of repeated hashing, and that configured Argon2 params
//! are honoured in the produced PHC string.

mod common;

use common::{auth_service, auth_service_with, test_config};

#[test]
fn hash_then_verify_succeeds() {
    let auth = auth_service();
    let password = "CorrectHorseBattery9!";

    let hash = auth.hash_password(password).expect("hash should succeed");
    assert!(
        auth.verify_password(password, &hash)
            .expect("verify should not error"),
        "round-trip must verify"
    );
}

#[test]
fn verify_rejects_wrong_password() {
    let auth = auth_service();
    let hash = auth.hash_password("RightPassword1").unwrap();
    assert!(
        !auth.verify_password("WrongPassword1", &hash).unwrap(),
        "wrong password must not verify"
    );
}

#[test]
fn verify_rejects_empty_password_against_real_hash() {
    let auth = auth_service();
    let hash = auth.hash_password("RealPassword1").unwrap();
    assert!(!auth.verify_password("", &hash).unwrap());
}

#[test]
fn verify_handles_malformed_hash() {
    let auth = auth_service();
    // A blatantly malformed PHC string. Should map to an Internal error,
    // not panic.
    let res = auth.verify_password("anything", "not-a-valid-phc-hash");
    assert!(res.is_err(), "malformed PHC must error, got {:?}", res);
}

#[test]
fn verify_handles_truncated_phc_string() {
    let auth = auth_service();
    let full = auth.hash_password("Password1A").unwrap();
    let truncated = &full[..full.len() / 2];
    assert!(auth.verify_password("Password1A", truncated).is_err());
}

#[test]
fn hashes_are_non_deterministic() {
    let auth = auth_service();
    let password = "SamePassword1";
    let h1 = auth.hash_password(password).unwrap();
    let h2 = auth.hash_password(password).unwrap();
    assert_ne!(h1, h2, "Argon2id must use a fresh salt each call");
    // Both should still verify the same plaintext.
    assert!(auth.verify_password(password, &h1).unwrap());
    assert!(auth.verify_password(password, &h2).unwrap());
}

#[test]
fn hash_string_uses_argon2id() {
    let auth = auth_service();
    let hash = auth.hash_password("SomeStrong1").unwrap();
    // PHC string identifier for Argon2id, per RFC 9106 / argon2 crate.
    assert!(
        hash.starts_with("$argon2id$"),
        "expected Argon2id PHC prefix, got: {hash}"
    );
}

#[test]
fn hash_encodes_configured_params() {
    let cfg = test_config();
    let auth = auth_service_with(cfg.clone());
    let hash = auth.hash_password("ParamCheck1").unwrap();

    // PHC format: $argon2id$v=19$m=<memory>,t=<time>,p=<parallelism>$<salt>$<hash>
    let m_tag = format!("m={}", cfg.argon2_memory_cost);
    let t_tag = format!("t={}", cfg.argon2_time_cost);
    let p_tag = format!("p={}", cfg.argon2_parallelism);
    assert!(hash.contains(&m_tag), "missing memory param: {hash}");
    assert!(hash.contains(&t_tag), "missing time param: {hash}");
    assert!(hash.contains(&p_tag), "missing parallelism param: {hash}");
}

#[test]
fn validate_password_accepts_strong() {
    let auth = auth_service();
    assert!(auth.validate_password("Strongpass1").is_ok());
    assert!(auth.validate_password("Another9Pass").is_ok());
}

#[test]
fn validate_password_rejects_too_short() {
    let auth = auth_service();
    assert!(auth.validate_password("Ab1").is_err());
    assert!(auth.validate_password("Aa1aaaa").is_err()); // 7 chars
}

#[test]
fn validate_password_rejects_missing_uppercase() {
    let auth = auth_service();
    assert!(auth.validate_password("alllower1").is_err());
}

#[test]
fn validate_password_rejects_missing_lowercase() {
    let auth = auth_service();
    assert!(auth.validate_password("ALLUPPER1").is_err());
}

#[test]
fn validate_password_rejects_missing_digit() {
    let auth = auth_service();
    assert!(auth.validate_password("NoDigitsHere").is_err());
}

#[test]
fn verify_is_constant_time_ish_does_not_panic_on_garbage() {
    // We're not asserting timing properties here — we just want to make
    // sure feeding the verifier truly random input doesn't blow up.
    let auth = auth_service();
    let inputs = [
        "",
        " ",
        "$",
        "$argon2id",
        "$argon2id$$$$",
        "$argon2id$v=19$m=65536,t=3,p=4$invalid$invalid",
    ];
    for s in inputs {
        // Each call must terminate, either Ok(false) or Err(_).
        let _ = auth.verify_password("nope", s);
    }
}
