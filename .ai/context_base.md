# rustpress-plugin-authpro — AI Context

> **Purpose**: Orient an AI agent to this repo without reading the whole tree. Pair with the RustPress organisation context in `rustpress-core-base/.ai/context/CONTEXT_BASE.md`.

## Project

`rustpress-plugin-authpro` is RustPress's **foundational authentication plugin**. Despite the "plugin" label, it isn't optional — most RustPress deployments depend on it for JWT access + refresh tokens, Argon2id password hashing, registration/login flows, password reset, email verification, and account lockout. It is compiled directly into the RustPress binary as a `cdylib + rlib` and creates its own PostgreSQL tables on activation via sqlx migrations.

The crate name on Cargo.toml is `rustpress-auth` (not `rustpress-authpro`); the "pro" in the repo name is historical and the crate identity will be `rustpress-auth` on crates.io.

## Tech stack

- **Language**: Rust 2021, edition 2021, MSRV inherited from core
- **Crate**: `rustpress-auth` v1.0.0, `MIT OR Apache-2.0`, `crate-type = ["cdylib", "rlib"]`
- **Web**: `axum 0.7` + `tower` + `tower-http` (cors)
- **Async**: `tokio` (sync, time, rt-multi-thread)
- **DB**: `sqlx 0.7` with `postgres`, `uuid`, `chrono`, `migrate` features (compile-time-checked queries)
- **Crypto**: `jsonwebtoken 9` (JWT), `argon2 0.5` (password hashing), `rand 0.8`
- **Validation**: `validator 0.18` (derive macros)
- **Errors**: `thiserror`, **tracing** for logs

## Directory layout

```
rustpress-plugin-authpro/
├── Cargo.toml          # crate = rustpress-auth, v1.0.0, MIT OR Apache-2.0
├── README.md           # status table + integration guide
├── LICENSE-MIT
├── LICENSE-APACHE
└── src/
    ├── lib.rs          # Plugin trait impl, create_routes(), public API
    ├── config.rs       # JWT secret validation (≥32 chars), Argon2 params
    ├── error.rs        # AuthError variants
    ├── extractors.rs   # Axum extractors (Bearer, claims, current user)
    ├── handlers.rs     # /register, /login, /refresh, /reset-password, etc.
    ├── middleware.rs   # auth middleware, token validation
    ├── models.rs       # User, Session, RefreshToken, etc.
    └── service.rs      # password hashing, JWT issuance, lockout logic
```

Migrations are embedded in the crate (sqlx `migrate!` macro) — no separate `migrations/` dir.

## Public API / what this repo exposes

- Implements the RustPress `Plugin` trait (async `activate`, `deactivate`, `state()`)
- Exports `create_routes() -> axum::Router` for mounting auth endpoints
- Endpoints (under whatever prefix the host mounts): `POST /register`, `POST /login`, `POST /refresh`, `POST /logout`, `POST /password-reset/request`, `POST /password-reset/confirm`, `POST /email/verify`, plus current-user fetch
- Axum extractors for downstream plugins/handlers to require auth
- Config struct read from env (`JWT_SECRET`, `DATABASE_URL`, plus Argon2 tunables)

## How to build / test

```bash
cargo build --release             # produces cdylib + rlib
cargo test                        # currently only test_plugin_info + test_plugin_initial_state
cargo clippy -- -D warnings
cargo fmt --check

# Required env to run:
export DATABASE_URL=postgres://...
export JWT_SECRET=$(openssl rand -hex 32)  # MUST be ≥32 chars
```

CI: `rustpress-net/rustpress-core-devops/actions/ci-rust@main`.

## Cross-repo dependencies

- **Depends on**: `rustpress-core-base` (the `Plugin` trait, `RustPressContext`, server runtime). Today the dep is via the workspace path when built in-tree.
- **Depended on by**: most other RustPress plugins that gate behaviour by user identity (e.g. `rustpress-plugin-rustcommerce` orders, `rustpress-plugin-visual-queue` admin pages — visual-queue declares `rustpress-auth >=1.0.0` in its `plugin.toml`).

## Conventions

- **License**: `MIT OR Apache-2.0` (both LICENSE files at repo root, declared in Cargo.toml)
- **Commits**: Conventional Commits
- **DB queries**: sqlx compile-time checked — never `format!` SQL strings
- **Secrets**: JWT secret read from env only; ≥32-char length validated at startup (`config.rs:128–132`)
- **Token storage**: refresh tokens are **hashed at rest**, never stored plaintext

## Status

- Release readiness: **🔴 NOT READY at v1.0** → ship as `0.9.0-beta` (see `AUDIT-plugins.md` and master `AUDIT.md`)
- Core crypto (Argon2id, sqlx-checked queries, refresh-token rotation) is sound; gaps are in testing and rate-limiting.
- LICENSE files: ✅ added (recent commit `94c2970 chore: add LICENSE files, README, and dual-license metadata`).
- README: ✅ added (recent commit, status table + integration guide).
- Phase: alpha hardening; promotion to 1.0 conditional on test coverage + rate limiting landing.

## Known issues / TODOs

From `AUDIT-plugins.md` (section 1) and master audit:

- **P0 CRITICAL**: Only 2 trivial unit tests (`test_plugin_info`, `test_plugin_initial_state`). For a security plugin this is unacceptable. Need integration tests for: Argon2 password hashing (verify + rehash), JWT signing/verification, refresh-token rotation, account lockout (`failed_login_attempts`, `locked_until`), email-verification flow, password-reset flow, sqlx migrations on a fresh DB. Target: 15+ cases minimum.
- **P0 CRITICAL**: No rate limiting on `/login` — brute-force exposure. Add `tower-governor` (or equivalent) per-IP and per-account, configurable via env.
- **P1**: Password validation requires upper + lower + digit but **no special-character requirement**. Add `require_special_chars` knob (default true).
- **P1**: Expand integration tests to cover concurrent refresh-token rotation (race against revocation).
- **P1**: Document env var matrix in README (every config knob).

## When working in this repo

- This is a **security-critical** plugin. No PR lands without tests for the changed surface. Reviewers should reject "fixed" + "no tests" PRs by default.
- Never log password material, JWT contents, or refresh-token plaintext. Use `tracing` with redaction.
- Never store secrets in `Cargo.toml`, `*.toml` configs, or test fixtures. Use `.env.example` placeholders only.
- Argon2 params (memory, iterations, parallelism) are tunable but defaults should match OWASP recommendations. Don't loosen defaults without a written justification.
- DB migrations: forward-only. Once shipped, do not rewrite — add a new migration that fixes the data.
- Coordinate breaking changes with `rustpress-plugin-visual-queue` and any other plugin that lists `rustpress-auth >=1.0.0`.
