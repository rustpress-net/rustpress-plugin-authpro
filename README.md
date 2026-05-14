# rustpress-plugin-authpro

Authentication plugin for [RustPress](https://github.com/rustpress-net/rustpress-core-base): JWT access + refresh tokens, Argon2id password hashing, registration/login flows, password reset, email verification, and account lockout protection.

> **Status:** pre-1.0. Crypto core (Argon2id, sqlx-checked queries, refresh-token rotation) is solid, but `/login` rate limiting and a broader integration-test suite are landing before GA. Use with care in production until 1.0.

## What it does

| Feature | Status |
|---|---|
| Argon2id password hashing (params configurable) | ✅ |
| JWT signing (access + refresh, ≥32-char secret enforced) | ✅ |
| Refresh-token rotation (hashed at rest) | ✅ |
| Account lockout (`failed_login_attempts`, `locked_until`) | ✅ |
| Email verification flow | ✅ |
| Password reset flow | ✅ |
| Rate limiting on `/login` | 🚧 landing in 1.0 |
| Special-char password rule | 🚧 landing in 1.0 |

## Integration

The plugin implements the RustPress `Plugin` trait and is compiled as `cdylib + rlib` into the RustPress binary. It creates its tables on activation (sqlx migrations) and exports `create_routes()` to mount Axum endpoints.

Required environment:

```
DATABASE_URL=postgres://...
JWT_SECRET=<at least 32 chars>
```

If `JWT_SECRET` is shorter than 32 chars or absent, activation fails fast — by design.

## Endpoints (default mount)

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/register` | Create user, send verification email |
| POST | `/auth/login` | Issue access + refresh tokens |
| POST | `/auth/refresh` | Rotate refresh, issue new access |
| POST | `/auth/logout` | Revoke active session |
| POST | `/auth/verify-email` | Confirm email token |
| POST | `/auth/forgot-password` | Issue reset token |
| POST | `/auth/reset-password` | Apply reset token |

## Configuration

Full config schema is documented in `src/config.rs`. Knobs include Argon2 memory/time/parallelism, JWT TTLs, lockout threshold and duration, and email-template overrides.

## Security notes

- Pre-1.0: no rate limiting on auth endpoints — front with a reverse-proxy limiter (nginx `limit_req`, Cloudflare, tower-governor) in production.
- Refresh tokens are stored hashed; access tokens are never persisted.
- All SQL goes through sqlx compile-time-checked queries.

## License

Dual-licensed under MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.
