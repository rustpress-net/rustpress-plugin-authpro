# rustpress-plugin-authpro

Authentication plugin for [RustPress](https://github.com/rustpress-net/rustpress-core-base): JWT access + refresh tokens, Argon2id password hashing, registration/login flows, password reset, email verification, and account lockout protection.

> **Status:** 0.9.0-beta. Crypto core (Argon2id, sqlx-checked queries, refresh-token rotation) is solid; per-IP rate limiting on the credential-bearing endpoints landed in this release and a 45+ case integration test suite covers password hashing, JWT, refresh-token hashing, and the rate limiter. Full DB-backed integration tests (lockout state machine, refresh-rotation end-to-end) ship in 1.0 once a Postgres testcontainer harness is in place.

## What it does

| Feature | Status |
|---|---|
| Argon2id password hashing (params configurable) | ✅ |
| JWT signing (access + refresh, ≥32-char secret enforced) | ✅ |
| Refresh-token rotation (hashed at rest) | ✅ |
| Account lockout (`failed_login_attempts`, `locked_until`) | ✅ |
| Email verification flow | ✅ |
| Password reset flow | ✅ |
| Rate limiting on `/auth/login`, `/auth/register`, `/auth/refresh`, `/auth/forgot-password`, `/auth/reset-password` | ✅ |
| Special-char password rule | 🚧 landing in 1.0 |

## Integration

The plugin implements the RustPress `Plugin` trait and is compiled as `cdylib + rlib` into the RustPress binary. It creates its tables on activation (sqlx migrations) and exports `create_routes()` to mount Axum endpoints.

Required environment:

```
DATABASE_URL=postgres://...
JWT_SECRET=<at least 32 chars>
```

If `JWT_SECRET` is shorter than 32 chars or absent, activation fails fast — by design.

### Rate-limit knobs

The auth-credentials endpoints are wrapped in a `tower_governor` per-IP token-bucket limiter. All knobs are environment-driven:

| Env var | Default | Effect |
|---|---|---|
| `AUTHPRO_LOGIN_RATE_PER_MIN` | `10` | Sustained requests per minute, per client IP |
| `AUTHPRO_LOGIN_BURST` | `5` | Burst pool above the sustained rate |
| `AUTHPRO_RATE_LIMIT_DISABLED` | unset | Set to `true` to disable (e.g. when fronting with nginx/Cloudflare) |

When a client exceeds the budget the request short-circuits with HTTP 429 and a `Retry-After` header. The limiter uses `SmartIpKeyExtractor`, which respects `X-Forwarded-For` / `X-Real-IP` so proxied deployments still get per-client buckets.

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

- Credential-bearing endpoints (`/auth/login`, `/auth/register`, `/auth/refresh`, `/auth/forgot-password`, `/auth/reset-password`) carry a per-IP rate limit out of the box — tune via the `AUTHPRO_LOGIN_*` env vars above. For high-traffic deployments you can still front with an additional reverse-proxy limiter (nginx `limit_req`, Cloudflare) for defence-in-depth.
- Refresh tokens are stored hashed; access tokens are never persisted.
- All SQL goes through sqlx compile-time-checked queries.

## License

Dual-licensed under MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.
