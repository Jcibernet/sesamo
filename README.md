# Sésamo

A single-binary authentication server. Opaque Postgres-backed sessions,
OAuth (Google / GitHub / Apple), email flows (magic-link, password reset,
verification), an embedded themeable login UI, and a fast
service-to-service introspection API.

No JWTs to verify, no JWKS to fetch, no client SDK to install. Your
backend makes one HTTP call per request to check a session — **p50 under
1ms, p99 ~4ms** including the Postgres lookup (see [Load test](#load-test)).

```
┌──────────┐   sid cookie    ┌──────────┐   POST /v1/introspect   ┌──────────┐
│ Browser  │ ───────────────▶│ Your app │ ───────────────────────▶│  Sésamo  │
└──────────┘                 └──────────┘   { "active": true,      └────┬─────┘
                                              "user_id": "...",         │
                                              "email": "..." }     ┌────▼─────┐
                                                                   │ Postgres │
                                                                   └──────────┘
```

## Why opaque sessions instead of JWTs

| | JWT / JWKS (Auth0-style) | Sésamo opaque sessions |
|---|---|---|
| Per-request cost | 10–50ms (JWKS fetch + RS256 verify) | <1ms (one indexed lookup) |
| Instant revocation | No (token valid until expiry) | Yes (delete the row) |
| Client SDK required | Usually | No — a `fetch` is enough |
| Secret material in client | Public keys, token parsing | None |

## Quick start (clone to login in < 2 min)

```bash
# 1. Start the isolated dev Postgres (port 7432)
docker compose up -d postgres
cp .env.example .env            # defaults work for local dev

# 2. Build the single static binary
go build -o sesamo ./cmd/sesamo

# 3. Migrate (idempotent) and serve (serve also auto-migrates)
export $(grep -v '^#' .env | xargs)
./sesamo migrate
./sesamo serve
```

Open <http://localhost:7777/login>. With `SESAMO_EMAIL_PROVIDER=log` the
magic-link / reset / verification links are printed to stdout, so you can
complete every flow locally with no email provider configured.

```bash
# Create an account and log in (headless JSON mode)
curl -s -XPOST -d 'email=me@example.com&password=supersecret1' \
  http://localhost:7777/signup
curl -s -XPOST -H 'Accept: application/json' \
  -d 'email=me@example.com&password=supersecret1' \
  http://localhost:7777/login -c cookies.txt

# Introspect the session (what your backend does on every request)
SID=$(grep sid cookies.txt | awk '{print $7}')
curl -s -XPOST -H "Authorization: Bearer $SESAMO_SERVICE_TOKEN" \
  -d "token=$SID" http://localhost:7777/v1/introspect
# => {"active":true,"user_id":"019...","email":"me@example.com",...}
```

## Endpoints

### End-user (browser)
| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/login` | Login page (HTML, or JSON with `Accept: application/json`) |
| `POST` | `/login` | Email + password login |
| `POST` | `/signup` | Create account, send verification email |
| `POST` | `/logout` | Revoke session (POST-only, anti-CSRF) |
| `GET`  | `/auth/{provider}` | Start OAuth (`google` / `github` / `apple`) |
| `GET`  | `/auth/{provider}/callback` | OAuth callback (state + PKCE checked) |
| `POST` | `/reset` · `/reset/confirm` | Password reset request / confirm |
| `GET`  | `/verify` | Confirm email verification token |
| `POST` | `/magiclink` · `GET /magiclink/confirm` | Passwordless login |
| `GET`  | `/ui/theme.css` | Embedded base stylesheet (design tokens) |

### Service-to-service (require `Authorization: Bearer $SESAMO_SERVICE_TOKEN`)
| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/introspect` | Validate a session token → identity |
| `POST` | `/v1/sessions/revoke` | Force-logout a session by token |

### Admin (require `Authorization: Bearer $SESAMO_ADMIN_API_KEY`)
| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/v1/admin/users/{id}` | Fetch a user |
| `POST` | `/v1/admin/users/{id}/revoke-sessions` | Kill all of a user's sessions |

### Ops
| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | Readiness (pings Postgres) |
| `GET` | `/metrics` | Prometheus exposition |

## Reference clients

Minimal, SDK-free integrations live in [`examples/`](./examples):

- [`nextjs-middleware.ts`](./examples/nextjs-middleware.ts) — Next.js App
  Router middleware that gates routes via `/v1/introspect`.
- [`fastapi_dependency.py`](./examples/fastapi_dependency.py) — a FastAPI
  `Depends(current_user)` dependency.

Both are ~30 lines and use nothing but the standard HTTP client.

## Configuration

All configuration is environment variables — no config file, no config
library. See [`.env.example`](./.env.example) for the full annotated list.

| Variable | Default | Notes |
|---|---|---|
| `SESAMO_DATABASE_URL` | _(required)_ | Postgres DSN |
| `SESAMO_BASE_URL` | `http://localhost:7777` | Public URL (cookies, OAuth redirects) |
| `SESAMO_LISTEN_ADDR` | `:7777` | HTTP listen address |
| `SESAMO_COOKIE_SECURE` | `false` | `true` in production (enables HSTS) |
| `SESAMO_COOKIE_DOMAIN` | _(empty)_ | Set when Sésamo and the consuming app live on sibling subdomains and you want the `sid` cookie sent to both (e.g. `.example.com`). Leave empty for single-origin deployments (path-routed under one host) or for local dev. |
| `SESAMO_SESSION_LIFETIME_DAYS` | `30` | Absolute session lifetime |
| `SESAMO_ROLLING_RENEWAL_THRESHOLD_MINUTES` | `15` | Rolling renewal cadence |
| `SESAMO_SERVICE_TOKEN` | _(required for introspect)_ | S2S bearer token |
| `SESAMO_ADMIN_API_KEY` | _(required for admin)_ | Admin bearer token |
| `SESAMO_{GOOGLE,GITHUB,APPLE}_*` | — | OAuth provider credentials |
| `SESAMO_EMAIL_PROVIDER` | `log` | `log` / `resend` / `postmark` |
| `SESAMO_THEME_CSS_URL` | — | Override stylesheet (see Theming) |

## Theming

The embedded UI is styled entirely with CSS custom properties (design
tokens). To rebrand, point `SESAMO_THEME_CSS_URL` at a stylesheet that
overrides the tokens — it loads after the base sheet, so your `:root`
wins. No template forking, no rebuild.

```css
/* my-theme.css */
:root {
  --sesamo-primary: #e2007a;
  --sesamo-bg: #ffffff;
  --sesamo-surface: #f7f7f9;
  --sesamo-text: #14161a;
  --sesamo-radius: 4px;
}
```

For fully custom UIs, use headless mode: send `Accept: application/json`
(or `?mode=json`) to any end-user endpoint and render your own screens.

## Migrating from Auth0

Export your users (Auth0 → User Migrations / bulk export extension) as
NDJSON, then:

```bash
./sesamo admin import auth0-export.ndjson
```

Bcrypt password hashes are stored **verbatim**, so every user's existing
password keeps working immediately — no reset emails, no big-bang cutover.
On each user's first successful login the hash is transparently re-hashed
from bcrypt to Argon2id (lazy migration). Re-running the import is
idempotent (existing emails are skipped).

## Security model

- **Tokens**: 256-bit random session tokens; only `SHA-256(token)` is
  stored. Raw tokens never touch the database.
- **Passwords**: Argon2id (RFC 9106, 64 MiB). Imported bcrypt verified and
  upgraded on login. Constant-time comparisons; dummy-hash work on missing
  users to defeat timing-based enumeration.
- **Anti-enumeration**: login, signup, reset, and magic-link return
  identical responses whether or not the account exists.
- **CSRF**: OAuth uses `state` + PKCE S256; logout is POST-only.
- **Rate limiting**: token-bucket per-IP **and** per-identity on every
  credential endpoint (Postgres-backed, holds across instances).
- **Session hygiene**: password reset revokes all sessions; rolling
  renewal extends active sessions without unbounded lifetime.
- **Headers**: strict CSP, `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy`, and HSTS when `SESAMO_COOKIE_SECURE=true`.

16 threat-model integration tests cover these (`go test ./internal/http/
-run Threat`).

## Load test

The introspect hot path is the number that matters. The included load
test drives 3,200 concurrent introspections over loopback HTTP against a
real Postgres session:

```
$ go test ./internal/http -run TestLoadIntrospect -v
introspect load: n=3200 rps=16051 p50=794µs p95=1.708ms p99=4.011ms
```

SLO: **p50 < 5ms, p99 < 20ms** — met with large margin.

## Testing

```bash
# Unit tests run without a database.
go test ./...

# DB-backed + integration + load tests need a Postgres DSN:
export SESAMO_TEST_DB='postgres://sesamo:sesamo@localhost:7432/sesamo_dev?sslmode=disable'
go test ./...
```

Tests that need a database skip cleanly when `SESAMO_TEST_DB` is unset.

## Build & deploy

```bash
CGO_ENABLED=0 go build -ldflags='-s -w' -o sesamo ./cmd/sesamo
```

Produces a single static binary (~16 MB). It needs only a reachable
Postgres. `./sesamo serve` runs migrations on boot, so a rolling deploy is
safe (migrations take a Postgres advisory lock to serialize concurrent
starts). Health: `/healthz` (liveness), `/readyz` (readiness).

## License

[FSL-1.1-Apache-2.0](./LICENSE) — Functional Source License, converting to
Apache 2.0 two years after each release.
