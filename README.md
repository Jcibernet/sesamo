<p align="center">
  <a href="https://github.com/Jcibernet/sesamo/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Jcibernet/sesamo/ci.yml?style=for-the-badge&labelColor=0d1117&color=56d364&label=CI" alt="ci"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/LICENSE-FSL--1.1-3fb950?style=for-the-badge&labelColor=0d1117" alt="license"></a>
  <img src="https://img.shields.io/badge/GO-%3E%3D1.26-2ea043?style=for-the-badge&labelColor=0d1117" alt="go">
</p>

# Sésamo

A single-binary authentication server with opaque Postgres-backed sessions,
OAuth (Google / GitHub / Apple), email flows (magic link, password reset and
verification), an embedded themeable login UI, and a service-to-service
introspection API.

No JWT verification, JWKS fetching or client SDK is required. The consuming
backend sends the opaque session token to Sésamo for validation, keeping
session state and revocation centralized.

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

Opaque sessions keep validation and revocation in one place. A consuming
backend calls `/v1/introspect` rather than parsing tokens or managing signing
keys, and deleting a session invalidates it immediately. The tradeoff is that
request authentication depends on Sésamo and Postgres being reachable, so
deployments should account for that dependency in their availability design.

## Quick start

```bash
# 1. Start the isolated dev Postgres (port 7432)
docker compose up -d postgres
cp .env.example .env            # defaults work for local dev

# 2. Build the server
go build -o sesamo ./cmd/sesamo

# 3. Migrate (idempotent) and serve (serve also auto-migrates)
set -a; . ./.env; set +a
./sesamo migrate
./sesamo serve
```

Open <http://localhost:7777/login>. With `SESAMO_EMAIL_PROVIDER=log`, magic
link, reset and verification URLs are printed to stdout, so email-based flows
work locally without configuring an email provider.

```bash
# In another terminal, load the local configuration, then create an account
# and log in. Each POST uses the CSRF cookie and token returned together by
# GET /login.
set -a; . ./.env; set +a
curl -sS -c cookies.txt -H 'Accept: application/json' \
  'http://localhost:7777/login?mode=json' > login.json
CSRF=$(python3 -c 'import json; print(json.load(open("login.json"))["csrf_token"])')
curl -sS -c cookies.txt -b cookies.txt -H 'Accept: application/json' \
  --data-urlencode 'email=me@example.com' \
  --data-urlencode 'password=supersecret1' \
  --data-urlencode "csrf_token=$CSRF" \
  http://localhost:7777/signup

curl -sS -c cookies.txt -b cookies.txt -H 'Accept: application/json' \
  'http://localhost:7777/login?mode=json' > login.json
CSRF=$(python3 -c 'import json; print(json.load(open("login.json"))["csrf_token"])')
curl -sS -c cookies.txt -b cookies.txt -H 'Accept: application/json' \
  --data-urlencode 'email=me@example.com' \
  --data-urlencode 'password=supersecret1' \
  --data-urlencode "csrf_token=$CSRF" \
  http://localhost:7777/login

# Introspect the session (what your backend does on every request)
SID=$(awk '$6 == "sid" { print $7 }' cookies.txt)
curl -sS -XPOST -H "Authorization: Bearer $SESAMO_SERVICE_TOKEN" \
  --data-urlencode "token=$SID" http://localhost:7777/v1/introspect
# => {"active":true,"user_id":"019...","email":"me@example.com",...}
rm login.json cookies.txt
```

## Endpoints

### End-user (browser)
| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/login` | Login page; JSON mode returns methods, branding and a short-lived `csrf_token` while setting its matching HttpOnly cookie. `?redirect_to=` captures the post-login destination: an internal path or an origin allowlisted in `SESAMO_REDIRECT_ORIGINS` |
| `POST` | `/login` | Email + password login; requires the CSRF pair and returns to the captured/`redirect_to` destination |
| `POST` | `/signup` | Create account, send verification email; requires CSRF (`SESAMO_SIGNUP=disabled` refuses with a stable 403 after CSRF validation) |
| `POST` | `/logout` | Revoke session; requires CSRF. Optional `redirect_to` form field uses the same allowlist |
| `GET`  | `/auth/{provider}` | Start OAuth (`google` / `github` / `apple`); `?redirect_to=` captured like `/login` |
| `GET`  | `/auth/{provider}/callback` | OAuth callback (state + PKCE checked) |
| `POST` | `/reset` · `/reset/confirm` | Password reset request / confirm; require CSRF |
| `GET`  | `/verify` | Confirm email verification token |
| `POST` | `/magiclink` · `GET /magiclink/confirm` | Passwordless login. Request requires CSRF; a captured `redirect_to` survives only when confirmation happens in the same browser within 15 minutes |
| `GET`  | `/ui/theme.css` | Embedded base stylesheet (design tokens) |

### Service-to-service (require `Authorization: Bearer $SESAMO_SERVICE_TOKEN`)
| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/introspect` | Validate a session token → identity |
| `POST` | `/v1/sessions/revoke` | Force-logout a session by token |

### Admin (require `Authorization: Bearer $SESAMO_ADMIN_API_KEY`)
| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/v1/admin/users/{id}` | Fetch a user, including its `disabled` kill-switch state |
| `POST` | `/v1/admin/users/{id}/revoke-sessions` | Kill all of a user's sessions |
| `POST` | `/v1/admin/users/{id}/disable` | Set form field `disabled=true|false`; disabling revokes all sessions atomically |

### Ops
| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | Readiness (pings Postgres) |
| `GET` | `/metrics` | Prometheus exposition |

### Discovery (public, read-only, no secrets)
| Method | Path | Purpose |
|---|---|---|
| `GET` | `/.well-known/sesamo` | Machine-readable deployment descriptor: project identity, endpoint map, enabled capabilities, session contract, stable error codes. Derived from the same constants the handlers use — `sesamo describe` prints the same JSON offline |
| `GET` | `/openapi.json` | OpenAPI 3.1 contract for the HTTP surface |
| `GET` | `/llms.txt` | Short integration guide for AI agents |

### Webhooks (signature-verified)
| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/webhooks/resend` | Resend delivery events (delivered / bounced / complained / failed) for queued email; svix-signed with `SESAMO_RESEND_WEBHOOK_SECRET`, replay-deduplicated. 503 when the secret is unset |

## Reference clients

Minimal, SDK-free integrations live in [`examples/`](./examples):

- [`nextjs-middleware.ts`](./examples/nextjs-middleware.ts) — Next.js App
  Router middleware that gates routes via `/v1/introspect`.
- [`fastapi_dependency.py`](./examples/fastapi_dependency.py) — a FastAPI
  `Depends(current_user)` dependency.

Both use only their language's standard HTTP client.

### Identity boundary

Sésamo authenticates an identity; the consuming application owns authorization
and its domain data. Treat introspection's `user_id` as the stable UUIDv7
identity key and keep any local user mapping and ownership scope in the
consuming application's database. Do not key that mapping by `email`, which is
mutable. `metadata` is returned by introspection but has no HTTP write API.


## Configuration

All configuration is environment variables — no config file, no config
library. See [`.env.example`](./.env.example) for the full annotated list.

| Variable | Default | Notes |
|---|---|---|
| `SESAMO_ENV` | `development` | `development` keeps local defaults. `production` fails boot unless HTTPS, secure cookie, two distinct 32+ character secrets, real email credentials, explicit encrypted DB SSL mode, valid durations, and complete-or-empty OAuth blocks are present |
| `SESAMO_PROJECT_SLUG` | `sesamo` | Deployment identity: one Sésamo deployment serves one consuming project (see `docs/adr/0001`). Lowercase slug, surfaced by the descriptor and `sesamo describe`; never an authorization boundary |
| `SESAMO_PROJECT_DISPLAY_NAME` | `Sésamo` | Human-facing project name in the descriptor |
| `SESAMO_DATABASE_URL` | _(required)_ | Postgres DSN. Pool tuning goes in the DSN via pgx params — e.g. `?pool_max_conns=10&pool_min_conns=2`. Defaults: max conns = `max(4, NumCPU)`, conn lifetime 1 h, idle timeout 30 min. Production requires explicit `sslmode=require`, `verify-ca`, or `verify-full` |
| `SESAMO_BASE_URL` | `http://localhost:7777` | Public URL (cookies, OAuth redirects); production requires `https://` |
| `SESAMO_LISTEN_ADDR` | `:7777` | HTTP listen address |
| `SESAMO_COOKIE_SECURE` | `false` | `true` in production (enables HSTS; mandatory under `SESAMO_ENV=production`) |
| `SESAMO_COOKIE_DOMAIN` | _(empty)_ | Set when Sésamo and the consuming app live on sibling subdomains and you want the `sid` cookie sent to both (e.g. `.example.com`). This widens the trust boundary to every matching subdomain. Leave empty for path-routed/single-host deployments |
| `SESAMO_SESSION_LIFETIME_DAYS` | `30` | Idle-renewal window |
| `SESAMO_SESSION_MAX_LIFETIME_DAYS` | `90` | Absolute cap from session creation. Rolling renewal cannot extend past it; must be >= `SESAMO_SESSION_LIFETIME_DAYS` |
| `SESAMO_ROLLING_RENEWAL_THRESHOLD_MINUTES` | `15` | Rolling renewal cadence |
| `SESAMO_SERVICE_TOKEN` | _(required for introspect)_ | S2S bearer token; required and 32+ characters in production |
| `SESAMO_ADMIN_API_KEY` | _(required for admin)_ | Admin bearer token; required, 32+ characters, and different from service token in production |
| `SESAMO_TRUST_PROXY` | `false` | Honor `X-Forwarded-For` for client IP (rate-limit keying, logs, audit). Enable ONLY behind a proxy that overwrites the header |
| `SESAMO_AUDIT_STRICT` | `false` | In strict mode, action and audit evidence share one transaction: either both commit or neither does. Default: best-effort — availability wins |
| `SESAMO_AUDIT_RETENTION_DAYS` | `0` (keep forever) | When > 0, the hourly maintenance job deletes `audit_log` rows older than N days. Unset = unbounded growth; pick a retention before production |
| `SESAMO_REDIRECT_ORIGINS` | _(empty)_ | Comma-separated exact-match allowlist of external origins `redirect_to` may target (e.g. `https://app.example.com`). Bare origins only. Empty keeps redirects internal-only |
| `SESAMO_SIGNUP` | `public` | `public` or `disabled`. Disabled: `/signup` refuses new accounts and OAuth refuses identities that would create one; existing users keep logging in |
| `SESAMO_{GOOGLE,GITHUB,APPLE}_*` | — | OAuth provider credentials; production accepts each provider block only complete or empty |
| `SESAMO_EMAIL_PROVIDER` | `log` | `log` / `resend` / `postmark`; production requires `resend` or `postmark` plus API key and deliverable From address |
| `SESAMO_EMAIL_OUTBOX_KEYS` | _(dev: ephemeral)_ | AES-256-GCM keyring encrypting queued email payloads (they embed one-time bearer links): `id:base64-32-bytes[,old:key]`. First key encrypts, the rest decrypt (overlapped rotation). Required in production |
| `SESAMO_RESEND_WEBHOOK_SECRET` | _(empty: webhook off)_ | Svix signing secret for `POST /v1/webhooks/resend` delivery events |
| `SESAMO_THEME_CSS_URL` | — | Full override stylesheet (see Theming) |
| `SESAMO_BRAND_LOGO_URL` | — | Logo atop the login card (SVG recommended; host is added to CSP `img-src`) |
| `SESAMO_BRAND_PRIMARY_COLOR` | — | Primary/button/link color, any CSS color |
| `SESAMO_BRAND_PAGE_BG` | — | Page background: color or `linear-gradient(...)` |
| `SESAMO_BRAND_FONT_URL` | — | WOFF/WOFF2 font file (host is added to CSP `font-src`) |

## Theming

Three tiers, mirroring Auth0's customization ladder (no-code branding →
theme tokens → fully custom UI). They layer: base tokens < brand env
vars < your stylesheet.

**Tier 1 — no-code branding (env vars only).** Logo, primary color,
page background, and font, without writing a line of CSS:

```bash
SESAMO_BRAND_LOGO_URL=https://cdn.example.com/logo.svg
SESAMO_BRAND_PRIMARY_COLOR="#e11d48"
SESAMO_BRAND_PAGE_BG="linear-gradient(135deg, #1e1b4b, #312e81)"
SESAMO_BRAND_FONT_URL=https://cdn.example.com/brand.woff2
```

Sésamo serves these as a generated `/ui/brand.css`; the strict CSP only
gains the exact logo/font origins, never wildcards. Values are
validated at boot — a bad color or URL refuses to start rather than
rendering broken.

**Tier 2 — design tokens (one stylesheet).** Every visual knob is a CSS
custom property: page & card colors, inputs (bg/border/text/placeholder/
label), primary & secondary buttons, link/focus/danger/success states,
radii per element (card/button/input), card border width/shadow/padding/
alignment, typography (family/sizes/title weight/alignment), and logo
height. Point `SESAMO_THEME_CSS_URL` at a stylesheet that overrides any
of them — it loads last, so your `:root` wins. Derived tokens follow
their base (override `--sesamo-primary` and links/focus follow), but
each is individually overridable. The full list lives in
`internal/ui/assets/theme.css`.

```css
/* my-theme.css — light theme in six lines */
:root {
  --sesamo-primary: #e2007a;
  --sesamo-bg: #ffffff;
  --sesamo-surface: #f7f7f9;
  --sesamo-text: #14161a;
  --sesamo-radius: 4px;
  --sesamo-card-shadow: 0 8px 30px rgb(0 0 0 / 0.08);
}
```

**Tier 3 — headless (your UI, our API).** Send `Accept:
application/json` (or `?mode=json`) to any end-user endpoint and render
your own screens. `GET /login` in JSON mode also returns the operator's
`branding` object (logo, colors, font, theme URL), so a custom frontend
can honor the configured look without hardcoding it.

## Migrating from Auth0

Export your users (Auth0 → User Migrations / bulk export extension) as
NDJSON, then:

```bash
./sesamo admin import auth0-export.ndjson
```

Bcrypt password hashes are stored **verbatim**, so every user's existing
password keeps working immediately — no reset emails or big-bang cutover.
On each user's first successful login, the hash is transparently re-hashed
from bcrypt to Argon2id (lazy migration). Rows are inserted in pipelined
batches of 500 (one round trip per batch). Re-running the import is idempotent:
existing emails are skipped, and a skip does **not** update other fields
(name, `email_verified`) that may have changed in Auth0 since.

## Security model

- **Tokens**: 256-bit random session tokens; only `SHA-256(token)` is
  stored. Raw tokens never touch the database.
- **Passwords**: Argon2id (RFC 9106, 64 MiB). Imported bcrypt verified and
  upgraded on login. Constant-time comparisons; dummy-hash work on missing
  users to defeat timing-based enumeration.
- **Anti-enumeration**: login, signup, reset, and magic-link return
  identical responses whether or not the account exists.
- **CSRF**: OAuth uses `state` + PKCE S256. Every state-changing form POST
  (`/login`, `/signup`, `/logout`, reset and magic-link request) requires a
  constant-time double-submit pair: the HttpOnly `sesamo_csrf` cookie and
  either form field `csrf_token` or `X-CSRF-Token`. Headless clients obtain
  the token from `GET /login` JSON.
- **Rate limiting**: token-bucket per-IP **and** per-identity on every
  credential endpoint (Postgres-backed, holds across instances).
- **Session hygiene**: password reset and account disable revoke all
  sessions. Rolling renewal is capped at
  `SESAMO_SESSION_MAX_LIFETIME_DAYS` from creation.
- **Account kill switch**: `disabled=true` blocks password, OAuth and magic
  link login; introspection returns inactive and disabling revokes sessions
  atomically.
- **Headers**: strict CSP, `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy`, and HSTS when `SESAMO_COOKIE_SECURE=true`.
- **Failure bounds**: server read/write/idle deadlines, bounded OAuth/JWKS/
  email clients, panic recovery and request correlation IDs.

The threat model and its corresponding tests are documented in
[`THREAT_MODEL.md`](./THREAT_MODEL.md).

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
VERSION=v0.1.0
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o sesamo ./cmd/sesamo
./sesamo version
```

This produces a single static binary that needs a reachable Postgres.
`./sesamo serve` runs migrations on boot; a Postgres advisory lock serializes
concurrent migration attempts. The server bounds headers (10 s), full
reads/writes (30 s) and idle connections (120 s). Health: `/healthz`
(liveness), `/readyz` (readiness).

Release tags `v*` run the tag workflow: cross-compiled binary assets with
checksums, a multi-arch GHCR image whose digest is emitted in the summary,
Trivy critical-vulnerability gating, and an SPDX SBOM artifact. CI also gates
the DB-backed suite, the race detector and `govulncheck`.

Migrations run `CREATE EXTENSION IF NOT EXISTS pgcrypto, citext`, which
needs a role allowed to create extensions. Fine on RDS/Supabase/Neon
defaults; on a restrictive managed Postgres, have a DBA pre-create both
extensions once and Sésamo needs nothing further.

## License

[FSL-1.1-Apache-2.0](./LICENSE) — Functional Source License, converting to
Apache 2.0 two years after each release.
