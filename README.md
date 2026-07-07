<p align="center">
  <img src=".github/banner.svg" alt="Sésamo" width="100%">
</p>

<p align="center">
  <a href="https://github.com/Jcibernet/sesamo/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Jcibernet/sesamo/ci.yml?style=for-the-badge&labelColor=0d1117&color=56d364&label=CI" alt="ci"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/LICENSE-FSL--1.1-3fb950?style=for-the-badge&labelColor=0d1117" alt="license"></a>
  <img src="https://img.shields.io/badge/GO-%3E%3D1.26-2ea043?style=for-the-badge&labelColor=0d1117" alt="go">
  <img src="https://img.shields.io/badge/INTROSPECT_P99-%3C20MS-d29922?style=for-the-badge&labelColor=0d1117" alt="latency">
  <img src="docs/12-de-10.svg" alt="12 de 10">
</p>

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
| `SESAMO_DATABASE_URL` | _(required)_ | Postgres DSN. Pool tuning goes in the DSN via pgx params — e.g. `?pool_max_conns=10&pool_min_conns=2`. Defaults: max conns = `max(4, NumCPU)`, conn lifetime 1 h, idle timeout 30 min. Cap `pool_max_conns` explicitly when sharing a small managed Postgres across replicas |
| `SESAMO_BASE_URL` | `http://localhost:7777` | Public URL (cookies, OAuth redirects) |
| `SESAMO_LISTEN_ADDR` | `:7777` | HTTP listen address |
| `SESAMO_COOKIE_SECURE` | `false` | `true` in production (enables HSTS) |
| `SESAMO_COOKIE_DOMAIN` | _(empty)_ | Set when Sésamo and the consuming app live on sibling subdomains and you want the `sid` cookie sent to both (e.g. `.example.com`). Leave empty for single-origin deployments (path-routed under one host) or for local dev. |
| `SESAMO_SESSION_LIFETIME_DAYS` | `30` | Absolute session lifetime |
| `SESAMO_ROLLING_RENEWAL_THRESHOLD_MINUTES` | `15` | Rolling renewal cadence |
| `SESAMO_SERVICE_TOKEN` | _(required for introspect)_ | S2S bearer token |
| `SESAMO_ADMIN_API_KEY` | _(required for admin)_ | Admin bearer token |
| `SESAMO_TRUST_PROXY` | `false` | Honor `X-Forwarded-For` for client IP (rate-limit keying, logs, audit). Enable ONLY behind a proxy that overwrites the header |
| `SESAMO_AUDIT_STRICT` | `false` | Fail auth operations whose `audit_log` write fails (no evidence, no action). Default: best-effort — availability wins |
| `SESAMO_AUDIT_RETENTION_DAYS` | `0` (keep forever) | When > 0, the hourly maintenance job deletes `audit_log` rows older than N days. Unset = unbounded growth; pick a retention before production |
| `SESAMO_{GOOGLE,GITHUB,APPLE}_*` | — | OAuth provider credentials |
| `SESAMO_EMAIL_PROVIDER` | `log` | `log` / `resend` / `postmark` |
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
password keeps working immediately — no reset emails, no big-bang cutover.
On each user's first successful login the hash is transparently re-hashed
from bcrypt to Argon2id (lazy migration). Rows are inserted in pipelined
batches of 500 (one round trip per batch), so a bulk import stays fast
even against a remote Postgres. Re-running the import is idempotent:
existing emails are skipped — a skip does **not** update other fields
(name, `email_verified`) that may have changed in Auth0 since.

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

Migrations run `CREATE EXTENSION IF NOT EXISTS pgcrypto, citext`, which
needs a role allowed to create extensions. Fine on RDS/Supabase/Neon
defaults; on a restrictive managed Postgres, have a DBA pre-create both
extensions once and Sésamo needs nothing further.

## License

[FSL-1.1-Apache-2.0](./LICENSE) — Functional Source License, converting to
Apache 2.0 two years after each release.
