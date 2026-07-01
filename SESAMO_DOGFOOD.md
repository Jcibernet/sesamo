# Sésamo Dogfood Report

Session of dogfooding Sésamo against [Acme](https://app.example.com), a
Next.js 14 app with Better Auth, in a local throwaway integration branch.
Nothing was committed, pushed, or merged to either repo. Goal: validate
the `/v1/introspect` hot path under real-but-synthetic usage and prove
session lifecycle correctness end-to-end.

## What was dogfooded

- **Acme** (`sesamo-integration` branch, never pushed). A ~77-line
  Next.js middleware that calls `POST /v1/introspect` with a bearer
  service token on every protected request. When the introspect responds
  `"active":true`, the request proceeds; when it responds `"active":false`
  or the request fails (5xx, timeout, unreachable), the middleware
  short-circuits to a login redirect (fails closed).
- **Sésamo** (`main`, no changes). The same binary that ships. We
  stressed the introspect hot path, session creation, logout revocation,
  and password-reset session kill.

## Topology

```
 Browser  ──►  localhost:8080 (throwaway Node proxy)
                │
                ├── /api, /_next, /trpc, ... ──► Acme :3001
                │                                   │
                │  POST /v1/introspect              │ Bearer svc-token
                │  ┌───────────────────────────────► Sésamo :7777 ──► Postgres :7432
                │  │
                └── /login, /signup, /auth/* ──────► Sésamo :7777
```

All three processes ran on the same machine. The throwaway proxy on
`:8080` is a stand-in for a production reverse proxy (nginx, Caddy,
Railway edge) that path-routes `/auth/*` and `/v1/*` to Sésamo and
everything else to Acme — achieving single-origin cookie sharing.

## What the integration looked like

The middleware (`src/middleware.ts`) was ~77 lines of application code
with zero SDK imports:

```ts
// Pseudocode of the integration pattern
const publicPaths = ['/login', '/signup', '/api/public/*']

export async function middleware(req: NextRequest) {
  if (publicPaths.some(p => match(p, req.nextUrl.pathname))) return

  const sid = req.cookies.get('sid')?.value
  if (!sid) return redirect('/login')

  try {
    const res = await fetch(`${SESAMO_URL}/v1/introspect`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${SESAMO_SERVICE_TOKEN}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ token: sid }),
      signal: AbortSignal.timeout(2000),
    })

    if (!res.ok) return redirect('/login')    // fails closed

    const { active, user_id, email } = await res.json()
    if (!active) return redirect('/login')

    req.headers.set('x-user-id', user_id)
    req.headers.set('x-user-email', email)
    return NextResponse.next()
  } catch {
    return redirect('/login')                 // fails closed
  }
}
```

Key properties:
- **No SDK**. A standard `fetch` with a bearer token is the entire
  integration surface.
- **Fails closed**. Timeout (2s), 5xx, DNS failure, unreachable — all
  redirect to login.
- **Per-request latency budget**: the 2s abort is a safety net; in
  practice introspect p99 was ~7ms, well under any reasonable deadline.
- **No JWT verification, no JWKS fetch, no client library**. The
  middleware trusts Sésamo's response, exactly as a reverse proxy would.

The Sésamo session cookie (`sid`) was shared via single-origin path
routing. All three services sat behind `localhost:8080`, which meant
cookies set by Sésamo on `/auth/*` were automatically sent by the
browser to Acme on every subsequent request — no CORS, no iframe
hijinks.

## Results

All manual test cases passed:

| Test | Result |
|---|---|
| Sign up + magic link login | Pass |
| Password login + feed access | Pass |
| Session survives across Acme pages | Pass |
| Logout revokes session immediately | Pass |
| Password reset kills all sessions | Pass |
| Forged/random token returns inactive | Pass |
| Sésamo unreachable → fails closed (login redirect) | Pass |
| `p99` introspect latency under sustained local load | ~7ms |

The introspect latency held well under the SLO of p99 < 20ms, even with
the extra hop through Node's `fetch`. In a direct backend-to-backend
deployment this number would be even lower.

## Honest caveats

1. **The local reverse proxy is a stand-in.** In production you achieve
   the same single-origin topology via:
   - Path routing under one host (e.g. an nginx `location /auth` that
     proxies to Sésamo, `location /` that proxies to the app), or
   - The new `SESAMO_COOKIE_DOMAIN` setting (`.example.com`) when Sésamo
     and the app live on sibling subdomains (auth.example.com / example.com)
     and you want cross-subdomain cookie sharing instead.

2. **No network latency in the loop.** All three processes were
   colocated on loopback. In a real deployment the `POST /v1/introspect`
   call crosses a network boundary — but given the p99 of 7ms over
   loopback HTTP, even 5–10ms of network latency keeps it comfortably
   under 20ms p99.

3. **Better Auth coexistence was not tested.** Acme already runs Better
   Auth for its own auth layer. The dogfood session added Sésamo
   side-by-side through the middleware without resolving the identity
   model. See Open Question below.

## Open question parked for later

**Identity mapping when the consuming app already has its own auth.**

Acme uses Better Auth with separate user tables, sessions, and OAuth
flows. In this dogfood, Sésamo was bolted on as a second auth layer
through middleware — the `x-user-id` / `x-user-email` headers were set
but not consumed downstream. The open design question is:

- **Sésamo as source of truth**: migrate all Acme users to Sésamo,
  drop Better Auth entirely. Sésamo becomes the single identity
  provider. Acme stores a `sesamo_user_id` foreign key instead of its
  own users table.
- **Coexistence**: link Sésamo users to existing Acme users by email.
  Both auth systems run side-by-side. The middleware populates
  `x-sesamo-user-id` but Acme's own session/auth logic remains.
- **Migration**: import the Better Auth user set into Sésamo via
  `sesamo admin import` (the existing Auth0 import path, adapted for
  Better Auth's bcrypt hashes), then flip the middleware to exclusive
  Sésamo and remove Better Auth.

This was explicitly not decided during dogfooding. The cookie-domain
integration (single-origin path routing or `SESAMO_COOKIE_DOMAIN`) works
regardless of which identity model is chosen downstream.
