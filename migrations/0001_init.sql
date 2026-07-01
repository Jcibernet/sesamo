-- Sésamo schema baseline. Idempotent.
-- IDs: UUIDv7 supplied by the application layer (portable across PG
-- versions). gen_random_uuid() is kept only as a safety fallback so a
-- raw INSERT without an app-supplied id still works.
-- audit_log uses BIGINT identity: append-only, internal, never exposed
-- in URLs, and we want natural ordering + cheap counts.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

-- ── USERS ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email          CITEXT UNIQUE NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    -- PHC string: $argon2id$... (native) or $2b$... (bcrypt, Auth0 import).
    -- NULL when the user is OAuth-only.
    password_hash  TEXT,
    name           TEXT,
    picture_url    TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata       JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- ── IDENTITIES (OAuth providers, 1 user -> N identities) ───────────
CREATE TABLE IF NOT EXISTS identities (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider     TEXT NOT NULL,          -- 'google' | 'apple' | 'github'
    provider_sub TEXT NOT NULL,          -- stable subject id at provider
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_sub)
);
CREATE INDEX IF NOT EXISTS ix_identities_user_id ON identities (user_id);

-- ── SESSIONS (opaque token; raw lives only in the cookie) ──────────
CREATE TABLE IF NOT EXISTS sessions (
    id_hash      BYTEA PRIMARY KEY,      -- SHA-256(raw_token)
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    user_agent   TEXT,
    ip_first     INET
);
CREATE INDEX IF NOT EXISTS ix_sessions_user_id ON sessions (user_id);
CREATE INDEX IF NOT EXISTS ix_sessions_expires_at ON sessions (expires_at);

-- ── OAUTH CLIENTS (only used when OIDC/V2 is enabled) ──────────────
CREATE TABLE IF NOT EXISTS oauth_clients (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id          TEXT UNIQUE NOT NULL,
    client_secret_hash TEXT NOT NULL,
    redirect_uris      TEXT[] NOT NULL,  -- exact allowlist (anti-SSRF)
    grant_types        TEXT[] NOT NULL DEFAULT '{authorization_code}',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── ONE-TIME TOKENS (password reset + email verification) ──────────
CREATE TABLE IF NOT EXISTS one_time_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  BYTEA NOT NULL,          -- SHA-256
    purpose     TEXT NOT NULL,           -- 'reset' | 'verify' | 'magiclink'
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,             -- single-use guard
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_ott_token_hash
    ON one_time_tokens (token_hash) WHERE consumed_at IS NULL;

-- ── AUDIT LOG (append-only) ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_user  UUID,
    event       TEXT NOT NULL,
    ip          INET,
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS ix_audit_occurred ON audit_log (occurred_at);

-- ── RATE LIMIT BUCKETS (token bucket, per-IP and per-identity) ─────
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    key        TEXT PRIMARY KEY,         -- 'ip:1.2.3.4' | 'identity:user@x'
    tokens     DOUBLE PRECISION NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
