-- Durable transactional-email outbox. Idempotent.
-- Sending from the request handler loses the email whenever the provider
-- is down, and a naive retry after a post-acceptance timeout duplicates
-- it. The handler now enqueues here inside the very transaction that
-- creates the one-time token, and a worker delivers outside it with a
-- lease, bounded retries and a provider idempotency key.
--
-- The queued body embeds a bearer link, so it is NEVER stored in clear:
-- key_id/nonce/ciphertext hold an AES-256-GCM payload whose associated
-- data binds it to this row's id, provider and purpose
-- (SESAMO_EMAIL_OUTBOX_KEYS). The worker erases nonce and ciphertext as
-- soon as the job leaves 'pending', so the plaintext link exists in the
-- database only while it is still deliverable. Recipient, sender and
-- subject stay in clear: they are the envelope an operator needs to
-- diagnose a stuck queue, and none of them is a credential.

-- ── EMAIL OUTBOX ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email_outbox (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- The token the link spends. ON DELETE SET NULL because token purge
    -- must not delete delivery history; a NULL token_id simply means the
    -- worker can no longer re-check whether the link is still live.
    token_id            UUID REFERENCES one_time_tokens(id) ON DELETE SET NULL,
    provider            TEXT NOT NULL,           -- 'resend' | 'postmark' | 'log'
    purpose             TEXT NOT NULL,           -- 'reset' | 'verify' | 'magiclink'
    recipient           CITEXT NOT NULL,
    sender              TEXT NOT NULL,
    subject             TEXT NOT NULL,
    -- Encrypted payload (the body carrying the link). NULL once the job
    -- is no longer deliverable.
    key_id              TEXT,
    nonce               BYTEA,
    ciphertext          BYTEA,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'accepted', 'delivered',
                                          'failed', 'canceled', 'expired')),
    attempt_count       INT NOT NULL DEFAULT 0,
    available_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Lease: a worker that lost its lease cannot overwrite the new owner
    -- (every finalize is scoped by id + lease_token).
    lease_token         UUID,
    lease_until         TIMESTAMPTZ,
    provider_message_id TEXT,
    last_error          TEXT,                    -- bounded code, never a payload
    -- Earlier than the token's expiry by a safety margin: an almost-dead
    -- link is worse than no link.
    send_before         TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    accepted_at         TIMESTAMPTZ,             -- provider API accepted the request
    delivered_at        TIMESTAMPTZ,             -- provider webhook confirmed delivery
    failed_at           TIMESTAMPTZ,
    canceled_at         TIMESTAMPTZ,
    expired_at          TIMESTAMPTZ
);

-- The claim query's only index: pending jobs ordered by readiness. The
-- partial predicate keeps it the size of the backlog, not of history.
CREATE INDEX IF NOT EXISTS ix_email_outbox_pending
    ON email_outbox (available_at) WHERE status = 'pending';
-- Webhook correlation path.
CREATE INDEX IF NOT EXISTS ix_email_outbox_provider_message_id
    ON email_outbox (provider_message_id) WHERE provider_message_id IS NOT NULL;

-- ── PROVIDER DELIVERY EVENTS ───────────────────────────────────────
-- Deduplicated webhook deliveries. svix_id UNIQUE is the replay guard:
-- the endpoint verifies a signature, then an ON CONFLICT DO NOTHING
-- insert decides whether the event still has to move the outbox state.
-- Kept separate from email_outbox so the outbox row holds only the
-- derived operational state.
CREATE TABLE IF NOT EXISTS email_events (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    svix_id             TEXT UNIQUE NOT NULL,
    provider_message_id TEXT NOT NULL,
    event_type          TEXT NOT NULL,           -- 'email.delivered', 'email.bounced', ...
    occurred_at         TIMESTAMPTZ NOT NULL,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_email_events_provider_message_id
    ON email_events (provider_message_id);
CREATE INDEX IF NOT EXISTS ix_email_events_received_at
    ON email_events (received_at);
