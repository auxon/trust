-- EntangleIT Trust tables live in the SHARED entangleit D1 (same database as
-- agentpay's ap_ tables). Everything is tr_-prefixed so the schema stays
-- additive. Apply: wrangler d1 execute entangleit --file=schema.sql --remote

-- Canonical subjects: 'wallet:<id>' | 'account:<n>' | 'key:<pubkey>'.
CREATE TABLE IF NOT EXISTS tr_subjects (
  subject TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);

-- Ratchet state per subject: trust climbs at most one level per RATCHET_DAYS
-- and drops immediately when the evidence drops. Never raised by hand.
CREATE TABLE IF NOT EXISTS tr_state (
  subject TEXT PRIMARY KEY,
  level TEXT NOT NULL DEFAULT 'new',
  updated_at INTEGER NOT NULL
);

-- Verified facts, one row per external reference. Content is never stored:
-- only counters, amounts, and short refs. UNIQUE(source, ref) makes ingestion
-- idempotent, so replays and retried webhooks move nothing twice.
CREATE TABLE IF NOT EXISTS tr_observations (
  id TEXT PRIMARY KEY,
  subject TEXT NOT NULL,
  source TEXT NOT NULL,                  -- agentpay | bounties | gateway | operator
  kind TEXT NOT NULL,                    -- spend_snapshot | reputation | payment_settled | ...
  ref TEXT NOT NULL,
  value INTEGER,
  meta_json TEXT NOT NULL DEFAULT '{}',
  observed_at INTEGER NOT NULL,
  UNIQUE (source, ref)
);
CREATE INDEX IF NOT EXISTS idx_tr_observations_subject ON tr_observations (subject, observed_at DESC);

-- Two-sided bindings. A subject pair only merges when both sides carry proof
-- (signed attestation, signed challenge, or an operator-observed link).
CREATE TABLE IF NOT EXISTS tr_bindings (
  a TEXT NOT NULL,
  b TEXT NOT NULL,
  proof TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '',
  bound_at INTEGER NOT NULL,
  revoked_at INTEGER,
  PRIMARY KEY (a, b)
);
CREATE INDEX IF NOT EXISTS idx_tr_bindings_b ON tr_bindings (b);

-- Signed profile cache. Profiles are deterministic; this only saves recompute.
CREATE TABLE IF NOT EXISTS tr_verdicts (
  subject TEXT PRIMARY KEY,
  profile_json TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

-- Billing accounts for the MCP connector (pack/pro/b2b credits).
CREATE TABLE IF NOT EXISTS tr_accounts (
  id TEXT PRIMARY KEY,
  email TEXT,
  credits INTEGER NOT NULL DEFAULT 0,
  plan TEXT NOT NULL DEFAULT 'free',
  stripe_customer TEXT,
  created_at INTEGER NOT NULL
);

-- Per-call metadata for the free tier and stats. No content, ever.
CREATE TABLE IF NOT EXISTS tr_calls (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  subject TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tr_calls_account ON tr_calls (account_id, created_at DESC);