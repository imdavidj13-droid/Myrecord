-- MySafeSpace: prospective D1 encrypted-vault schema (DESIGN ONLY).
-- This file is NOT part of an automated migration and MUST NOT be deployed.
-- No live data, real user accounts or public storage endpoints are allowed yet.
--
-- The database must NEVER receive recovery words, decrypted text, signing
-- private keys, unwrapped data keys or phrase-derived secret material.
--
-- Must complete independent review of protocol, anonymous registration,
-- signed request authorization, replay protection, deletion and retention.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS prototype_vaults (
  vault_id TEXT PRIMARY KEY,
  verification_key_jwk TEXT NOT NULL,
  wrapped_key_envelope TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  latest_revision INTEGER NOT NULL DEFAULT 0 CHECK(latest_revision >= 0),
  status TEXT NOT NULL DEFAULT 'active'
    CHECK(status IN ('active', 'deletion_pending', 'deleted'))
);

-- Only encrypted text, never plaintext. The client authenticates each
-- entry's vault ID, revision, and metadata in AEAD associated data.
-- Original rows must be insert-only; never silently overwrite them.
CREATE TABLE IF NOT EXISTS prototype_encrypted_entries (
  entry_id TEXT PRIMARY KEY,
  vault_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK(revision >= 1),
  envelope_json TEXT NOT NULL,
  previous_digest TEXT,
  envelope_digest TEXT NOT NULL,
  server_received_ms INTEGER NOT NULL,
  FOREIGN KEY (vault_id) REFERENCES prototype_vaults(vault_id) ON DELETE RESTRICT,
  UNIQUE(vault_id, revision)
);

CREATE TRIGGER IF NOT EXISTS prototype_entry_no_update
BEFORE UPDATE ON prototype_encrypted_entries
BEGIN
  SELECT RAISE(ABORT, 'Encrypted entry revisions are append-only');
END;

CREATE TRIGGER IF NOT EXISTS prototype_entry_no_delete
BEFORE DELETE ON prototype_encrypted_entries
BEGIN
  SELECT RAISE(ABORT, 'Use independently reviewed vault deletion process');
END;

-- A challenge MUST be atomically consumed once by the server. A simple
-- in-memory JS Map is not enough for concurrent Cloudflare Workers.
CREATE TABLE IF NOT EXISTS prototype_access_challenges (
  nonce TEXT PRIMARY KEY,
  vault_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN ('read', 'append', 'export', 'delete')),
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > issued_at_ms),
  consumed_at_ms INTEGER,
  FOREIGN KEY (vault_id) REFERENCES prototype_vaults(vault_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS prototype_challenge_expiry
ON prototype_access_challenges(expires_at_ms);

-- Pending questions before this design can be made live:
-- 1. Anonymous enrollment authentication / first-write race.
-- 2. How a returning user discovers vault ID without disclosing entropy.
-- 3. Private signing-key recovery using the same phrase without leaving
--    phrase-derived verifier material susceptible to offline guessing.
-- 4. Transactional consume + authorization + atomic append, with revision
--    checks and idempotency across Cloudflare edge invocations.
-- 5. Retention, backup, restore, deletion, rate limiting and legal holds.
-- 6. End-to-end integrity anchoring against server rollback/omission.
-- 7. Authenticated metadata including timestamps and revision order.
-- 8. Data minimization: logs, IP addresses, location and account linkage.
