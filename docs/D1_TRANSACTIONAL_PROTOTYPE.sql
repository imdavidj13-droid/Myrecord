-- MySafeSpace D1 TRANSACTIONAL PROTOTYPE — DO NOT APPLY TO LIVE DATABASE.
-- This is a non-deployed draft. All records must be synthetic test ciphertext.
-- No env.DB binding or Worker route is configured by this file.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sandbox_vaults (
  vault_id TEXT NOT NULL PRIMARY KEY,
  lookup_id TEXT NOT NULL UNIQUE,
  verification_jwk TEXT NOT NULL,
  wrapped_backup_json TEXT NOT NULL,
  latest_revision INTEGER NOT NULL DEFAULT 0 CHECK(latest_revision >= 0),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'deletion_pending', 'deleted'))
);

-- Public verification keys and encrypted bootstrap must not be rewritten by
-- a compromised/misconfigured application endpoint after registration.
CREATE TRIGGER IF NOT EXISTS sandbox_vault_identity_immutable
BEFORE UPDATE OF vault_id, lookup_id, verification_jwk, wrapped_backup_json
ON sandbox_vaults
BEGIN
  SELECT RAISE(ABORT, 'vault identity and backup are immutable');
END;

CREATE TABLE IF NOT EXISTS sandbox_challenges (
  nonce TEXT NOT NULL PRIMARY KEY,
  vault_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN ('append', 'read', 'export', 'delete')),
  issued_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL CHECK(expires_ms > issued_ms),
  request_digest TEXT NOT NULL,
  FOREIGN KEY(vault_id) REFERENCES sandbox_vaults(vault_id)
);

-- UNIQUE insertion is the atomic replay barrier.
-- This table intentionally retains consumed nonces until a reviewed retention
-- and expiry policy exists. Do not periodically clear it without assessing
-- replay and nonce lifetime guarantees.
CREATE TABLE IF NOT EXISTS sandbox_consumed_nonces (
  nonce TEXT NOT NULL PRIMARY KEY,
  consumed_ms INTEGER NOT NULL,
  FOREIGN KEY(nonce) REFERENCES sandbox_challenges(nonce)
);

-- A deletion challenge may be consumed only while the vault is active.
-- This trigger also rejects the losing request in concurrent deletion races;
-- a rejected D1 batch rolls back the nonce claim.
CREATE TRIGGER IF NOT EXISTS sandbox_reject_stale_deletion_claim
AFTER INSERT ON sandbox_consumed_nonces
WHEN EXISTS (
  SELECT 1 FROM sandbox_challenges c
  JOIN sandbox_vaults v ON v.vault_id = c.vault_id
  WHERE c.nonce = NEW.nonce AND c.action = 'delete'
    AND v.status <> 'active'
)
BEGIN
  SELECT RAISE(ABORT, 'vault is no longer active');
END;

CREATE TABLE IF NOT EXISTS sandbox_entries (
  entry_id TEXT NOT NULL PRIMARY KEY,
  vault_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK(revision >= 1),
  encrypted_envelope_json TEXT NOT NULL,
  server_received_ms INTEGER NOT NULL,
  FOREIGN KEY(vault_id) REFERENCES sandbox_vaults(vault_id),
  UNIQUE(vault_id, revision)
);

-- The insert must succeed only if the revision is exactly next and the vault
-- is active. SQLite RAISE in a trigger causes the entire D1 batch to rollback.
CREATE TRIGGER IF NOT EXISTS sandbox_validate_append
BEFORE INSERT ON sandbox_entries
BEGIN
  SELECT RAISE(ABORT, 'invalid revision or inactive vault')
  WHERE NOT EXISTS (
    SELECT 1 FROM sandbox_vaults
    WHERE vault_id = NEW.vault_id AND status = 'active'
      AND latest_revision + 1 = NEW.revision
  );
END;

CREATE TRIGGER IF NOT EXISTS sandbox_advance_revision
AFTER INSERT ON sandbox_entries
BEGIN
  UPDATE sandbox_vaults SET latest_revision = NEW.revision
  WHERE vault_id = NEW.vault_id;
END;

CREATE TRIGGER IF NOT EXISTS sandbox_entries_no_update
BEFORE UPDATE ON sandbox_entries
BEGIN
  SELECT RAISE(ABORT, 'append-only entry');
END;

CREATE TRIGGER IF NOT EXISTS sandbox_entries_no_delete
BEFORE DELETE ON sandbox_entries
BEGIN
  SELECT RAISE(ABORT, 'entry deletion requires reviewed lifecycle');
END;

CREATE INDEX IF NOT EXISTS sandbox_entries_by_vault_revision
ON sandbox_entries(vault_id, revision);

CREATE INDEX IF NOT EXISTS sandbox_challenges_expiry
ON sandbox_challenges(expires_ms);

-- Real evidence integrity needs authenticated vault ID, entry ID, revision,
-- chronology and digests inside each AEAD payload. This draft does not provide
-- anti-rollback protection or operator-independent integrity anchoring.
