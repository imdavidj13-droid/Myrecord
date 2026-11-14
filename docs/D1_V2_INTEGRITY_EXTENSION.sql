-- Experimental v2 digest-chain D1 schema extension.
-- TEST DATABASES ONLY. Do not apply to mysafespace-db or any live vault.
-- V1 sandbox_entries is intentionally left in place for prior regression tests.

CREATE TABLE IF NOT EXISTS sandbox_integrity_entries_v2 (
  entry_id TEXT NOT NULL PRIMARY KEY,
  vault_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK(revision >= 1),
  previous_digest TEXT NOT NULL CHECK(length(previous_digest) = 64),
  envelope_digest TEXT NOT NULL CHECK(length(envelope_digest) = 64),
  encrypted_envelope_json TEXT NOT NULL,
  server_received_ms INTEGER NOT NULL,
  FOREIGN KEY(vault_id) REFERENCES sandbox_vaults(vault_id),
  UNIQUE(vault_id, revision)
);

-- A separate latest revision/head is used for the v2 test path. No v1
-- migration is implied; mixed-version writes to one vault are unsupported.
CREATE TABLE IF NOT EXISTS sandbox_integrity_heads_v2 (
  vault_id TEXT NOT NULL PRIMARY KEY,
  latest_revision INTEGER NOT NULL DEFAULT 0 CHECK(latest_revision >= 0),
  head_digest TEXT NOT NULL DEFAULT
    '0000000000000000000000000000000000000000000000000000000000000000',
  FOREIGN KEY(vault_id) REFERENCES sandbox_vaults(vault_id)
);

CREATE TRIGGER IF NOT EXISTS sandbox_integrity_v2_validate
BEFORE INSERT ON sandbox_integrity_entries_v2
BEGIN
  SELECT RAISE(ABORT, 'invalid v2 digest continuity or vault state')
  WHERE NOT EXISTS (
    SELECT 1 FROM sandbox_integrity_heads_v2 h
    JOIN sandbox_vaults v ON v.vault_id = h.vault_id
    WHERE h.vault_id = NEW.vault_id AND v.status = 'active'
      AND h.latest_revision + 1 = NEW.revision
      AND h.head_digest = NEW.previous_digest
  );
END;

CREATE TRIGGER IF NOT EXISTS sandbox_integrity_v2_advance
AFTER INSERT ON sandbox_integrity_entries_v2
BEGIN
  UPDATE sandbox_integrity_heads_v2
  SET latest_revision = NEW.revision, head_digest = NEW.envelope_digest
  WHERE vault_id = NEW.vault_id;
END;

CREATE TRIGGER IF NOT EXISTS sandbox_integrity_v2_no_update
BEFORE UPDATE ON sandbox_integrity_entries_v2
BEGIN
  SELECT RAISE(ABORT, 'v2 integrity revisions are immutable');
END;

CREATE TRIGGER IF NOT EXISTS sandbox_integrity_v2_no_delete
BEFORE DELETE ON sandbox_integrity_entries_v2
BEGIN
  SELECT RAISE(ABORT, 'v2 integrity deletion requires reviewed lifecycle');
END;

CREATE INDEX IF NOT EXISTS sandbox_integrity_v2_history
ON sandbox_integrity_entries_v2(vault_id,revision);
