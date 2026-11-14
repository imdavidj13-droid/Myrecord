-- SYNTHETIC-ONLY registration extension; DO NOT APPLY TO THE LIVE DATABASE.
-- Enrollment challenges deliberately do not have a vault FK: vaults do not
-- exist until the entire authorized registration transaction commits.
CREATE TABLE IF NOT EXISTS sandbox_registration_challenges (
  nonce TEXT PRIMARY KEY NOT NULL,
  vault_id TEXT NOT NULL,
  action TEXT NOT NULL DEFAULT 'append' CHECK(action = 'append'),
  issued_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL CHECK(expires_ms > issued_ms),
  consumed_ms INTEGER,
  CHECK(consumed_ms IS NULL OR consumed_ms >= issued_ms)
);

CREATE INDEX IF NOT EXISTS sandbox_registration_expiry
ON sandbox_registration_challenges(expires_ms);

-- A consumed registration challenge must be unique and immutable. Its
-- consumption is a transaction precondition for vault insertion.
CREATE TRIGGER IF NOT EXISTS sandbox_reg_challenge_no_delete
BEFORE DELETE ON sandbox_registration_challenges
BEGIN
  SELECT RAISE(ABORT, 'registration challenge history is immutable');
END;

CREATE TRIGGER IF NOT EXISTS sandbox_reg_challenge_no_rewrite
BEFORE UPDATE OF nonce, vault_id, action, issued_ms, expires_ms
ON sandbox_registration_challenges
BEGIN
  SELECT RAISE(ABORT, 'registration challenge identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS sandbox_reg_challenge_consume_once
BEFORE UPDATE OF consumed_ms ON sandbox_registration_challenges
WHEN OLD.consumed_ms IS NOT NULL OR NEW.consumed_ms IS NULL
BEGIN
  SELECT RAISE(ABORT, 'registration challenge already consumed');
END;

-- A successful registration must present a consumed, matching challenge;
-- no other write path may create a vault without one in the same transaction.
-- This is a local prototype guard, not an independently audited protocol.
CREATE TRIGGER IF NOT EXISTS sandbox_reg_vault_requires_challenge
BEFORE INSERT ON sandbox_vaults
WHEN NOT EXISTS (
  SELECT 1 FROM sandbox_registration_challenges
  WHERE vault_id = NEW.vault_id AND consumed_ms IS NOT NULL
)
BEGIN
  SELECT RAISE(ABORT, 'vault registration requires a consumed challenge');
END;
