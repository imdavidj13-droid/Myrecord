-- FICTIONAL LOCAL WRANGLER D1 INTEGRATION FIXTURE. NEVER EXECUTE REMOTELY.
-- This tests SQL lifecycle constraints, NOT cryptographic authorization.
-- The cryptographic proof/signature tests run separately under Vitest.

INSERT INTO sandbox_registration_challenges
(nonce,vault_id,action,issued_ms,expires_ms)
VALUES (
  'RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR',
  'syntheticVault12345678','append',1000,61000
);

-- Claim the registration challenge as an all-or-nothing enrollment.
UPDATE sandbox_registration_challenges
SET consumed_ms=2000,consume_marker='MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM'
WHERE nonce='RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR'
  AND consumed_ms IS NULL AND issued_ms<=2000 AND expires_ms>2000;

INSERT INTO sandbox_vaults(vault_id,lookup_id,verification_jwk,wrapped_backup_json)
VALUES(
 'syntheticVault12345678',
 'LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL',
 '{"kty":"EC","test":"synthetic-only"}',
 '{"wrappedDataKey":"synthetic-only","wrappedSigningKey":"synthetic-only"}'
);

INSERT INTO sandbox_integrity_heads_v2(vault_id)
VALUES ('syntheticVault12345678');

-- Simulate atomic one-use append challenges and chained ciphertext records.
INSERT INTO sandbox_challenges
(nonce,vault_id,action,issued_ms,expires_ms,request_digest)
VALUES (
 'SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS',
 'syntheticVault12345678','append',1000,61000,'fixture-digest-1'
);

INSERT INTO sandbox_consumed_nonces(nonce,consumed_ms)
VALUES('SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS',2001);

INSERT INTO sandbox_integrity_entries_v2
(entry_id,vault_id,revision,previous_digest,envelope_digest,encrypted_envelope_json,server_received_ms)
VALUES (
 'syntheticLifecycleEntry001','syntheticVault12345678',1,
 '0000000000000000000000000000000000000000000000000000000000000000',
 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
 '{"version":2,"note":"synthetic SQL fixture, NOT authentic ciphertext"}',2001
);

INSERT INTO sandbox_challenges
(nonce,vault_id,action,issued_ms,expires_ms,request_digest)
VALUES (
 'TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT',
 'syntheticVault12345678','append',1000,61000,'fixture-digest-2'
);

INSERT INTO sandbox_consumed_nonces(nonce,consumed_ms)
VALUES('TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT',2002);

INSERT INTO sandbox_integrity_entries_v2
(entry_id,vault_id,revision,previous_digest,envelope_digest,encrypted_envelope_json,server_received_ms)
VALUES (
 'syntheticLifecycleEntry002','syntheticVault12345678',2,
 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
 '{"version":2,"note":"synthetic SQL fixture, NOT authentic ciphertext"}',2002
);
