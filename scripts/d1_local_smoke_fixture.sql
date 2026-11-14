-- LOCAL WRANGLER TEST FIXTURE ONLY. NEVER APPLY TO REMOTE.
-- The values are synthetic strings and deliberately not valid survivor records.
INSERT INTO sandbox_vaults(vault_id,lookup_id,verification_jwk,wrapped_backup_json)
VALUES('fictionalVaultId123456','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','{"kty":"EC","test":true}','{"ciphertext":"synthetic"}');

INSERT INTO sandbox_challenges(nonce,vault_id,action,issued_ms,expires_ms,request_digest)
VALUES('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
       'fictionalVaultId123456','append',1000,61000,'synthetic-digest');

INSERT INTO sandbox_consumed_nonces(nonce,consumed_ms)
VALUES('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',2000);

INSERT INTO sandbox_entries(entry_id,vault_id,revision,encrypted_envelope_json,server_received_ms)
VALUES('fictionalEntryId123456','fictionalVaultId123456',1,'{"ciphertext":"fictional-only"}',2000);
