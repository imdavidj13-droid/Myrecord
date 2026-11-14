/**
 * End-to-end browser / D1-adapter synthetic recovery regression.
 *
 * Exercises recovery words -> registration intent -> transactional D1 adapter ->
 * independently recovered keys -> encrypted v2 history round trip.
 * An in-memory D1 mock is used; no Worker, real database or network calls.
 */
import { describe, expect, it } from "vitest";
import { generateRecoveryWords } from "./recovery";
import { deriveVaultLookupIdForTests } from "./recovery-bootstrap";
import { createWrappedVaultKeyForTests, unwrapVaultKeyForTests } from "./key-wrapping";
import { createWrappedSigningCredentialForTests, recoverSigningCredentialForTests } from "./signing-recovery";
import { prepareRegistrationForTests } from "./prepare-registration";
import { issueRegistrationChallengeD1ForTests, registerVaultD1ForTests } from "./d1-registration";
import {
  encryptIntegrityEntryForTests, decryptIntegrityEntryForTests,
  verifyIntegrityChainForTests, GENESIS_DIGEST_FOR_TESTS
} from "./integrity-chain";
import { issueChallengeForTests } from "./access-proof";
import { signIntegrityAppendForTests, appendIntegrityEntryD1ForTests } from "./d1-v2-integrity";
import type { PrototypeD1Database, PrototypeD1Statement } from "./d1-transaction";
import type { SyntheticVaultBackup } from "./synthetic-vault-store";

const now = 1_783_000_000_000;
function dummyDatabase() {
  const statements: Array<{ sql: string; args: Array<string | number> }> = [];
  const batches: number[] = [];
  let backup: SyntheticVaultBackup | undefined;
  const db: PrototypeD1Database = {
    prepare(sql: string): PrototypeD1Statement {
      return {
        bind(...args: Array<string | number>): PrototypeD1Statement {
          statements.push({ sql, args });
          return this;
        },
        async run() { return { meta: { changes: 1 } }; },
        async first<T>(): Promise<T | null> {
          return backup
            ? { verification_jwk: JSON.stringify(backup.verificationKey) } as T
            : null;
        }
      };
    },
    async batch(records: PrototypeD1Statement[]) {
      batches.push(records.length);
      return records.map(() => ({ success: true, results: [] }));
    }
  };
  return { db, statements, batches, setBackup: (value: SyntheticVaultBackup) => { backup = value; } };
}
async function setup() {
  const phrase = generateRecoveryWords();
  const data = await createWrappedVaultKeyForTests(phrase);
  const signing = await createWrappedSigningCredentialForTests(phrase, data.envelope.vaultId);
  const backup: SyntheticVaultBackup = {
    vaultId: data.envelope.vaultId,
    wrappedDataKey: data.envelope,
    wrappedSigningKey: signing.envelope,
    verificationKey: signing.envelope.publicKey
  };
  return { phrase, data, signing, backup, lookupId: await deriveVaultLookupIdForTests(phrase) };
}

describe("synthetic vault registration -> recovery -> v2 evidence", () => {
  it("registers ciphertext metadata, recovers independently and signs a chained append", async () => {
    const f = await setup();
    const store = dummyDatabase();
    const challenge = await issueRegistrationChallengeD1ForTests(
      store.db, f.backup.vaultId, now
    );
    const prepared = await prepareRegistrationForTests(
      f.phrase, f.lookupId, f.backup, challenge
    );
    await registerVaultD1ForTests(
      store.db, prepared.backup, prepared.lookupId,
      prepared.proof, prepared.intent, now + 1
    );
    expect(store.batches).toEqual([3]);
    expect(store.statements.some(x => x.sql.includes("sandbox_integrity_heads_v2"))).toBe(true);
    expect(JSON.stringify(store.statements)).not.toContain(f.phrase);

    // Simulate a different browser: reconstruct both non-extractable keys
    // from the words and immutable encrypted backup, not the original keys.
    const recoveredDataKey = await unwrapVaultKeyForTests(
      f.phrase, f.backup.wrappedDataKey
    );
    const recoveredSigning = await recoverSigningCredentialForTests(
      f.phrase, f.backup.wrappedSigningKey
    );
    const first = await encryptIntegrityEntryForTests(
      recoveredDataKey, "Synthetic testimony A", f.backup.vaultId,
      "syntheticEvidenceEntry001", 1, GENESIS_DIGEST_FOR_TESTS
    );
    const second = await encryptIntegrityEntryForTests(
      recoveredDataKey, "Synthetic testimony B", f.backup.vaultId,
      "syntheticEvidenceEntry002", 2, first.digest
    );
    store.setBackup(f.backup);
    const appendChallenge = issueChallengeForTests(f.backup.vaultId, "append", now);
    const signed = await signIntegrityAppendForTests(
      recoveredSigning.privateKey, appendChallenge, first
    );
    await appendIntegrityEntryD1ForTests(
      store.db, appendChallenge, first, signed, now + 1
    );
    expect(store.batches).toEqual([3, 2]);
    expect(store.statements.some(x => x.sql.includes("sandbox_integrity_entries_v2"))).toBe(true);

    const verified = await verifyIntegrityChainForTests([first, second], second.digest);
    expect(verified).toEqual({ revision: 2, headDigest: second.digest });
    expect(await decryptIntegrityEntryForTests(recoveredDataKey, first)).toBe("Synthetic testimony A");
    expect(await decryptIntegrityEntryForTests(recoveredDataKey, second)).toBe("Synthetic testimony B");
    expect(JSON.stringify(store.statements)).not.toContain("Synthetic testimony");
  });

  it("rejects a different recovery phrase before any registration transaction", async () => {
    const original = await setup();
    const other = generateRecoveryWords();
    const store = dummyDatabase();
    const challenge = await issueRegistrationChallengeD1ForTests(
      store.db, original.backup.vaultId, now
    );
    await expect(prepareRegistrationForTests(
      other, original.lookupId, original.backup, challenge
    )).rejects.toThrow();
    expect(store.batches).toEqual([]);
  });

  it("rejects an envelope swap before registration or recovery", async () => {
    const original = await setup();
    const another = await setup();
    const store = dummyDatabase();
    const challenge = await issueRegistrationChallengeD1ForTests(
      store.db, original.backup.vaultId, now
    );
    const malicious: SyntheticVaultBackup = {
      ...original.backup, wrappedSigningKey: another.backup.wrappedSigningKey
    };
    await expect(prepareRegistrationForTests(
      original.phrase, original.lookupId, malicious, challenge
    )).rejects.toThrow();
    expect(store.batches).toEqual([]);
  });
});
