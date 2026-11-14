import { describe, expect, it } from "vitest";
import { generateRecoveryWords } from "./recovery";
import { deriveVaultLookupIdForTests } from "./recovery-bootstrap";
import { createWrappedVaultKeyForTests } from "./key-wrapping";
import { createWrappedSigningCredentialForTests } from "./signing-recovery";
import { prepareRegistrationForTests } from "./prepare-registration";
import { SyntheticVaultStoreForTests, type SyntheticVaultBackup } from "./synthetic-vault-store";

async function fixture() {
  const words = generateRecoveryWords();
  const lookupId = await deriveVaultLookupIdForTests(words);
  const data = await createWrappedVaultKeyForTests(words);
  const signing = await createWrappedSigningCredentialForTests(words, data.envelope.vaultId);
  const backup: SyntheticVaultBackup = {
    vaultId: data.envelope.vaultId,
    wrappedDataKey: data.envelope,
    wrappedSigningKey: signing.envelope,
    verificationKey: signing.envelope.publicKey
  };
  return { words, lookupId, backup };
}

describe("synthetic registration preparation", () => {
  it("locally recovers credentials before signing the exact registration", async () => {
    const f = await fixture();
    const store = new SyntheticVaultStoreForTests();
    const now = 1_783_000_000_000;
    const challenge = store.issueRegistrationChallenge(f.backup.vaultId, now);
    const prepared = await prepareRegistrationForTests(
      f.words, f.lookupId, f.backup, challenge
    );
    expect(JSON.stringify(prepared)).not.toContain(f.words);
    await store.register(prepared.backup, prepared.proof, now + 1, prepared.lookupId, prepared.intent);
    expect(store.lookupEncryptedRecoveryPackage(f.lookupId)).toEqual(f.backup);
  });

  it("refuses to sign when the recovery words are incorrect", async () => {
    const f = await fixture();
    const store = new SyntheticVaultStoreForTests();
    const challenge = store.issueRegistrationChallenge(f.backup.vaultId, 1_783_000_000_000);
    await expect(prepareRegistrationForTests(
      generateRecoveryWords(), f.lookupId, f.backup, challenge
    )).rejects.toThrow();
  });

  it("refuses to sign when the challenge is for another vault", async () => {
    const f = await fixture();
    const other = await fixture();
    const store = new SyntheticVaultStoreForTests();
    const challenge = store.issueRegistrationChallenge(other.backup.vaultId, 1_783_000_000_000);
    await expect(prepareRegistrationForTests(
      f.words, f.lookupId, f.backup, challenge
    )).rejects.toThrow();
  });
});
