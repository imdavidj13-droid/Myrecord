import { describe, expect, it } from "vitest";
import { deriveVaultLookupIdForTests, isValidVaultLookupIdForTests } from "./recovery-bootstrap";
import { generateRecoveryWords } from "./recovery";
import { createWrappedVaultKeyForTests, unwrapVaultKeyForTests } from "./key-wrapping";
import { createWrappedSigningCredentialForTests, recoverSigningCredentialForTests } from "./signing-recovery";
import { encryptSyntheticEntry, decryptSyntheticEntry } from "./crypto";
import { signChallengeForTests } from "./access-proof";
import { SyntheticVaultStoreForTests, type SyntheticVaultBackup } from "./synthetic-vault-store";

const now = 1_783_000_000_000;

async function createFixture() {
  const phrase = generateRecoveryWords();
  const lookupId = await deriveVaultLookupIdForTests(phrase);
  const vault = await createWrappedVaultKeyForTests(phrase);
  const signing = await createWrappedSigningCredentialForTests(phrase, vault.envelope.vaultId);
  const backup: SyntheticVaultBackup = {
    vaultId: vault.envelope.vaultId,
    wrappedDataKey: vault.envelope,
    wrappedSigningKey: signing.envelope,
    verificationKey: signing.envelope.publicKey
  };
  return { phrase, lookupId, vault, signing, backup };
}

async function register(store: SyntheticVaultStoreForTests, fixture: Awaited<ReturnType<typeof createFixture>>) {
  const issued = store.issueRegistrationChallenge(fixture.backup.vaultId, now);
  const signed = await signChallengeForTests(fixture.signing.privateKey, issued);
  await store.register(fixture.backup, signed, now + 1, fixture.lookupId);
}

describe("isolated 12-word recovery bootstrap — synthetic data only", () => {
  it("derives a stable, separate opaque identifier without exposing recovery words", async () => {
    const words = generateRecoveryWords();
    const id = await deriveVaultLookupIdForTests(words);
    expect(isValidVaultLookupIdForTests(id)).toBe(true);
    expect(id).toHaveLength(43);
    expect(id).toBe(await deriveVaultLookupIdForTests("  " + words.toUpperCase() + "  "));
    expect(id).not.toContain(words.split(" ")[0]);
    const another = generateRecoveryWords();
    expect(await deriveVaultLookupIdForTests(another)).not.toBe(id);
    await expect(deriveVaultLookupIdForTests("invalid recovery phrase")).rejects.toThrow();
    expect(isValidVaultLookupIdForTests("bad")).toBe(false);
  });

  it("retrieves only encrypted backup before auth; restores keys and reads ciphertext after signed proof", async () => {
    const f = await createFixture();
    const store = new SyntheticVaultStoreForTests();
    await register(store, f);
    const secret = "Fictional synthetic example 🌿";
    const entry = await encryptSyntheticEntry(f.vault.key, secret);
    const appendProof = await signChallengeForTests(
      f.signing.privateKey, store.issueActionChallenge(f.backup.vaultId, "append", now)
    );
    await store.appendEntry(f.backup.vaultId, appendProof,
      { entryId: "fictionalEntry_12345678", revision: 1, ciphertext: entry }, now + 2);

    // Simulate a new browser: retain ONLY the user's remembered recovery words.
    const rediscovered = await deriveVaultLookupIdForTests(f.phrase);
    const publicPackage = store.lookupEncryptedRecoveryPackage(rediscovered);
    expect(publicPackage).not.toBeNull();
    const serialized = JSON.stringify(publicPackage);
    expect(serialized).not.toContain(f.phrase);
    expect(serialized).not.toContain(secret);
    expect(serialized).not.toContain(entry.ciphertext);

    const recoveredSigning = await recoverSigningCredentialForTests(f.phrase, publicPackage!.wrappedSigningKey);
    const recoveredKey = await unwrapVaultKeyForTests(f.phrase, publicPackage!.wrappedDataKey);
    const readProof = await signChallengeForTests(recoveredSigning.privateKey,
      store.issueActionChallenge(publicPackage!.vaultId, "read", now));
    const records = await store.readEntries(publicPackage!.vaultId, readProof, now + 3);
    expect(records).toHaveLength(1);
    expect(await decryptSyntheticEntry(recoveredKey, records[0].ciphertext)).toBe(secret);
  });

  it("does not let a different phrase discover or decrypt the vault", async () => {
    const f = await createFixture();
    const store = new SyntheticVaultStoreForTests();
    await register(store, f);
    const wrong = generateRecoveryWords();
    expect(store.lookupEncryptedRecoveryPackage(await deriveVaultLookupIdForTests(wrong))).toBeNull();
    await expect(recoverSigningCredentialForTests(wrong, f.backup.wrappedSigningKey)).rejects.toThrow();
    await expect(unwrapVaultKeyForTests(wrong, f.backup.wrappedDataKey)).rejects.toThrow();
  });

  it("rejects duplicate recovery locator registration", async () => {
    const f = await createFixture();
    const store = new SyntheticVaultStoreForTests();
    await register(store, f);
    const other = await createFixture();
    const challenge = store.issueRegistrationChallenge(other.backup.vaultId, now);
    const proof = await signChallengeForTests(other.signing.privateKey, challenge);
    await expect(store.register(other.backup, proof, now + 1, f.lookupId)).rejects.toThrow();
  });

  it("removes the lookup index after authorized test deletion", async () => {
    const f = await createFixture();
    const store = new SyntheticVaultStoreForTests();
    await register(store, f);
    const proof = await signChallengeForTests(f.signing.privateKey,
      store.issueActionChallenge(f.backup.vaultId, "delete", now));
    await store.deleteVault(f.backup.vaultId, proof, now + 5);
    expect(store.lookupEncryptedRecoveryPackage(f.lookupId)).toBeNull();
  });
});
