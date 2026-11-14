import { describe, expect, it } from "vitest";
import { decryptSyntheticEntry, encryptSyntheticEntry } from "./crypto";
import { signChallengeForTests } from "./access-proof";
import { createWrappedVaultKeyForTests, unwrapVaultKeyForTests } from "./key-wrapping";
import { createWrappedSigningCredentialForTests } from "./signing-recovery";
import { generateRecoveryWords } from "./recovery";
import { deriveVaultLookupIdForTests } from "./recovery-bootstrap";
import { signRegistrationIntentForTests } from "./registration-intent";
import { SyntheticVaultStoreForTests, type SyntheticVaultBackup } from "./synthetic-vault-store";

const clock = 1_783_000_000_000;

async function prepare() {
  const phrase = generateRecoveryWords();
  const lookupId = await deriveVaultLookupIdForTests(phrase);
  const data = await createWrappedVaultKeyForTests(phrase);
  const signing = await createWrappedSigningCredentialForTests(phrase, data.envelope.vaultId);
  const backup: SyntheticVaultBackup = {
    vaultId: data.envelope.vaultId,
    wrappedDataKey: data.envelope,
    wrappedSigningKey: signing.envelope,
    verificationKey: signing.envelope.publicKey
  };
  return { phrase, lookupId, data, signing, backup };
}

async function signFor(
  store: SyntheticVaultStoreForTests, vaultId: string,
  privateKey: CryptoKey, action: "read"|"append"|"export"|"delete",
  now = clock
) {
  return signChallengeForTests(privateKey, store.issueActionChallenge(vaultId, action, now));
}

async function registerFixture(
  store: SyntheticVaultStoreForTests,
  fixture: Awaited<ReturnType<typeof prepare>>,
  now = clock
) {
  const challenge = store.issueRegistrationChallenge(fixture.backup.vaultId, now);
  const proof = await signChallengeForTests(fixture.signing.privateKey, challenge);
  const intent = await signRegistrationIntentForTests(
    fixture.signing.privateKey, challenge, fixture.backup, fixture.lookupId
  );
  await store.register(fixture.backup, proof, now + 1, fixture.lookupId, intent);
}

describe("synthetic ciphertext-only store — no server or persistence", () => {
  it("requires proof-of-possession for registration and rejects duplicate vault IDs", async () => {
    const fixture = await prepare();
    const store = new SyntheticVaultStoreForTests();
    await registerFixture(store, fixture);
    const initial = store.issueRegistrationChallenge(fixture.backup.vaultId, clock);
    const proof = await signChallengeForTests(fixture.signing.privateKey, initial);
    const intent = await signRegistrationIntentForTests(fixture.signing.privateKey, initial, fixture.backup, fixture.lookupId);
    await expect(store.register(fixture.backup, proof, clock + 2, fixture.lookupId, intent)).rejects.toThrow();
    const other = await prepare();
    const attackerProof = await signChallengeForTests(other.signing.privateKey,
      store.issueRegistrationChallenge(other.backup.vaultId, clock));
    const forgedBackup = { ...other.backup, vaultId: fixture.backup.vaultId };
    const attackerIntent = await signRegistrationIntentForTests(
      other.signing.privateKey, attackerProof.challenge, other.backup, other.lookupId
    );
    await expect(store.register(forgedBackup, attackerProof, clock + 1, other.lookupId, attackerIntent)).rejects.toThrow();
  });

  it("stores and exports ciphertext without obtaining the phrase or plaintext", async () => {
    const fixture = await prepare();
    const store = new SyntheticVaultStoreForTests();
    await registerFixture(store, fixture);
    const original = "Synthetic example only, not real testimony.";
    const ciphertext = await encryptSyntheticEntry(fixture.data.key, original);
    await store.appendEntry(fixture.backup.vaultId,
      await signFor(store, fixture.backup.vaultId, fixture.signing.privateKey, "append"),
      { entryId: "syntheticEntry_123456789", revision: 1, ciphertext }, clock + 10);
    const exportPackage = await store.exportCiphertext(fixture.backup.vaultId,
      await signFor(store, fixture.backup.vaultId, fixture.signing.privateKey, "export"),
      clock + 10);
    const encoded = JSON.stringify(exportPackage);
    expect(encoded).not.toContain(original);
    expect(encoded).not.toContain(fixture.phrase);
    const restoredKey = await unwrapVaultKeyForTests(fixture.phrase, exportPackage.backup.wrappedDataKey);
    expect(await decryptSyntheticEntry(restoredKey, exportPackage.entries[0].ciphertext)).toBe(original);
    expect(exportPackage.entries[0].ciphertext.ciphertext).toBe(ciphertext.ciphertext);
  });

  it("rejects unauthorized reads and cross-vault proof reuse", async () => {
    const owner = await prepare();
    const other = await prepare();
    const store = new SyntheticVaultStoreForTests();
    await registerFixture(store, owner);
    const forged = await signFor(store, owner.backup.vaultId, other.signing.privateKey, "read");
    await expect(store.readEntries(owner.backup.vaultId, forged, clock + 3)).rejects.toThrow();
    const proof = await signFor(store, owner.backup.vaultId, owner.signing.privateKey, "read");
    await expect(store.readEntries(other.backup.vaultId, proof, clock + 3)).rejects.toThrow();
    expect(await store.readEntries(owner.backup.vaultId,
      await signFor(store, owner.backup.vaultId, owner.signing.privateKey, "read"), clock + 3)).toEqual([]);
  });

  it("rejects replayed append proofs and conflicting revisions", async () => {
    const fixture = await prepare();
    const store = new SyntheticVaultStoreForTests();
    await registerFixture(store, fixture);
    const cipher = await encryptSyntheticEntry(fixture.data.key, "fiction");
    const entry = { entryId: "syntheticEntry_123456789", revision: 1, ciphertext: cipher };
    const proof = await signFor(store, fixture.backup.vaultId, fixture.signing.privateKey, "append");
    await store.appendEntry(fixture.backup.vaultId, proof, entry, clock + 4);
    await expect(store.appendEntry(fixture.backup.vaultId, proof,
      { ...entry, entryId: "anotherEntry_123456789", revision: 2 }, clock + 5)).rejects.toThrow();
    await expect(store.appendEntry(fixture.backup.vaultId,
      await signFor(store, fixture.backup.vaultId, fixture.signing.privateKey, "append"),
      { ...entry, entryId: "anotherEntry_123456789", revision: 1 }, clock + 5)).rejects.toThrow();
  });

  it("requires a separate authorized deletion proof", async () => {
    const fixture = await prepare();
    const store = new SyntheticVaultStoreForTests();
    await registerFixture(store, fixture);
    const readProof = await signFor(store, fixture.backup.vaultId, fixture.signing.privateKey, "read");
    await expect(store.deleteVault(fixture.backup.vaultId, readProof, clock + 2)).rejects.toThrow();
    await store.deleteVault(fixture.backup.vaultId,
      await signFor(store, fixture.backup.vaultId, fixture.signing.privateKey, "delete"), clock + 3);
    await expect(store.getBackup(fixture.backup.vaultId,
      await signFor(store, fixture.backup.vaultId, fixture.signing.privateKey, "read"), clock + 4)).rejects.toThrow();
  });
});
