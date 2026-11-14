import { describe, expect, it } from "vitest";
import { generateRecoveryWords } from "./recovery";
import { deriveVaultLookupIdForTests } from "./recovery-bootstrap";
import { createWrappedVaultKeyForTests } from "./key-wrapping";
import { createWrappedSigningCredentialForTests } from "./signing-recovery";
import { signChallengeForTests } from "./access-proof";
import { signRegistrationIntentForTests } from "./registration-intent";
import { SyntheticVaultStoreForTests, type SyntheticVaultBackup } from "./synthetic-vault-store";

const now = 1_783_000_000_000;

async function fixture() {
  const phrase = generateRecoveryWords();
  const lookup = await deriveVaultLookupIdForTests(phrase);
  const data = await createWrappedVaultKeyForTests(phrase);
  const signing = await createWrappedSigningCredentialForTests(phrase, data.envelope.vaultId);
  const backup: SyntheticVaultBackup = {
    vaultId: data.envelope.vaultId,
    wrappedDataKey: data.envelope,
    wrappedSigningKey: signing.envelope,
    verificationKey: signing.envelope.publicKey
  };
  return { lookup, signing, backup };
}

async function signedRequest(store: SyntheticVaultStoreForTests, f: Awaited<ReturnType<typeof fixture>>) {
  const challenge = store.issueRegistrationChallenge(f.backup.vaultId, now);
  const proof = await signChallengeForTests(f.signing.privateKey, challenge);
  const intent = await signRegistrationIntentForTests(f.signing.privateKey, challenge, f.backup, f.lookup);
  return { proof, intent };
}

describe("signed registration content binding — synthetic only", () => {
  it("enrols the exact intended backup and locator", async () => {
    const f = await fixture();
    const store = new SyntheticVaultStoreForTests();
    const { proof, intent } = await signedRequest(store, f);
    await store.register(f.backup, proof, now + 1, f.lookup, intent);
    expect(store.lookupEncryptedRecoveryPackage(f.lookup)).toEqual(f.backup);
  });

  it("rejects changing the lookup identifier after signing", async () => {
    const f = await fixture();
    const other = await fixture();
    const store = new SyntheticVaultStoreForTests();
    const { proof, intent } = await signedRequest(store, f);
    await expect(store.register(f.backup, proof, now + 1, other.lookup, intent)).rejects.toThrow();
    expect(store.lookupEncryptedRecoveryPackage(other.lookup)).toBeNull();
  });

  it("rejects substitution of the encrypted data-key envelope", async () => {
    const f = await fixture();
    const store = new SyntheticVaultStoreForTests();
    const { proof, intent } = await signedRequest(store, f);
    const modified: SyntheticVaultBackup = {
      ...f.backup, wrappedDataKey: { ...f.backup.wrappedDataKey, wrappedKey: "AAAA" }
    };
    await expect(store.register(modified, proof, now + 1, f.lookup, intent)).rejects.toThrow();
    expect(store.lookupEncryptedRecoveryPackage(f.lookup)).toBeNull();
  });

  it("rejects substitution of the encrypted signing-key envelope", async () => {
    const f = await fixture();
    const store = new SyntheticVaultStoreForTests();
    const { proof, intent } = await signedRequest(store, f);
    const modified: SyntheticVaultBackup = {
      ...f.backup, wrappedSigningKey: { ...f.backup.wrappedSigningKey, wrappedPrivateKey: "AAAA" }
    };
    await expect(store.register(modified, proof, now + 1, f.lookup, intent)).rejects.toThrow();
  });

  it("rejects a signature from another signing key even when the challenge is valid", async () => {
    const f = await fixture();
    const attacker = await fixture();
    const store = new SyntheticVaultStoreForTests();
    const { proof } = await signedRequest(store, f);
    const forged = await signRegistrationIntentForTests(
      attacker.signing.privateKey, proof.challenge, f.backup, f.lookup
    );
    await expect(store.register(f.backup, proof, now + 1, f.lookup, forged)).rejects.toThrow();
  });

  it("rejects replay of a successfully registered challenge", async () => {
    const f = await fixture();
    const store = new SyntheticVaultStoreForTests();
    const { proof, intent } = await signedRequest(store, f);
    await store.register(f.backup, proof, now + 1, f.lookup, intent);
    await expect(store.register(f.backup, proof, now + 2, f.lookup, intent)).rejects.toThrow();
  });
});
