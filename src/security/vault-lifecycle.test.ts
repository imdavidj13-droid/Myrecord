import { describe, expect, it } from "vitest";
import { encryptSyntheticEntry, decryptSyntheticEntry } from "./crypto";
import { createWrappedVaultKeyForTests, unwrapVaultKeyForTests } from "./key-wrapping";
import { createWrappedSigningCredentialForTests, recoverSigningCredentialForTests } from "./signing-recovery";
import { InMemoryProofVerifierForTests, issueChallengeForTests, signChallengeForTests } from "./access-proof";
import { generateRecoveryWords } from "./recovery";

describe("complete isolated synthetic vault lifecycle", () => {
  it("restores both decryption and signing from one 12-word phrase after serialized backup", async () => {
    const phrase = generateRecoveryWords();
    const { envelope: vaultEnvelope, key } = await createWrappedVaultKeyForTests(phrase);
    expect(vaultEnvelope.vaultId).toMatch(/^[A-Za-z0-9_-]{22}$/);
    const { envelope: signingEnvelope } = await createWrappedSigningCredentialForTests(phrase, vaultEnvelope.vaultId);
    const entry = await encryptSyntheticEntry(key, "A fictional record, for automated tests only.");

    // Simulate restoring saved CIPHERTEXT and PUBLIC ENVELOPES after browser restart.
    // We do not retain the original in-memory keys in this simulated restore.
    const saved = JSON.parse(JSON.stringify({ vaultEnvelope, signingEnvelope, entry }));
    expect(JSON.stringify(saved)).not.toContain(phrase);
    expect(JSON.stringify(saved)).not.toContain("A fictional record, for automated tests only.");

    const recoveredKey = await unwrapVaultKeyForTests(phrase, saved.vaultEnvelope);
    expect(recoveredKey.extractable).toBe(false);
    expect(await decryptSyntheticEntry(recoveredKey, saved.entry)).toBe("A fictional record, for automated tests only.");

    const signing = await recoverSigningCredentialForTests(phrase, saved.signingEnvelope);
    const verifier = new InMemoryProofVerifierForTests();
    const issuedAt = 1_783_000_000_000;
    const challenge = issueChallengeForTests(vaultEnvelope.vaultId, "read", issuedAt);
    verifier.register(challenge);
    const signed = await signChallengeForTests(signing.privateKey, challenge);
    expect(await verifier.verify(signed, signing.publicKey, vaultEnvelope.vaultId, "read", issuedAt + 1000)).toBe(true);
    expect(await verifier.verify(signed, signing.publicKey, vaultEnvelope.vaultId, "read", issuedAt + 1001)).toBe(false);
  });

  it("rejects recovery of both keys using a different valid recovery phrase", async () => {
    const original = generateRecoveryWords();
    const incorrect = generateRecoveryWords();
    const { envelope: vaultEnvelope } = await createWrappedVaultKeyForTests(original);
    const { envelope: signingEnvelope } = await createWrappedSigningCredentialForTests(original, vaultEnvelope.vaultId);
    await expect(unwrapVaultKeyForTests(incorrect, vaultEnvelope)).rejects.toThrow();
    await expect(recoverSigningCredentialForTests(incorrect, signingEnvelope)).rejects.toThrow();
  });
});
