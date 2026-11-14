import { describe, expect, it } from "vitest";
import { issueChallengeForTests, signChallengeForTests, InMemoryProofVerifierForTests } from "./access-proof";
import { generateRecoveryWords } from "./recovery";
import { createWrappedSigningCredentialForTests, recoverSigningCredentialForTests } from "./signing-recovery";

const vaultId = "fictionalVaultId_123456789";
const start = 1_783_000_000_000;

describe("recovery-wrapped P-256 signing credential (test only)", () => {
  it("recovers authentication after serializing the encrypted backup", async () => {
    const phrase = generateRecoveryWords();
    const created = await createWrappedSigningCredentialForTests(phrase, vaultId);
    expect(created.privateKey.extractable).toBe(false);
    expect(JSON.stringify(created.envelope)).not.toContain(phrase);
    expect(created.envelope.publicKey.d).toBeUndefined();

    // Simulate losing the original in-memory key (no persistent browser keys).
    const serialized = JSON.parse(JSON.stringify(created.envelope)) as unknown;
    const restored = await recoverSigningCredentialForTests(phrase, serialized);
    expect(restored.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("pkcs8", restored.privateKey)).rejects.toThrow();

    const challenge = issueChallengeForTests(vaultId, "read", start);
    const verifier = new InMemoryProofVerifierForTests();
    verifier.register(challenge);
    const proof = await signChallengeForTests(restored.privateKey, challenge);
    expect(await verifier.verify(proof, restored.publicKey, vaultId, "read", start + 1)).toBe(true);
    expect(await verifier.verify(proof, restored.publicKey, vaultId, "read", start + 2)).toBe(false);
  });

  it("rejects a different but valid recovery phrase", async () => {
    const phrase = generateRecoveryWords();
    const other = generateRecoveryWords();
    const created = await createWrappedSigningCredentialForTests(phrase, vaultId);
    await expect(recoverSigningCredentialForTests(other, created.envelope)).rejects.toThrow();
  });

  it("detects encrypted backup metadata tampering", async () => {
    const phrase = generateRecoveryWords();
    const created = await createWrappedSigningCredentialForTests(phrase, vaultId);
    const envelope = created.envelope;
    const mutate = (s: string) => (s[0] === "A" ? "B" : "A") + s.slice(1);
    for (const field of ["salt", "iv", "wrappedPrivateKey"] as const) {
      await expect(recoverSigningCredentialForTests(phrase, {
        ...envelope, [field]: mutate(envelope[field])
      })).rejects.toThrow();
    }
    await expect(recoverSigningCredentialForTests(phrase, {
      ...envelope, vaultId: "fictionalVaultId_987654321"
    })).rejects.toThrow();
    await expect(recoverSigningCredentialForTests(phrase, {
      ...envelope, publicKey: { ...envelope.publicKey, x: mutate(envelope.publicKey.x!) }
    })).rejects.toThrow();
  });

  it("rejects malformed envelopes and unknown algorithms", async () => {
    const phrase = generateRecoveryWords();
    const created = await createWrappedSigningCredentialForTests(phrase, vaultId);
    await expect(recoverSigningCredentialForTests(phrase, null)).rejects.toThrow();
    await expect(recoverSigningCredentialForTests(phrase, {
      ...created.envelope, version: 2
    })).rejects.toThrow();
    await expect(recoverSigningCredentialForTests(phrase, {
      ...created.envelope, algorithm: "none"
    })).rejects.toThrow();
    await expect(recoverSigningCredentialForTests(phrase, {
      ...created.envelope, publicKey: { ...created.envelope.publicKey, d: "secret" }
    })).rejects.toThrow();
    await expect(createWrappedSigningCredentialForTests("fake recovery phrase", vaultId)).rejects.toThrow();
  });

  it("generates different encrypted credentials for separate vaults", async () => {
    const phrase = generateRecoveryWords();
    const first = await createWrappedSigningCredentialForTests(phrase, vaultId);
    const second = await createWrappedSigningCredentialForTests(phrase, vaultId);
    expect(first.envelope.salt).not.toBe(second.envelope.salt);
    expect(first.envelope.iv).not.toBe(second.envelope.iv);
    expect(first.envelope.wrappedPrivateKey).not.toBe(second.envelope.wrappedPrivateKey);
  });
});
