import { describe, expect, it } from "vitest";
import {
  InMemoryProofVerifierForTests, exportVerificationKeyForTests,
  importVerificationKeyForTests, issueChallengeForTests,
  makeEphemeralSigningPairForTests, signChallengeForTests
} from "./access-proof";

const vaultId = "fictionalVaultId_123456789";
const start = 1_783_000_000_000;

describe("anonymous signed challenge access prototype — synthetic only", () => {
  it("accepts a signed challenge with its public key exactly once", async () => {
    const pair = await makeEphemeralSigningPairForTests();
    expect(pair.privateKey.extractable).toBe(false);
    const publicJwk = await exportVerificationKeyForTests(pair.publicKey);
    expect(publicJwk.d).toBeUndefined();
    const verifierKey = await importVerificationKeyForTests(publicJwk);
    const challenge = issueChallengeForTests(vaultId, "read", start);
    const verifier = new InMemoryProofVerifierForTests();
    verifier.register(challenge);
    const proof = await signChallengeForTests(pair.privateKey, challenge);
    await expect(verifier.verify(proof, verifierKey, vaultId, "read", start + 1000)).resolves.toBe(true);
    await expect(verifier.verify(proof, verifierKey, vaultId, "read", start + 1000)).resolves.toBe(false);
  });

  it("rejects a different verification key", async () => {
    const pair = await makeEphemeralSigningPairForTests();
    const other = await makeEphemeralSigningPairForTests();
    const challenge = issueChallengeForTests(vaultId, "append", start);
    const verifier = new InMemoryProofVerifierForTests();
    verifier.register(challenge);
    const proof = await signChallengeForTests(pair.privateKey, challenge);
    expect(await verifier.verify(proof, other.publicKey, vaultId, "append", start + 50)).toBe(false);
  });

  it("rejects mismatched vault/action and tampered challenge fields", async () => {
    const pair = await makeEphemeralSigningPairForTests();
    const challenge = issueChallengeForTests(vaultId, "read", start);
    const verifier = new InMemoryProofVerifierForTests();
    verifier.register(challenge);
    const proof = await signChallengeForTests(pair.privateKey, challenge);
    expect(await verifier.verify(proof, pair.publicKey, vaultId, "delete", start + 200)).toBe(false);
    expect(await verifier.verify(proof, pair.publicKey, "differentVaultId_123456", "read", start + 200)).toBe(false);
    const tampered = { ...proof, challenge: { ...proof.challenge, action: "delete" as const } };
    expect(await verifier.verify(tampered, pair.publicKey, vaultId, "delete", start + 200)).toBe(false);
    expect(await verifier.verify(proof, pair.publicKey, vaultId, "read", start + 200)).toBe(true);
  });

  it("rejects expired challenges, future challenges and invalid signatures", async () => {
    const pair = await makeEphemeralSigningPairForTests();
    const expired = issueChallengeForTests(vaultId, "read", start);
    const verifier = new InMemoryProofVerifierForTests();
    verifier.register(expired);
    const proof = await signChallengeForTests(pair.privateKey, expired);
    expect(await verifier.verify(proof, pair.publicKey, vaultId, "read", start + 60_000)).toBe(false);
    expect(await verifier.verify(proof, pair.publicKey, vaultId, "read", start - 5_001)).toBe(false);
    const valid = issueChallengeForTests(vaultId, "delete", start);
    verifier.register(valid);
    const actual = await signChallengeForTests(pair.privateKey, valid);
    const invalid = { ...actual, signature: actual.signature.slice(0, -1) + (actual.signature.endsWith("A") ? "B" : "A") };
    expect(await verifier.verify(invalid, pair.publicKey, vaultId, "delete", start + 1)).toBe(false);
    expect(await verifier.verify(actual, pair.publicKey, vaultId, "delete", start + 2)).toBe(false);
  });

  it("requires registered challenges and checks public-key input", async () => {
    const pair = await makeEphemeralSigningPairForTests();
    const challenge = issueChallengeForTests(vaultId, "export", start);
    const proof = await signChallengeForTests(pair.privateKey, challenge);
    const verifier = new InMemoryProofVerifierForTests();
    expect(await verifier.verify(proof, pair.publicKey, vaultId, "export", start + 1)).toBe(false);
    await expect(exportVerificationKeyForTests(pair.privateKey)).rejects.toThrow();
    await expect(importVerificationKeyForTests({ kty: "EC", crv: "P-256", x: "x", y: "y", d: "secret" })).rejects.toThrow();
  });

  it("rejects invalid identifiers and issues unpredictable unique nonces", () => {
    expect(() => issueChallengeForTests("known", "read", start)).toThrow();
    const first = issueChallengeForTests(vaultId, "read", start);
    const second = issueChallengeForTests(vaultId, "read", start);
    expect(first.nonce).not.toBe(second.nonce);
  });
});
