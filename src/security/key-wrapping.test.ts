import { describe, expect, it } from "vitest";
import { decryptSyntheticEntry, encryptSyntheticEntry } from "./crypto";
import { createWrappedVaultKeyForTests, unwrapVaultKeyForTests } from "./key-wrapping";
import { generateRecoveryWords } from "./recovery";

describe("experimental key envelope, synthetic data only", () => {
  it("recovers a key that decrypts the same entry after an in-memory round trip", async () => {
    const words = generateRecoveryWords();
    const { envelope, key } = await createWrappedVaultKeyForTests(words);
    const entry = await encryptSyntheticEntry(key, "fictional text 🌿");
    const restoredKey = await unwrapVaultKeyForTests(words, JSON.parse(JSON.stringify(envelope)));
    await expect(decryptSyntheticEntry(restoredKey, entry)).resolves.toBe("fictional text 🌿");
    expect(key.extractable).toBe(false);
    expect(restoredKey.extractable).toBe(false);
    expect(JSON.stringify(envelope)).not.toContain(words);
  });

  it("rejects a different valid 12-word recovery phrase", async () => {
    const words = generateRecoveryWords();
    const wrong = generateRecoveryWords();
    const { envelope } = await createWrappedVaultKeyForTests(words);
    await expect(unwrapVaultKeyForTests(wrong, envelope)).rejects.toThrow();
  });

  it("rejects tampering with any authenticated envelope component", async () => {
    const words = generateRecoveryWords();
    const { envelope } = await createWrappedVaultKeyForTests(words);
    for (const field of ["vaultId", "salt", "iv", "wrappedKey"] as const) {
      const source = envelope[field];
      const replacement = (source.charAt(0) === "A" ? "B" : "A") + source.slice(1);
      await expect(unwrapVaultKeyForTests(words, { ...envelope, [field]: replacement })).rejects.toThrow();
    }
    await expect(unwrapVaultKeyForTests(words, { ...envelope, version: 2 })).rejects.toThrow();
    await expect(unwrapVaultKeyForTests(words, { ...envelope, algorithm: "none" })).rejects.toThrow();
  });

  it("rejects malformed envelopes, fake phrases and missing inputs", async () => {
    const words = generateRecoveryWords();
    await expect(createWrappedVaultKeyForTests("not a real phrase")).rejects.toThrow();
    await expect(unwrapVaultKeyForTests(words, null)).rejects.toThrow();
    await expect(unwrapVaultKeyForTests(words, { version: 1, algorithm: "HKDF-SHA-256+A256GCM" })).rejects.toThrow();
    const { envelope } = await createWrappedVaultKeyForTests(words);
    await expect(unwrapVaultKeyForTests(words, { ...envelope, wrappedKey: "A".repeat(1000) })).rejects.toThrow();
  });

  it("generates fresh identifiers and independently wrapped keys for each vault", async () => {
    const words = generateRecoveryWords();
    const first = await createWrappedVaultKeyForTests(words);
    const second = await createWrappedVaultKeyForTests(words);
    expect(first.envelope.vaultId).not.toBe(second.envelope.vaultId);
    expect(first.envelope.salt).not.toBe(second.envelope.salt);
    expect(first.envelope.iv).not.toBe(second.envelope.iv);
    expect(first.envelope.wrappedKey).not.toBe(second.envelope.wrappedKey);
  });
});
