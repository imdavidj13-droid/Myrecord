import { describe, expect, it } from "vitest";
import { decryptSyntheticEntry, encryptSyntheticEntry, generateTransientEntryKey } from "./crypto";

describe("isolated AES-256-GCM primitive (synthetic data only)", () => {
  it("round-trips Unicode and preserves the exact original text", async () => {
    const key = await generateTransientEntryKey();
    const original = "Synthetic test: café 🌿\nSecond line.\n";
    const encrypted = await encryptSyntheticEntry(key, original);
    expect(encrypted.version).toBe(1);
    expect(encrypted.algorithm).toBe("AES-256-GCM");
    expect(JSON.stringify(encrypted)).not.toContain(original);
    await expect(decryptSyntheticEntry(key, encrypted)).resolves.toBe(original);
  });

  it("uses distinct IVs and ciphertexts across writes", async () => {
    const key = await generateTransientEntryKey();
    const first = await encryptSyntheticEntry(key, "example");
    const second = await encryptSyntheticEntry(key, "example");
    expect(first.iv).not.toEqual(second.iv);
    expect(first.ciphertext).not.toEqual(second.ciphertext);
  });

  it("rejects decryption with a different key", async () => {
    const firstKey = await generateTransientEntryKey();
    const otherKey = await generateTransientEntryKey();
    const entry = await encryptSyntheticEntry(firstKey, "fictional entry");
    await expect(decryptSyntheticEntry(otherKey, entry)).rejects.toThrow();
  });

  it("rejects modified ciphertext, IV, and unsupported version", async () => {
    const key = await generateTransientEntryKey();
    const entry = await encryptSyntheticEntry(key, "fictional entry");
    const mutated = entry.ciphertext.slice(0, -4) + (entry.ciphertext.charAt(entry.ciphertext.length - 4) === "A" ? "B" : "A") + entry.ciphertext.slice(-3);
    await expect(decryptSyntheticEntry(key, { ...entry, ciphertext: mutated })).rejects.toThrow();
    await expect(decryptSyntheticEntry(key, { ...entry, iv: "AAAAAAAAAAAAAAAA" })).rejects.toThrow();
    await expect(decryptSyntheticEntry(key, { ...entry, version: 2 })).rejects.toThrow();
  });

  it("handles empty test entries and rejects oversized plaintext", async () => {
    const key = await generateTransientEntryKey();
    const empty = await encryptSyntheticEntry(key, "");
    await expect(decryptSyntheticEntry(key, empty)).resolves.toBe("");
    await expect(encryptSyntheticEntry(key, "x".repeat(1024 * 1024 + 1))).rejects.toThrow("size limit");
  });

  it("creates a non-extractable transient test key", async () => {
    const key = await generateTransientEntryKey();
    expect(key.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("raw", key)).rejects.toThrow();
  });
});
