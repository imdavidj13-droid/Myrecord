import { describe, expect, it } from "vitest";
import { generateTransientEntryKey } from "./crypto";
import {
  encryptIntegrityEntryForTests, decryptIntegrityEntryForTests,
  verifyIntegrityChainForTests, GENESIS_DIGEST_FOR_TESTS
} from "./integrity-chain";

const vault = "syntheticVaultId123456";
const firstId = "fictionalEvidenceEntry001";
const secondId = "fictionalEvidenceEntry002";

describe("isolated evidence AEAD metadata and history chain", () => {
  it("decrypts an authenticated two-revision history", async () => {
    const key = await generateTransientEntryKey();
    const first = await encryptIntegrityEntryForTests(
      key, "Fictional entry one", vault, firstId, 1, GENESIS_DIGEST_FOR_TESTS
    );
    const second = await encryptIntegrityEntryForTests(
      key, "Fictional entry two", vault, secondId, 2, first.digest
    );
    const result = await verifyIntegrityChainForTests([first, second], second.digest);
    expect(result).toEqual({ revision: 2, headDigest: second.digest });
    expect(await decryptIntegrityEntryForTests(key, first)).toBe("Fictional entry one");
    expect(await decryptIntegrityEntryForTests(key, second)).toBe("Fictional entry two");
    expect(JSON.stringify(second)).not.toContain("Fictional entry two");
  });

  it("rejects metadata swaps and ciphertext manipulation", async () => {
    const key = await generateTransientEntryKey();
    const entry = await encryptIntegrityEntryForTests(
      key, "Fictional data", vault, firstId, 1, GENESIS_DIGEST_FOR_TESTS
    );
    const mutations = [
      { ...entry, vaultId: "anotherSyntheticVault123" },
      { ...entry, entryId: secondId },
      { ...entry, revision: 2 },
      { ...entry, previousDigest: "a".repeat(64) },
      { ...entry, iv: "AAAAAAAAAAAAAAAA" },
      { ...entry, ciphertext: "AAAAAAAAAAAAAAAAAAAAAAAA" }
    ];
    for (const mutation of mutations) {
      await expect(decryptIntegrityEntryForTests(key, mutation)).rejects.toThrow();
    }
  });

  it("detects omission, reordering and trusted head rollback", async () => {
    const key = await generateTransientEntryKey();
    const first = await encryptIntegrityEntryForTests(
      key, "A", vault, firstId, 1, GENESIS_DIGEST_FOR_TESTS
    );
    const second = await encryptIntegrityEntryForTests(
      key, "B", vault, secondId, 2, first.digest
    );
    await expect(verifyIntegrityChainForTests([second, first])).rejects.toThrow();
    await expect(verifyIntegrityChainForTests([second])).rejects.toThrow();
    await expect(verifyIntegrityChainForTests([first], second.digest)).rejects.toThrow();
    await expect(verifyIntegrityChainForTests([first, {
      ...second, previousDigest: "b".repeat(64)
    }])).rejects.toThrow();
  });

  it("rejects invalid genesis, malformed revision and wrong decryption keys", async () => {
    const key = await generateTransientEntryKey();
    await expect(encryptIntegrityEntryForTests(
      key, "test", vault, firstId, 1, "f".repeat(64)
    )).rejects.toThrow();
    await expect(encryptIntegrityEntryForTests(
      key, "test", vault, firstId, 0, GENESIS_DIGEST_FOR_TESTS
    )).rejects.toThrow();
    const entry = await encryptIntegrityEntryForTests(
      key, "test", vault, firstId, 1, GENESIS_DIGEST_FOR_TESTS
    );
    await expect(decryptIntegrityEntryForTests(
      await generateTransientEntryKey(), entry
    )).rejects.toThrow();
  });
});
