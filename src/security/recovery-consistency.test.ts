import { describe, expect, it } from "vitest";
import { generateRecoveryWords } from "./recovery";
import { createWrappedVaultKeyForTests } from "./key-wrapping";
import { createWrappedSigningCredentialForTests } from "./signing-recovery";
import { deriveVaultLookupIdForTests } from "./recovery-bootstrap";
import { verifyLocalRecoveryConsistencyForTests } from "./recovery-consistency";
import { recoverSigningCredentialForTests } from "./signing-recovery";
import type { SyntheticVaultBackup } from "./synthetic-vault-store";

async function fixture() {
  const words = generateRecoveryWords();
  const lookupId = await deriveVaultLookupIdForTests(words);
  const wrappedData = await createWrappedVaultKeyForTests(words);
  const wrappedSigning = await createWrappedSigningCredentialForTests(
    words, wrappedData.envelope.vaultId
  );
  const backup: SyntheticVaultBackup = {
    vaultId: wrappedData.envelope.vaultId,
    wrappedDataKey: wrappedData.envelope,
    wrappedSigningKey: wrappedSigning.envelope,
    verificationKey: wrappedSigning.envelope.publicKey
  };
  return { words, lookupId, backup };
}

describe("local recovery-consistency preflight — synthetic only", () => {
  it("confirms lookup, data key and signing key are recoverable with one phrase", async () => {
    const f = await fixture();
    const recovered = await recoverSigningCredentialForTests(f.words, f.backup.wrappedSigningKey);
    expect(recovered.publicKey.extractable).toBe(false);
    expect(recovered.privateKey.extractable).toBe(false);
    const result = await verifyLocalRecoveryConsistencyForTests(
      f.words, f.lookupId, JSON.parse(JSON.stringify(f.backup)) as SyntheticVaultBackup
    );
    expect(result).toEqual({ ready: true, vaultId: f.backup.vaultId, lookupId: f.lookupId });
    expect(JSON.stringify(result)).not.toContain(f.words);
  });

  it("rejects another valid phrase", async () => {
    const f = await fixture();
    await expect(verifyLocalRecoveryConsistencyForTests(
      generateRecoveryWords(), f.lookupId, f.backup
    )).rejects.toThrow();
  });

  it("rejects mismatched lookup metadata", async () => {
    const f = await fixture();
    const other = await fixture();
    await expect(verifyLocalRecoveryConsistencyForTests(
      f.words, other.lookupId, f.backup
    )).rejects.toThrow();
  });

  it("rejects a different encrypted data-key backup even with matching vault ID", async () => {
    const f = await fixture();
    const otherPhrase = generateRecoveryWords();
    const otherVault = await createWrappedVaultKeyForTests(otherPhrase);
    const modified: SyntheticVaultBackup = {
      ...f.backup,
      wrappedDataKey: { ...otherVault.envelope, vaultId: f.backup.vaultId }
    };
    await expect(verifyLocalRecoveryConsistencyForTests(
      f.words, f.lookupId, modified
    )).rejects.toThrow();
  });

  it("rejects mismatched or corrupted signing backups", async () => {
    const f = await fixture();
    const otherPhrase = generateRecoveryWords();
    const otherSigning = await createWrappedSigningCredentialForTests(
      otherPhrase, f.backup.vaultId
    );
    await expect(verifyLocalRecoveryConsistencyForTests(
      f.words, f.lookupId, { ...f.backup, wrappedSigningKey: otherSigning.envelope }
    )).rejects.toThrow();
    await expect(verifyLocalRecoveryConsistencyForTests(
      f.words, f.lookupId,
      { ...f.backup, verificationKey: { ...f.backup.verificationKey, x: "invalid" } }
    )).rejects.toThrow();
  });

  it("rejects inconsistent vault IDs and invalid phrase formatting", async () => {
    const f = await fixture();
    await expect(verifyLocalRecoveryConsistencyForTests(
      f.words, f.lookupId, {
        ...f.backup, wrappedDataKey: { ...f.backup.wrappedDataKey, vaultId: "wrong" }
      }
    )).rejects.toThrow();
    await expect(verifyLocalRecoveryConsistencyForTests(
      "not a phrase", f.lookupId, f.backup
    )).rejects.toThrow();
  });
});
