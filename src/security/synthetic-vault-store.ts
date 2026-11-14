/**
 * In-memory, synthetic-data-only prototype of a vault service.
 *
 * NO ROUTES, NO DATABASE, NO PERSISTENCE, NO REAL SURVIVOR DATA.
 * Server operations accept ciphertext envelopes, never plaintext or recovery
 * words. This is intentionally NOT a Cloudflare Worker or production API.
 *
 * This is sequential test infrastructure. Its Map-based challenges, registration,
 * and revision checks are NOT atomic across concurrent requests or isolates.
 */
import {
  InMemoryProofVerifierForTests, importVerificationKeyForTests,
  issueChallengeForTests, type ProofChallengeV1, type SignedProofV1,
  type VaultAction
} from "./access-proof";
import type { EncryptedEntryV1 } from "./crypto";
import type { WrappedVaultKeyV1 } from "./key-wrapping";
import type { WrappedSigningKeyV1 } from "./signing-recovery";
import { isValidVaultLookupIdForTests } from "./recovery-bootstrap";

const vaultIdPattern = /^[A-Za-z0-9_-]{22}$/;
const entryIdPattern = /^[A-Za-z0-9_-]{16,128}$/;
const b64pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const maxCiphertextCharacters = 1_500_000;
const maxEntries = 1000;

export type EncryptedStoredEntry = Readonly<{
  entryId: string;
  revision: number;
  ciphertext: EncryptedEntryV1;
}>;

export type SyntheticVaultBackup = Readonly<{
  vaultId: string;
  wrappedDataKey: WrappedVaultKeyV1;
  wrappedSigningKey: WrappedSigningKeyV1;
  verificationKey: JsonWebKey;
}>;

type Vault = {
  backup: SyntheticVaultBackup;
  verifierKey: CryptoKey;
  entries: EncryptedStoredEntry[];
};

function validateBackup(backup: SyntheticVaultBackup): void {
  if (!backup || !vaultIdPattern.test(backup.vaultId) ||
      backup.wrappedDataKey?.version !== 1 ||
      backup.wrappedDataKey?.vaultId !== backup.vaultId ||
      backup.wrappedSigningKey?.version !== 1 ||
      backup.wrappedSigningKey?.vaultId !== backup.vaultId ||
      backup.wrappedDataKey.algorithm !== "HKDF-SHA-256+A256GCM" ||
      backup.wrappedSigningKey.algorithm !== "HKDF-SHA-256+A256GCM-PKCS8-P256") {
    throw new Error("Invalid encrypted vault backup.");
  }
  if (JSON.stringify(backup).length > 4096) {
    throw new Error("Vault backup is too large.");
  }
  // The signing envelope's public key must match the registered verification key.
  const a = backup.verificationKey;
  const b = backup.wrappedSigningKey.publicKey;
  if (!a || !b || a.kty !== "EC" || a.crv !== "P-256" ||
      a.x !== b.x || a.y !== b.y ||
      a.d !== undefined || b.d !== undefined) {
    throw new Error("Mismatched public verification key.");
  }
}

function validateCiphertext(input: EncryptedEntryV1): void {
  if (!input || input.version !== 1 || input.algorithm !== "AES-256-GCM" ||
      typeof input.iv !== "string" || typeof input.ciphertext !== "string" ||
      input.iv.length !== 16 || !b64pattern.test(input.iv) ||
      input.ciphertext.length < 24 ||
      input.ciphertext.length > maxCiphertextCharacters ||
      !b64pattern.test(input.ciphertext)) {
    throw new Error("Invalid encrypted entry.");
  }
  if (atob(input.iv).length !== 12 || atob(input.ciphertext).length < 16) {
    throw new Error("Invalid encrypted entry.");
  }
}

function snapshot<T>(value: T): T {
  // Prevent a caller mutating the in-memory store by retaining object references.
  return JSON.parse(JSON.stringify(value)) as T;
}

export class SyntheticVaultStoreForTests {
  private readonly vaults = new Map<string, Vault>();
  private readonly lookupIndex = new Map<string, string>();
  private readonly challenges = new InMemoryProofVerifierForTests();

  /**
   * Registration challenge is requested without a vault lookup.
   * The proof-of-possession is verified against the public key being enrolled.
   * This is NOT a fully authenticated or race-safe registration protocol.
   */
  issueRegistrationChallenge(vaultId: string, now: number): ProofChallengeV1 {
    if (!vaultIdPattern.test(vaultId)) throw new Error("Invalid vault identifier.");
    const challenge = issueChallengeForTests(vaultId, "append", now);
    this.challenges.register(challenge);
    return challenge;
  }

  async register(
    backup: SyntheticVaultBackup, proof: SignedProofV1, now: number,
    lookupId?: string
  ): Promise<void> {
    validateBackup(backup);
    if (lookupId !== undefined && !isValidVaultLookupIdForTests(lookupId)) {
      throw new Error("Invalid recovery lookup identifier.");
    }
    const verificationKey = await importVerificationKeyForTests(backup.verificationKey);
    if (!await this.challenges.verify(proof, verificationKey, backup.vaultId, "append", now)) {
      throw new Error("Registration authorization denied.");
    }
    if (this.vaults.has(backup.vaultId)) throw new Error("Vault already registered.");
    if (lookupId && this.lookupIndex.has(lookupId)) {
      throw new Error("Recovery identifier already registered.");
    }
    this.vaults.set(backup.vaultId, {
      backup: snapshot(backup), verifierKey: verificationKey, entries: []
    });
    if (lookupId) this.lookupIndex.set(lookupId, backup.vaultId);
  }

  /**
   * Unauthenticated recovery bootstrap: returns ONLY public metadata and
   * encrypted key backups. It never returns encrypted entries, access tokens,
   * signed proofs, private keys, or plaintext.
   *
   * A production implementation must mitigate metadata enumeration and abuse.
   */
  lookupEncryptedRecoveryPackage(lookupId: string): SyntheticVaultBackup | null {
    if (!isValidVaultLookupIdForTests(lookupId)) {
      throw new Error("Invalid recovery lookup identifier.");
    }
    const vaultId = this.lookupIndex.get(lookupId);
    const vault = vaultId === undefined ? undefined : this.vaults.get(vaultId);
    return vault ? snapshot(vault.backup) : null;
  }

  issueActionChallenge(vaultId: string, action: VaultAction, now: number): ProofChallengeV1 {
    if (!vaultIdPattern.test(vaultId)) throw new Error("Invalid vault identifier.");
    const challenge = issueChallengeForTests(vaultId, action, now);
    this.challenges.register(challenge);
    return challenge;
  }

  private async authorize(
    vaultId: string, action: VaultAction, proof: SignedProofV1, now: number
  ): Promise<Vault> {
    const vault = this.vaults.get(vaultId);
    if (!vault || !await this.challenges.verify(
      proof, vault.verifierKey, vaultId, action, now
    )) {
      throw new Error("Vault access denied.");
    }
    return vault;
  }

  async getBackup(
    vaultId: string, proof: SignedProofV1, now: number
  ): Promise<SyntheticVaultBackup> {
    const vault = await this.authorize(vaultId, "read", proof, now);
    return snapshot(vault.backup);
  }

  async readEntries(
    vaultId: string, proof: SignedProofV1, now: number
  ): Promise<ReadonlyArray<EncryptedStoredEntry>> {
    const vault = await this.authorize(vaultId, "read", proof, now);
    return snapshot(vault.entries);
  }

  async appendEntry(
    vaultId: string,
    proof: SignedProofV1,
    entry: EncryptedStoredEntry,
    now: number
  ): Promise<void> {
    const vault = await this.authorize(vaultId, "append", proof, now);
    if (!entry || !entryIdPattern.test(entry.entryId) ||
        !Number.isSafeInteger(entry.revision) ||
        entry.revision !== vault.entries.length + 1 ||
        vault.entries.length >= maxEntries ||
        vault.entries.some(existing => existing.entryId === entry.entryId)) {
      throw new Error("Invalid or conflicting entry revision.");
    }
    validateCiphertext(entry.ciphertext);
    vault.entries.push(snapshot(entry));
  }

  async exportCiphertext(
    vaultId: string, proof: SignedProofV1, now: number
  ): Promise<{ backup: SyntheticVaultBackup; entries: ReadonlyArray<EncryptedStoredEntry> }> {
    const vault = await this.authorize(vaultId, "export", proof, now);
    return snapshot({ backup: vault.backup, entries: vault.entries });
  }

  async deleteVault(
    vaultId: string, proof: SignedProofV1, now: number
  ): Promise<void> {
    await this.authorize(vaultId, "delete", proof, now);
    // In-memory test only. Production deletion requires a reviewed lifecycle,
    // backups/retention handling and audit documentation.
    this.vaults.delete(vaultId);
    for (const [lookupId, indexedVault] of this.lookupIndex) {
      if (indexedVault === vaultId) this.lookupIndex.delete(lookupId);
    }
  }
}
