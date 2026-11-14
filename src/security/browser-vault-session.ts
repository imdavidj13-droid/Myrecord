/**
 * SYNTHETIC TEST DATA ONLY — browser-side orchestration prototype.
 *
 * No implementation of VaultTransportForTests is shipped to the public app.
 * This module NEVER calls fetch, writes browser storage, or imports a Worker.
 * Only encrypted envelopes, an opaque lookup ID and signatures cross the
 * transport boundary. Phrase and plaintext stay within the calling browser.
 *
 * This is not a reviewed production protocol or a public writing feature.
 */
import { createWrappedVaultKeyForTests, unwrapVaultKeyForTests } from "./key-wrapping";
import { createWrappedSigningCredentialForTests, recoverSigningCredentialForTests } from "./signing-recovery";
import { deriveVaultLookupIdForTests } from "./recovery-bootstrap";
import { verifyLocalRecoveryConsistencyForTests } from "./recovery-consistency";
import { prepareRegistrationForTests } from "./prepare-registration";
import { encryptIntegrityEntryForTests, decryptIntegrityEntryForTests,
  verifyIntegrityChainForTests, GENESIS_DIGEST_FOR_TESTS,
  type IntegrityEnvelopeV2 } from "./integrity-chain";
import { signIntegrityAppendForTests } from "./d1-v2-integrity";
import { signD1ReadRequestForTests, type SignedReadRequestV1 } from "./d1-read-export";
import type { ProofChallengeV1, SignedProofV1 } from "./access-proof";
import type { SignedRegistrationIntentV1 } from "./registration-intent";
import type { SyntheticVaultBackup } from "./synthetic-vault-store";

export type EncryptedHistoryForTests = Readonly<{
  entries: ReadonlyArray<IntegrityEnvelopeV2>;
  latestRevision: number;
  headDigest: string;
}>;

export interface VaultTransportForTests {
  issueRegistrationChallenge(vaultId: string): Promise<ProofChallengeV1>;
  register(input: Readonly<{
    backup: SyntheticVaultBackup;
    lookupId: string;
    proof: SignedProofV1;
    intent: SignedRegistrationIntentV1;
  }>): Promise<void>;
  // An unauthenticated lookup must return only encrypted backup metadata.
  lookup(lookupId: string): Promise<SyntheticVaultBackup | null>;
  issueReadChallenge(vaultId: string, action: "read" | "export"): Promise<ProofChallengeV1>;
  read(input: Readonly<{
    vaultId: string;
    action: "read" | "export";
    challenge: ProofChallengeV1;
    proof: SignedReadRequestV1;
  }>): Promise<EncryptedHistoryForTests>;
  issueAppendChallenge(envelope: IntegrityEnvelopeV2): Promise<ProofChallengeV1>;
  append(input: Readonly<{
    envelope: IntegrityEnvelopeV2;
    challenge: ProofChallengeV1;
    proof: Readonly<{ version: 2; signature: string }>;
  }>): Promise<void>;
}

export type PlaintextEntryForTests = Readonly<{
  entryId: string;
  revision: number;
  text: string;
}>;
export type RecoveredHistoryForTests = Readonly<{
  entries: ReadonlyArray<PlaintextEntryForTests>;
  latestRevision: number;
  headDigest: string;
}>;

const idBytes = 16;
function randomEntryId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(idBytes));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-")
    .replace(/\//g, "_").replace(/=+$/, "");
}

export class BrowserVaultSessionForTests {
  // Keep the strongest previously observed head inside this session. This
  // guards against rollback or substitution during the same browser session.
  // Cross-device and cross-session anchoring still require a separate trust
  // mechanism that a backend operator cannot rewrite.
  private observedRevision = 0;
  private observedHead = GENESIS_DIGEST_FOR_TESTS;
  // Keys are intentionally non-extractable WebCrypto objects. A page reload
  // drops these references; restoration requires the recovery phrase.
  private constructor(
    private readonly transport: VaultTransportForTests,
    private readonly vaultId: string,
    private readonly dataKey: CryptoKey,
    private readonly signingKey: CryptoKey
  ) {}

  static async register(
    transport: VaultTransportForTests, recoveryPhrase: string
  ): Promise<BrowserVaultSessionForTests> {
    const data = await createWrappedVaultKeyForTests(recoveryPhrase);
    const signing = await createWrappedSigningCredentialForTests(
      recoveryPhrase, data.envelope.vaultId
    );
    const backup: SyntheticVaultBackup = {
      vaultId: data.envelope.vaultId,
      wrappedDataKey: data.envelope,
      wrappedSigningKey: signing.envelope,
      verificationKey: signing.envelope.publicKey
    };
    const lookupId = await deriveVaultLookupIdForTests(recoveryPhrase);
    const challenge = await transport.issueRegistrationChallenge(backup.vaultId);
    const prepared = await prepareRegistrationForTests(
      recoveryPhrase, lookupId, backup, challenge
    );
    await transport.register(prepared);
    return new BrowserVaultSessionForTests(
      transport, backup.vaultId, data.key, signing.privateKey
    );
  }

  static async recover(
    transport: VaultTransportForTests, recoveryPhrase: string,
    previouslyTrustedHead?: string
  ): Promise<BrowserVaultSessionForTests> {
    const lookupId = await deriveVaultLookupIdForTests(recoveryPhrase);
    const backup = await transport.lookup(lookupId);
    if (!backup) throw new Error("No encrypted vault found for these recovery words.");
    await verifyLocalRecoveryConsistencyForTests(recoveryPhrase, lookupId, backup);
    const dataKey = await unwrapVaultKeyForTests(recoveryPhrase, backup.wrappedDataKey);
    const recovered = await recoverSigningCredentialForTests(
      recoveryPhrase, backup.wrappedSigningKey
    );
    const session = new BrowserVaultSessionForTests(
      transport, backup.vaultId, dataKey, recovered.privateKey
    );
    // Even a valid key cannot accept a suppressed history when the caller
    // possesses an independently trusted previous chain head.
    await session.read(previouslyTrustedHead);
    return session;
  }

  async read(previouslyTrustedHead?: string): Promise<RecoveredHistoryForTests> {
    return this.retrieve("read", previouslyTrustedHead);
  }

  async export(previouslyTrustedHead?: string): Promise<RecoveredHistoryForTests> {
    return this.retrieve("export", previouslyTrustedHead);
  }

  private async retrieve(
    action: "read" | "export", previouslyTrustedHead?: string
  ): Promise<RecoveredHistoryForTests> {
    const challenge = await this.transport.issueReadChallenge(this.vaultId, action);
    if (challenge.action !== action || challenge.vaultId !== this.vaultId) {
      throw new Error("Untrusted read challenge.");
    }
    const proof = await signD1ReadRequestForTests(this.signingKey, challenge, action, 0);
    const history = await this.transport.read({
      vaultId: this.vaultId, action, challenge, proof
    });
    if (!history || !Number.isSafeInteger(history.latestRevision) ||
        history.latestRevision < 0 ||
        history.entries.length !== history.latestRevision) {
      throw new Error("Incomplete encrypted vault history.");
    }
    if (history.entries.some(entry => entry.vaultId !== this.vaultId)) {
      throw new Error("Encrypted history belongs to another vault.");
    }
    const verified = await verifyIntegrityChainForTests(
      history.entries, previouslyTrustedHead
    );
    if (verified.revision !== history.latestRevision ||
        verified.headDigest !== history.headDigest) {
      throw new Error("Encrypted history head mismatch.");
    }
    // Enforce this session's previously observed authenticated history
    // even if the caller does not supply a separate trust anchor.
    if (history.entries.length < this.observedRevision ||
        (this.observedRevision > 0 &&
          history.entries[this.observedRevision - 1]?.digest !== this.observedHead)) {
      throw new Error("Encrypted history was rolled back or replaced.");
    }
    // Decryption authenticates the AES-GCM AAD as well as the digest chain.
    // No plaintext is passed to VaultTransportForTests.
    const entries: PlaintextEntryForTests[] = [];
    for (const envelope of history.entries) {
      entries.push({
        entryId: envelope.entryId,
        revision: envelope.revision,
        text: await decryptIntegrityEntryForTests(this.dataKey, envelope)
      });
    }
    this.observedRevision = verified.revision;
    this.observedHead = verified.headDigest;
    return {entries, latestRevision: verified.revision, headDigest: verified.headDigest};
  }

  async appendSyntheticText(text: string): Promise<RecoveredHistoryForTests> {
    if (typeof text !== "string" || !text.trim()) throw new Error("Empty entry.");
    const current = await this.read();
    const envelope = await encryptIntegrityEntryForTests(
      this.dataKey, text, this.vaultId, randomEntryId(),
      current.latestRevision + 1,
      current.latestRevision === 0 ? GENESIS_DIGEST_FOR_TESTS : current.headDigest
    );
    const challenge = await this.transport.issueAppendChallenge(envelope);
    if (challenge.action !== "append" || challenge.vaultId !== this.vaultId) {
      throw new Error("Untrusted append challenge.");
    }
    const proof = await signIntegrityAppendForTests(
      this.signingKey, challenge, envelope
    );
    await this.transport.append({envelope,challenge,proof});
    const updated = await this.read();
    // Verify the server did not acknowledge while suppressing our record.
    if (updated.latestRevision !== envelope.revision ||
        updated.headDigest !== envelope.digest) {
      throw new Error("Stored ciphertext did not match the append confirmation.");
    }
    return updated;
  }
}
