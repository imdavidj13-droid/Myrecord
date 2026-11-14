/**
 * Browser-only recovery-consistency preflight for SYNTHETIC TEST DATA.
 *
 * Confirms that the *supplied* recovery words derive the supplied lookup ID,
 * unwrap both encrypted key backups, and recover a signing key matching the
 * registered public key. Neither words nor unwrapped keys are returned here.
 *
 * The server CANNOT verify these relationships from public metadata alone.
 * This check is not a zero-knowledge proof and is not a server-side safeguard
 * against a malicious client or an altered client bundle.
 */
import { deriveVaultLookupIdForTests, isValidVaultLookupIdForTests } from "./recovery-bootstrap";
import { unwrapVaultKeyForTests } from "./key-wrapping";
import { recoverSigningCredentialForTests } from "./signing-recovery";
import type { SyntheticVaultBackup } from "./synthetic-vault-store";

function toBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

/**
 * Throws on any mismatch or invalid recovery phrase; never transmits data.
 * Returns only public metadata and a boolean, NOT key material or words.
 */
export async function verifyLocalRecoveryConsistencyForTests(
  recoveryPhrase: string,
  lookupId: string,
  backup: SyntheticVaultBackup
): Promise<Readonly<{ ready: true; vaultId: string; lookupId: string }>> {
  if (!isValidVaultLookupIdForTests(lookupId) ||
      !backup || typeof backup.vaultId !== "string" ||
      backup.wrappedDataKey?.vaultId !== backup.vaultId ||
      backup.wrappedSigningKey?.vaultId !== backup.vaultId) {
    throw new Error("Inconsistent vault recovery metadata.");
  }

  // Compare a fresh local derivation against the supplied, signed locator.
  const derivedLookupId = await deriveVaultLookupIdForTests(recoveryPhrase);
  if (lookupId !== derivedLookupId) throw new Error("Recovery lookup does not match the phrase.");

  const signing = await recoverSigningCredentialForTests(
    recoveryPhrase, backup.wrappedSigningKey
  );
  const dataKey = await unwrapVaultKeyForTests(
    recoveryPhrase, backup.wrappedDataKey
  );
  if (!dataKey.usages.includes("decrypt") || dataKey.extractable ||
      !signing.privateKey.usages.includes("sign") ||
      signing.privateKey.extractable ||
      signing.publicKey.type !== "public") {
    throw new Error("Recovered keys have unexpected properties.");
  }

  const supplied = backup.verificationKey;
  const embedded = backup.wrappedSigningKey.publicKey;
  if (!supplied || supplied.kty !== "EC" || supplied.crv !== "P-256" ||
      supplied.d !== undefined || supplied.x !== embedded.x || supplied.y !== embedded.y) {
    throw new Error("Verification key does not match signing-key backup.");
  }

  // Match the actual imported public key against the verification key declared
  // in the outer envelope. An attacker must not substitute that key.
  const exported = await crypto.subtle.exportKey("jwk", signing.publicKey);
  if (exported.x !== supplied.x || exported.y !== supplied.y) {
    throw new Error("Recovered signing key does not match registered verifier.");
  }

  // Test key use with a local random challenge. No application data is saved.
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, signing.privateKey, toBuffer(challenge)
  );
  if (!await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, signing.publicKey,
    signature, toBuffer(challenge)
  )) {
    throw new Error("Recovered signing credential failed local verification.");
  }

  return { ready: true, vaultId: backup.vaultId, lookupId };
}
