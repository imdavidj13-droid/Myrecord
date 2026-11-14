/**
 * Isolated authenticated-registration intent, SYNTHETIC DATA ONLY.
 *
 * A normal challenge signature establishes possession of a signing key.
 * This separate signature binds its nonce, vault ID, recovery locator,
 * verification key and BOTH encrypted key envelopes to the enrolment.
 *
 * This is not a substitute for proving that the submitted recovery locator
 * is derived from the same entropy that unlocks the encrypted envelopes.
 * Production registration, atomicity and privacy remain unreviewed.
 */
import type { ProofChallengeV1 } from "./access-proof";
import type { SyntheticVaultBackup } from "./synthetic-vault-store";
import { isValidVaultLookupIdForTests } from "./recovery-bootstrap";

export type SignedRegistrationIntentV1 = Readonly<{
  version: 1;
  signature: string;
}>;

const domain = "mysafespace:registration-intent:v1";
const encoder = new TextEncoder();

function asBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

function encodeSignature(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeSignature(input: unknown): Uint8Array {
  if (typeof input !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(input)) {
    throw new Error("Invalid registration signature.");
  }
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const decoded = atob(normalized + "==");
  const bytes = new Uint8Array(decoded.length);
  for (let i = 0; i < decoded.length; i++) bytes[i] = decoded.charCodeAt(i);
  if (bytes.length !== 64 || encodeSignature(bytes) !== input) {
    throw new Error("Invalid registration signature.");
  }
  return bytes;
}

/** Explicit fixed-field encoding keeps object insertion order irrelevant. */
function registrationBytes(
  challenge: ProofChallengeV1, backup: SyntheticVaultBackup, lookupId: string
): ArrayBuffer {
  if (!isValidVaultLookupIdForTests(lookupId) || !backup || !challenge ||
      challenge.version !== 1 || challenge.action !== "append" ||
      backup.vaultId !== challenge.vaultId) {
    throw new Error("Invalid registration intent.");
  }
  const data = backup.wrappedDataKey;
  const signing = backup.wrappedSigningKey;
  const publicKey = backup.verificationKey;
  if (!data || !signing || !publicKey || !signing.publicKey ||
      data.vaultId !== backup.vaultId || signing.vaultId !== backup.vaultId ||
      publicKey.x !== signing.publicKey.x || publicKey.y !== signing.publicKey.y) {
    throw new Error("Mismatched registration envelope.");
  }

  const values: Array<string | number | undefined> = [
    domain, challenge.version, challenge.vaultId, challenge.action,
    challenge.nonce, challenge.issuedAt, challenge.expiresAt, lookupId,
    data.version, data.algorithm, data.vaultId, data.salt, data.iv, data.wrappedKey,
    signing.version, signing.algorithm, signing.vaultId, signing.salt,
    signing.iv, signing.wrappedPrivateKey,
    publicKey.kty, publicKey.crv, publicKey.x, publicKey.y
  ];
  if (values.some(value => (typeof value !== "string" && typeof value !== "number") ||
      (typeof value === "string" && value.length > 1000))) {
    throw new Error("Invalid registration fields.");
  }
  return asBuffer(encoder.encode(JSON.stringify(values)));
}

export async function signRegistrationIntentForTests(
  privateKey: CryptoKey,
  challenge: ProofChallengeV1,
  backup: SyntheticVaultBackup,
  lookupId: string
): Promise<SignedRegistrationIntentV1> {
  if (privateKey.type !== "private" || !privateKey.usages.includes("sign")) {
    throw new Error("Signing private key required.");
  }
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey, registrationBytes(challenge, backup, lookupId)
  );
  return { version: 1, signature: encodeSignature(new Uint8Array(signature)) };
}

export async function verifyRegistrationIntentForTests(
  publicKey: CryptoKey,
  challenge: ProofChallengeV1,
  backup: SyntheticVaultBackup,
  lookupId: string,
  intent: SignedRegistrationIntentV1
): Promise<boolean> {
  try {
    if (!intent || intent.version !== 1 || publicKey.type !== "public" ||
        !publicKey.usages.includes("verify")) return false;
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey, asBuffer(decodeSignature(intent.signature)),
      registrationBytes(challenge, backup, lookupId)
    );
  } catch {
    return false;
  }
}
