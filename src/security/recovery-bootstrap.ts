/**
 * Experimental deterministic vault discovery for synthetic tests only.
 *
 * Uses the CSPRNG-generated 128-bit BIP39 source entropy, not a memorised
 * password. The resulting identifier is a STABLE PSEUDONYM and must be
 * treated as sensitive metadata, NOT an authentication credential.
 *
 * Real API deployment requires threat review, anti-enumeration controls,
 * non-logging POST transport, abuse controls and secure client delivery.
 */
import { decodeRecoveryEntropyForTests, isValidRecoveryWords } from "./recovery";

const encoder = new TextEncoder();
const LOOKUP_SALT = encoder.encode("mysafespace:lookup-hkdf-salt:v1");
const LOOKUP_INFO = encoder.encode("mysafespace:lookup-identifier:v1");

function buffer(data: Uint8Array): ArrayBuffer {
  return Uint8Array.from(data).buffer;
}

function encodeUrlSafe(bytes: Uint8Array): string {
  // Output is always 32 bytes, so this small conversion is bounded.
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Produces a deterministic lookup ID for the same valid 12-word phrase.
 * Never send the phrase, raw entropy, or derived wrapping keys to a server.
 */
export async function deriveVaultLookupIdForTests(phrase: string): Promise<string> {
  if (!isValidRecoveryWords(phrase)) throw new Error("Invalid recovery phrase.");
  if (!globalThis.crypto?.subtle) throw new Error("Secure cryptography is unavailable.");
  const entropy = decodeRecoveryEntropyForTests(phrase);
  try {
    const material = await globalThis.crypto.subtle.importKey(
      "raw", buffer(entropy), "HKDF", false, ["deriveBits"]
    );
    const bits = await globalThis.crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: buffer(LOOKUP_SALT),
        info: buffer(LOOKUP_INFO) }, material, 256
    );
    return encodeUrlSafe(new Uint8Array(bits));
  } finally {
    // Best effort only; JS engines can retain extra copies in memory.
    entropy.fill(0);
  }
}

/** Validate the public lookup ID shape before using it as a database index. */
export function isValidVaultLookupIdForTests(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}
