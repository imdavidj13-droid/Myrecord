/**
 * Isolated recovery-word encoding experiment. Not connected to a vault or UI.
 * Only test data must be used until an independently reviewed protocol exists.
 *
 * BIP39 encodes 128 bits of CSPRNG entropy as 12 English words including a
 * checksum. This module provides word generation and validation ONLY.
 *
 * Never log, transmit, store, derive a server token from, or put a phrase
 * into a URL. A phrase is a *secret*, not an account identifier.
 */
import { generateMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

export const RECOVERY_WORD_COUNT = 12;
export const RECOVERY_ENTROPY_BITS = 128;

export function normalizeRecoveryWords(input: string): string {
  if (typeof input !== "string") throw new TypeError("Recovery words must be text.");
  // BIP39 English words are ASCII. Normalize pasted whitespace and case only.
  return input.trim().toLowerCase().replace(/\s+/g, " ");
}

export function generateRecoveryWords(): string {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("Secure randomness unavailable.");
  }
  return generateMnemonic(wordlist, RECOVERY_ENTROPY_BITS);
}

export function isValidRecoveryWords(input: string): boolean {
  if (typeof input !== "string") return false;
  const normalized = normalizeRecoveryWords(input);
  if (normalized.split(" ").length !== RECOVERY_WORD_COUNT) return false;
  return validateMnemonic(normalized, wordlist);
}

/**
 * Returns the source entropy for testing round trips, NOT a usable vault key.
 * Avoid exporting entropy or using it directly as AES encryption key material.
 */
export function decodeRecoveryEntropyForTests(input: string): Uint8Array {
  const normalized = normalizeRecoveryWords(input);
  if (!isValidRecoveryWords(normalized)) throw new Error("Invalid recovery phrase.");
  const entropy = mnemonicToEntropy(normalized, wordlist);
  if (entropy.length !== 16) throw new Error("Unexpected recovery entropy length.");
  return Uint8Array.from(entropy);
}
