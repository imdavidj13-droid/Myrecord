/**
 * EXPERIMENTAL KEY WRAPPING for FICTIONAL DATA ONLY.
 *
 * This is NOT a deployed vault protocol or a server-authentication mechanism.
 * Independent protocol review is mandatory before connecting it to user input.
 * Recovery words and unwrapped keys MUST NEVER be sent to a server.
 */
import { decodeRecoveryEntropyForTests, isValidRecoveryWords } from "./recovery";

const textEncoder = new TextEncoder();
const MAX_B64 = 128;
const WRAP_DOMAIN = "mysafespace:vault-key-wrap:v1";
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;
const ID_LENGTH = 16;
const IV_LENGTH = 12;

export type WrappedVaultKeyV1 = Readonly<{
  version: 1;
  algorithm: "HKDF-SHA-256+A256GCM";
  vaultId: string;
  salt: string;
  iv: string;
  wrappedKey: string;
}>;

function cryptoApi(): Crypto {
  if (!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues) {
    throw new Error("Secure browser cryptography is required.");
  }
  return globalThis.crypto;
}
function buffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}
function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}
function fromBase64(value: unknown, expectedLength: number): Uint8Array {
  if (typeof value !== "string" || value.length > MAX_B64 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error("Malformed wrapped key.");
  }
  const decoded = atob(value);
  if (decoded.length !== expectedLength) throw new Error("Malformed wrapped key.");
  const bytes = new Uint8Array(decoded.length);
  for (let i = 0; i < decoded.length; i++) bytes[i] = decoded.charCodeAt(i);
  return bytes;
}

async function deriveWrappingKey(phrase: string, salt: Uint8Array, vaultId: Uint8Array): Promise<CryptoKey> {
  if (!isValidRecoveryWords(phrase)) throw new Error("Invalid recovery words.");
  // High-entropy BIP39 source bits, not a human-chosen password.
  // HKDF uses distinct salt and info to isolate this application context.
  const entropy = decodeRecoveryEntropyForTests(phrase);
  try {
    const material = await cryptoApi().subtle.importKey(
      "raw", buffer(entropy), "HKDF", false, ["deriveKey"]
    );
    return await cryptoApi().subtle.deriveKey(
      {
        name: "HKDF", hash: "SHA-256", salt: buffer(salt),
        info: buffer(textEncoder.encode(WRAP_DOMAIN + ":" + toBase64(vaultId)))
      },
      material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  } finally {
    // Best effort: JS engines and Web Crypto may retain copies we cannot erase.
    entropy.fill(0);
  }
}

function additionalData(vaultId: Uint8Array): ArrayBuffer {
  return buffer(textEncoder.encode(WRAP_DOMAIN + ":" + toBase64(vaultId)));
}

/** Creates a new in-memory non-extractable data key and its encrypted envelope. */
export async function createWrappedVaultKeyForTests(
  recoveryPhrase: string,
): Promise<{ envelope: WrappedVaultKeyV1; key: CryptoKey }> {
  const api = cryptoApi();
  if (!isValidRecoveryWords(recoveryPhrase)) throw new Error("Invalid recovery words.");
  const vaultId = api.getRandomValues(new Uint8Array(ID_LENGTH));
  const salt = api.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = api.getRandomValues(new Uint8Array(IV_LENGTH));
  const rawKey = api.getRandomValues(new Uint8Array(KEY_LENGTH));
  try {
    const wrappingKey = await deriveWrappingKey(recoveryPhrase, salt, vaultId);
    const ciphertext = await api.subtle.encrypt(
      { name: "AES-GCM", iv: buffer(iv), additionalData: additionalData(vaultId), tagLength: 128 },
      wrappingKey, buffer(rawKey)
    );
    const key = await api.subtle.importKey(
      "raw", buffer(rawKey), { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
    return {
      envelope: {
        version: 1, algorithm: "HKDF-SHA-256+A256GCM",
        vaultId: toBase64(vaultId), salt: toBase64(salt),
        iv: toBase64(iv), wrappedKey: toBase64(new Uint8Array(ciphertext))
      },
      key
    };
  } finally {
    rawKey.fill(0);
  }
}

/** Recovers the non-extractable key in-memory after authenticating the envelope. */
export async function unwrapVaultKeyForTests(
  recoveryPhrase: string, envelope: unknown
): Promise<CryptoKey> {
  const api = cryptoApi();
  if (!envelope || typeof envelope !== "object") throw new Error("Unsupported key envelope.");
  const candidate = envelope as Partial<WrappedVaultKeyV1>;
  if (candidate.version !== 1 || candidate.algorithm !== "HKDF-SHA-256+A256GCM") {
    throw new Error("Unsupported key envelope.");
  }
  const vaultId = fromBase64(candidate.vaultId, ID_LENGTH);
  const salt = fromBase64(candidate.salt, SALT_LENGTH);
  const iv = fromBase64(candidate.iv, IV_LENGTH);
  const wrappedKey = fromBase64(candidate.wrappedKey, KEY_LENGTH + 16);
  const wrappingKey = await deriveWrappingKey(recoveryPhrase, salt, vaultId);
  const raw = new Uint8Array(await api.subtle.decrypt(
    { name: "AES-GCM", iv: buffer(iv), additionalData: additionalData(vaultId), tagLength: 128 },
    wrappingKey, buffer(wrappedKey)
  ));
  try {
    if (raw.length !== KEY_LENGTH) throw new Error("Unexpected decrypted key length.");
    return await api.subtle.importKey(
      "raw", buffer(raw), { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  } finally {
    raw.fill(0);
  }
}
