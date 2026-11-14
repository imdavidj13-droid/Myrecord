/**
 * Experimental, browser-only cryptographic primitive for synthetic test data.
 *
 * NOT a vault protocol. It does not implement recovery words, key wrapping,
 * authentication, persistence, backups, audit logs or evidence integrity history.
 * Never use this alone to hold real survivor testimony.
 */
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const CONTEXT = encoder.encode("mysafespace:written-entry:v1");
const MAX_PLAINTEXT_BYTES = 1024 * 1024;
const MAX_CIPHERTEXT_BYTES = MAX_PLAINTEXT_BYTES + 16;
const IV_LENGTH = 12;

export type EncryptedEntryV1 = Readonly<{
  version: 1;
  algorithm: "AES-256-GCM";
  iv: string;
  ciphertext: string;
}>;

function requireCrypto(): SubtleCrypto {
  if (!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues) {
    throw new Error("Secure browser cryptography is not available.");
  }
  return globalThis.crypto.subtle;
}

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  // Copies the bytes into a standalone ArrayBuffer, avoiding shared buffers.
  return Uint8Array.from(bytes).buffer;
}

function encodeBase64(bytes: Uint8Array): string {
  // Avoid spreading an arbitrarily large array into a single function call.
  const chunk = 0x4000;
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunk));
  }
  return btoa(binary);
}

function decodeBase64(input: string, maxBytes: number): Uint8Array {
  if (typeof input !== "string" || !input || input.length > Math.ceil(maxBytes / 3) * 4 + 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(input)) {
    throw new Error("Invalid encrypted entry encoding.");
  }
  const binary = atob(input);
  if (binary.length > maxBytes) throw new Error("Encrypted entry exceeds size limit.");
  const result = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) result[i] = binary.charCodeAt(i);
  return result;
}

export async function generateTransientEntryKey(): Promise<CryptoKey> {
  const subtle = requireCrypto();
  return subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export async function encryptSyntheticEntry(
  key: CryptoKey,
  text: string,
): Promise<EncryptedEntryV1> {
  const subtle = requireCrypto();
  const plaintext = encoder.encode(text);
  if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new Error("Entry exceeds size limit.");
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertext = await subtle.encrypt(
    { name: "AES-GCM", iv: arrayBuffer(iv), additionalData: arrayBuffer(CONTEXT), tagLength: 128 },
    key,
    arrayBuffer(plaintext),
  );
  return {
    version: 1,
    algorithm: "AES-256-GCM",
    iv: encodeBase64(iv),
    ciphertext: encodeBase64(new Uint8Array(ciphertext)),
  };
}

export async function decryptSyntheticEntry(
  key: CryptoKey,
  input: unknown,
): Promise<string> {
  const subtle = requireCrypto();
  if (!input || typeof input !== "object") throw new Error("Unsupported encrypted entry.");
  const payload = input as Partial<EncryptedEntryV1>;
  if (payload.version !== 1 || payload.algorithm !== "AES-256-GCM") {
    throw new Error("Unsupported encrypted entry version.");
  }
  const iv = decodeBase64(payload.iv as string, IV_LENGTH);
  const ciphertext = decodeBase64(payload.ciphertext as string, MAX_CIPHERTEXT_BYTES);
  if (iv.length !== IV_LENGTH || ciphertext.length < 16) {
    throw new Error("Invalid encrypted entry.");
  }
  // Web Crypto rejects an altered ciphertext, tag, IV, context, or incorrect key.
  const plaintext = await subtle.decrypt(
    { name: "AES-GCM", iv: arrayBuffer(iv), additionalData: arrayBuffer(CONTEXT), tagLength: 128 },
    key,
    arrayBuffer(ciphertext),
  );
  return decoder.decode(plaintext);
}
