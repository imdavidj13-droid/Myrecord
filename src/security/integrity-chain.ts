/**
 * Synthetic-only versioned evidence envelope experiment.
 *
 * Authenticates vault, entry ID, revision and previous digest inside AES-GCM
 * associated data, then hashes the complete authenticated envelope for a
 * forward-linked sequence. It does NOT protect against a malicious operator
 * hiding the chain head, replacing the whole chain, or rolling back D1.
 *
 * Never attach this to real testimony without independent protocol review.
 */
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const idPattern = /^[A-Za-z0-9_-]{16,128}$/;
const hexPattern = /^[0-9a-f]{64}$/;
const zeroDigest = "0".repeat(64);
const maxBytes = 1024 * 1024;

export type IntegrityEnvelopeV2 = Readonly<{
  version: 2;
  algorithm: "AES-256-GCM";
  vaultId: string;
  entryId: string;
  revision: number;
  previousDigest: string;
  iv: string;
  ciphertext: string;
  digest: string;
}>;

function bytes(input: Uint8Array): ArrayBuffer {
  return Uint8Array.from(input).buffer;
}

function encode64(value: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < value.length; i += 0x4000) {
    binary += String.fromCharCode(...value.subarray(i, i + 0x4000));
  }
  return btoa(binary);
}

function decode64(value: unknown, maximum: number): Uint8Array {
  if (typeof value !== "string" || !value ||
      value.length > Math.ceil(maximum / 3) * 4 + 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error("Invalid encrypted evidence encoding.");
  }
  const decoded = atob(value);
  if (decoded.length > maximum) throw new Error("Invalid encrypted evidence length.");
  return Uint8Array.from(Array.from(decoded, char => char.charCodeAt(0)));
}

function metadata(vaultId: string, entryId: string, revision: number, previousDigest: string): ArrayBuffer {
  if (!idPattern.test(vaultId) || !idPattern.test(entryId) ||
      !Number.isSafeInteger(revision) || revision < 1 ||
      !hexPattern.test(previousDigest) ||
      (revision === 1 && previousDigest !== zeroDigest) ||
      (revision > 1 && previousDigest === zeroDigest)) {
    throw new Error("Invalid evidence metadata.");
  }
  return bytes(encoder.encode(JSON.stringify([
    "mysafespace:written-evidence:v2", vaultId, entryId, revision, previousDigest
  ])));
}

async function calculateDigest(input: Omit<IntegrityEnvelopeV2, "digest">): Promise<string> {
  // All fields including IV and AEAD tag participate in a fixed-order digest.
  const data = encoder.encode(JSON.stringify([
    "mysafespace:envelope-digest:v2", input.version, input.algorithm,
    input.vaultId, input.entryId, input.revision, input.previousDigest,
    input.iv, input.ciphertext
  ]));
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes(data))))
    .map(byte => byte.toString(16).padStart(2, "0")).join("");
}

export async function encryptIntegrityEntryForTests(
  key: CryptoKey,
  plaintext: string,
  vaultId: string,
  entryId: string,
  revision: number,
  previousDigest: string
): Promise<IntegrityEnvelopeV2> {
  const aad = metadata(vaultId, entryId, revision, previousDigest);
  const encoded = encoder.encode(plaintext);
  if (encoded.length > maxBytes) throw new Error("Evidence entry exceeds size limit.");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    {name: "AES-GCM", iv: bytes(iv), additionalData: aad, tagLength: 128},
    key, bytes(encoded)
  );
  const envelope: Omit<IntegrityEnvelopeV2, "digest"> = {
    version: 2, algorithm: "AES-256-GCM", vaultId, entryId, revision,
    previousDigest, iv: encode64(iv), ciphertext: encode64(new Uint8Array(encrypted))
  };
  return { ...envelope, digest: await calculateDigest(envelope) };
}

export async function decryptIntegrityEntryForTests(
  key: CryptoKey,
  input: IntegrityEnvelopeV2
): Promise<string> {
  if (!input || input.version !== 2 || input.algorithm !== "AES-256-GCM") {
    throw new Error("Unsupported evidence envelope.");
  }
  const aad = metadata(input.vaultId, input.entryId, input.revision, input.previousDigest);
  const iv = decode64(input.iv, 12);
  const encrypted = decode64(input.ciphertext, maxBytes + 16);
  if (iv.length !== 12 || encrypted.length < 16 ||
      !hexPattern.test(input.digest) ||
      await calculateDigest(input) !== input.digest) {
    throw new Error("Evidence envelope integrity failure.");
  }
  const plain = await crypto.subtle.decrypt(
    {name: "AES-GCM", iv: bytes(iv), additionalData: aad, tagLength: 128},
    key, bytes(encrypted)
  );
  return decoder.decode(plain);
}

/**
 * Checks sequence order and digest continuity against a previously known
 * anchor. The caller must retain the expected head outside untrusted storage
 * to detect complete chain rollback or suppression.
 */
export async function verifyIntegrityChainForTests(
  entries: ReadonlyArray<IntegrityEnvelopeV2>,
  expectedLastDigest?: string
): Promise<{revision: number; headDigest: string}> {
  let prior = zeroDigest;
  for (let i = 0; i < entries.length; i++) {
    const current = entries[i];
    if (!current || current.revision !== i + 1 ||
        current.previousDigest !== prior ||
        !hexPattern.test(current.digest) ||
        await calculateDigest(current) !== current.digest) {
      throw new Error("Evidence history is inconsistent.");
    }
    metadata(current.vaultId, current.entryId, current.revision, current.previousDigest);
    if (i && current.vaultId !== entries[0].vaultId) {
      throw new Error("Evidence history spans multiple vaults.");
    }
    prior = current.digest;
  }
  if (expectedLastDigest !== undefined && prior !== expectedLastDigest) {
    throw new Error("Evidence history head does not match the trusted anchor.");
  }
  return { revision: entries.length, headDigest: prior };
}

export const GENESIS_DIGEST_FOR_TESTS = zeroDigest;
