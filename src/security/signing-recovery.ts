/**
 * EXPERIMENTAL recovery of anonymous signing credentials, synthetic tests only.
 * This is not a production login, storage or vault-recovery implementation.
 * An extractable private key exists briefly during creation so Web Crypto can
 * wrap it; the returned/recovered private key is non-extractable.
 * Do not send the mnemonic or unwrapped signing key to a server.
 */
import { decodeRecoveryEntropyForTests, isValidRecoveryWords } from "./recovery";
import { importVerificationKeyForTests } from "./access-proof";

const domain = "mysafespace:signing-key-backup:v1";
const encoder = new TextEncoder();
const saltBytes = 16;
const ivBytes = 12;
const vaultIdPattern = /^[A-Za-z0-9_-]{16,128}$/;
const maxWrappedBytes = 512;

export type WrappedSigningKeyV1 = Readonly<{
  version: 1;
  algorithm: "HKDF-SHA-256+A256GCM-PKCS8-P256";
  vaultId: string;
  salt: string;
  iv: string;
  wrappedPrivateKey: string;
  publicKey: JsonWebKey;
}>;

function requireCrypto(): Crypto {
  if (!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues) {
    throw new Error("Secure Web Crypto is required.");
  }
  return globalThis.crypto;
}

function bytesBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

function base64(bytes: Uint8Array): string {
  let result = "";
  for (let i = 0; i < bytes.length; i += 0x4000) {
    result += String.fromCharCode(...bytes.subarray(i, i + 0x4000));
  }
  return btoa(result);
}

function fromBase64(encoded: unknown, maxBytes: number, exactBytes?: number): Uint8Array {
  if (typeof encoded !== "string" || encoded.length < 4 ||
      encoded.length > Math.ceil(maxBytes / 3) * 4 + 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
    throw new Error("Invalid signing-key envelope encoding.");
  }
  const decoded = atob(encoded);
  if (decoded.length > maxBytes || (exactBytes !== undefined && decoded.length !== exactBytes)) {
    throw new Error("Invalid signing-key envelope length.");
  }
  const bytes = new Uint8Array(decoded.length);
  for (let i = 0; i < decoded.length; i++) bytes[i] = decoded.charCodeAt(i);
  return bytes;
}

function validatePublicKey(key: unknown): asserts key is JsonWebKey {
  if (!key || typeof key !== "object") throw new Error("Invalid verification key.");
  const jwk = key as JsonWebKey;
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" ||
      typeof jwk.x !== "string" || typeof jwk.y !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(jwk.x) ||
      !/^[A-Za-z0-9_-]{43}$/.test(jwk.y) ||
      jwk.d !== undefined || jwk.ext === false ||
      (jwk.key_ops !== undefined && (
        jwk.key_ops.length !== 1 || jwk.key_ops[0] !== "verify"
      ))) {
    throw new Error("Invalid verification key.");
  }
}

function authenticatedContext(vaultId: string, publicKey: JsonWebKey): ArrayBuffer {
  validatePublicKey(publicKey);
  if (!vaultIdPattern.test(vaultId)) throw new Error("Invalid vault identifier.");
  // Fixed-order canonical representation. Binds the wrapped private key to the
  // public verification key and vault ID, not just the recovery words.
  return bytesBuffer(encoder.encode([domain, vaultId, publicKey.x, publicKey.y].join("\n")));
}

async function wrappingKey(phrase: string, salt: Uint8Array, vaultId: string): Promise<CryptoKey> {
  if (!isValidRecoveryWords(phrase)) throw new Error("Invalid recovery words.");
  const entropy = decodeRecoveryEntropyForTests(phrase);
  try {
    const material = await requireCrypto().subtle.importKey(
      "raw", bytesBuffer(entropy), "HKDF", false, ["deriveKey"]
    );
    return await requireCrypto().subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256",
        salt: bytesBuffer(salt),
        info: bytesBuffer(encoder.encode(domain + "\n" + vaultId)) },
      material, { name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]
    );
  } finally {
    entropy.fill(0); // best effort only; JS memory cannot be guaranteed erased
  }
}

export async function createWrappedSigningCredentialForTests(
  phrase: string, vaultId: string
): Promise<{ envelope: WrappedSigningKeyV1; privateKey: CryptoKey; publicKey: CryptoKey }> {
  if (!isValidRecoveryWords(phrase) || !vaultIdPattern.test(vaultId)) {
    throw new Error("Invalid recovery words or vault identifier.");
  }
  const crypto = requireCrypto();
  const salt = crypto.getRandomValues(new Uint8Array(saltBytes));
  const iv = crypto.getRandomValues(new Uint8Array(ivBytes));
  // Briefly extractable, for encryption. Must never be exposed to untrusted JS.
  const temporary = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]
  );
  const exported = await crypto.subtle.exportKey("jwk", temporary.publicKey);
  const publicKey: JsonWebKey = {
    kty: "EC", crv: "P-256", x: exported.x, y: exported.y, ext: true, key_ops: ["verify"]
  };
  const wrap = await wrappingKey(phrase, salt, vaultId);
  const wrapped = await crypto.subtle.wrapKey(
    "pkcs8", temporary.privateKey, wrap, {
      name: "AES-GCM", iv: bytesBuffer(iv),
      additionalData: authenticatedContext(vaultId, publicKey), tagLength: 128
    }
  );
  // Re-import the protected backup as non-extractable and return ONLY that key.
  const privateKey = await crypto.subtle.unwrapKey(
    "pkcs8", wrapped, wrap, {
      name: "AES-GCM", iv: bytesBuffer(iv),
      additionalData: authenticatedContext(vaultId, publicKey), tagLength: 128
    }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
  );
  const recoveredPublicKey = await importVerificationKeyForTests(publicKey);
  return {
    envelope: {
      version: 1, algorithm: "HKDF-SHA-256+A256GCM-PKCS8-P256",
      vaultId, salt: base64(salt), iv: base64(iv),
      wrappedPrivateKey: base64(new Uint8Array(wrapped)), publicKey
    },
    privateKey, publicKey: recoveredPublicKey
  };
}

export async function recoverSigningCredentialForTests(
  phrase: string, rawEnvelope: unknown
): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
  if (!rawEnvelope || typeof rawEnvelope !== "object") throw new Error("Invalid signing-key envelope.");
  const envelope = rawEnvelope as Partial<WrappedSigningKeyV1>;
  if (envelope.version !== 1 ||
      envelope.algorithm !== "HKDF-SHA-256+A256GCM-PKCS8-P256" ||
      typeof envelope.vaultId !== "string") {
    throw new Error("Unsupported signing-key envelope.");
  }
  validatePublicKey(envelope.publicKey);
  const context = authenticatedContext(envelope.vaultId, envelope.publicKey);
  const salt = fromBase64(envelope.salt, saltBytes, saltBytes);
  const iv = fromBase64(envelope.iv, ivBytes, ivBytes);
  const wrapped = fromBase64(envelope.wrappedPrivateKey, maxWrappedBytes);
  if (!isValidRecoveryWords(phrase)) throw new Error("Invalid recovery words.");
  const crypto = requireCrypto();
  const wrap = await wrappingKey(phrase, salt, envelope.vaultId);
  const privateKey = await crypto.subtle.unwrapKey(
    "pkcs8", bytesBuffer(wrapped), wrap,
    { name: "AES-GCM", iv: bytesBuffer(iv), additionalData: context, tagLength: 128 },
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
  );
  const publicKey = await importVerificationKeyForTests(envelope.publicKey);
  // Reject mismatched public/private key pairs rather than returning a
  // credential which looks valid but can never authenticate.
  const probe = crypto.getRandomValues(new Uint8Array(32));
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, privateKey, bytesBuffer(probe)
  );
  const matches = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, publicKey, signature, bytesBuffer(probe)
  );
  if (!matches) throw new Error("Signing key does not match verification key.");
  return { privateKey, publicKey };
}
