/**
 * Test-only D1 append transaction adapter. NOT wired to Workers or live users.
 *
 * Assumptions: schema in docs/D1_TRANSACTIONAL_PROTOTYPE.sql has been
 * separately installed in a dedicated synthetic test database.
 *
 * Proof signatures authenticate the exact append request (vault, nonce,
 * entry ID, revision, ciphertext envelope), not just an action label.
 * D1 batch([claim nonce, insert entry]) is all-or-nothing. The schema's
 * BEFORE/AFTER INSERT triggers atomically validate/advance revision.
 */
import type { EncryptedStoredEntry } from "./synthetic-vault-store";
import type { ProofChallengeV1 } from "./access-proof";
import { importVerificationKeyForTests, issueChallengeForTests } from "./access-proof";

export interface PrototypeD1Statement {
  bind(...args: Array<string | number>): PrototypeD1Statement;
  first<T>(): Promise<T | null>;
  run(): Promise<unknown>;
}
export interface PrototypeD1Database {
  prepare(query: string): PrototypeD1Statement;
  batch(statements: PrototypeD1Statement[]): Promise<unknown>;
}

export type BoundAppendProofV1 = Readonly<{
  version: 1;
  signature: string;
}>;

const encoder = new TextEncoder();
const vaultPattern = /^[A-Za-z0-9_-]{22}$/;
const entryPattern = /^[A-Za-z0-9_-]{16,128}$/;
const noncePattern = /^[A-Za-z0-9_-]{43}$/;
const b64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function bytes(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

function signatureBase64(bytesValue: Uint8Array): string {
  return btoa(String.fromCharCode(...bytesValue))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeSignature(value: unknown): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(value)) {
    throw new Error("Malformed append signature.");
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(normalized + "==");
  const result = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) result[i] = raw.charCodeAt(i);
  if (result.length !== 64 || signatureBase64(result) !== value) {
    throw new Error("Malformed append signature.");
  }
  return result;
}

function validate(challenge: ProofChallengeV1, entry: EncryptedStoredEntry): void {
  if (!challenge || challenge.version !== 1 || challenge.action !== "append" ||
      !vaultPattern.test(challenge.vaultId) || !noncePattern.test(challenge.nonce) ||
      !Number.isSafeInteger(challenge.issuedAt) ||
      !Number.isSafeInteger(challenge.expiresAt) ||
      challenge.expiresAt <= challenge.issuedAt ||
      challenge.expiresAt - challenge.issuedAt > 60_000 ||
      !entry || !entryPattern.test(entry.entryId) ||
      !Number.isSafeInteger(entry.revision) || entry.revision < 1 ||
      entry.ciphertext?.version !== 1 || entry.ciphertext.algorithm !== "AES-256-GCM" ||
      typeof entry.ciphertext.iv !== "string" ||
      typeof entry.ciphertext.ciphertext !== "string" ||
      entry.ciphertext.iv.length !== 16 ||
      !b64.test(entry.ciphertext.iv) ||
      entry.ciphertext.ciphertext.length < 24 ||
      entry.ciphertext.ciphertext.length > 1_500_000 ||
      !b64.test(entry.ciphertext.ciphertext)) {
    throw new Error("Invalid append request.");
  }
}

function canonicalAppendBytes(
  challenge: ProofChallengeV1, entry: EncryptedStoredEntry
): ArrayBuffer {
  validate(challenge, entry);
  return bytes(encoder.encode(JSON.stringify([
    "mysafespace:d1-append-intent:v1",
    challenge.version, challenge.vaultId, challenge.action,
    challenge.nonce, challenge.issuedAt, challenge.expiresAt,
    entry.entryId, entry.revision,
    entry.ciphertext.version, entry.ciphertext.algorithm,
    entry.ciphertext.iv, entry.ciphertext.ciphertext
  ])));
}

export async function digestAppendIntentForTests(
  challenge: ProofChallengeV1, entry: EncryptedStoredEntry
): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", canonicalAppendBytes(challenge, entry));
  return signatureBase64(new Uint8Array(hash));
}

export async function signBoundAppendForTests(
  key: CryptoKey, challenge: ProofChallengeV1, entry: EncryptedStoredEntry
): Promise<BoundAppendProofV1> {
  if (key.type !== "private" || !key.usages.includes("sign")) {
    throw new Error("Missing private signing key.");
  }
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key, canonicalAppendBytes(challenge, entry)
  );
  return { version: 1, signature: signatureBase64(new Uint8Array(signature)) };
}

export async function verifyBoundAppendForTests(
  key: CryptoKey, challenge: ProofChallengeV1,
  entry: EncryptedStoredEntry, proof: BoundAppendProofV1
): Promise<boolean> {
  try {
    if (key.type !== "public" || !key.usages.includes("verify") ||
        !proof || proof.version !== 1) return false;
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" }, key,
      bytes(decodeSignature(proof.signature)), canonicalAppendBytes(challenge, entry)
    );
  } catch {
    return false;
  }
}

/**
 * Test-only server challenge issuance. The plaintext recovery phrase is never
 * accepted. It records the SHA-256 digest of the exact proposed ciphertext
 * append request, binding later proof verification to this payload.
 *
 * The caller must enforce abuse/rate limits before this function is deployed.
 */
export async function issueBoundAppendChallengeD1ForTests(
  db: PrototypeD1Database,
  vaultId: string,
  entry: EncryptedStoredEntry,
  now: number
): Promise<ProofChallengeV1> {
  if (!Number.isSafeInteger(now)) throw new Error("Invalid challenge time.");
  const challenge = issueChallengeForTests(vaultId, "append", now);
  const digest = await digestAppendIntentForTests(challenge, entry);
  await db.prepare(`
    INSERT INTO sandbox_challenges(nonce, vault_id, action, issued_ms, expires_ms, request_digest)
    SELECT ?, vault_id, 'append', ?, ?, ? FROM sandbox_vaults
    WHERE vault_id = ? AND status = 'active'
  `).bind(
    challenge.nonce, challenge.issuedAt, challenge.expiresAt,
    digest, challenge.vaultId
  ).run();
  // Production MUST verify exactly one challenge was inserted. SQL SELECT
  // can silently insert 0 rows if the vault is missing; never advertise
  // this method as production-ready without checking run().meta.changes.
  return challenge;
}

/**
 * Only called by a trusted server after public verification key retrieval and
 * proof validation. The challenge must already exist in D1, with digest bound
 * to the exact append request. All checks are re-evaluated inside the SQL
 * INSERT SELECT before claiming the nonce.
 *
 * This function never accepts recovery words or plaintext.
 */
export async function appendCiphertextD1ForTests(
  db: PrototypeD1Database,
  challenge: ProofChallengeV1,
  entry: EncryptedStoredEntry,
  proof: BoundAppendProofV1,
  now: number
): Promise<void> {
  validate(challenge, entry);
  if (!Number.isSafeInteger(now) || now < challenge.issuedAt - 5000 ||
      now >= challenge.expiresAt) throw new Error("Expired append authorization.");
  // Load the trusted registered key from D1, never accept it from the request.
  const registered = await db.prepare(
    "SELECT verification_jwk FROM sandbox_vaults WHERE vault_id = ? AND status = 'active'"
  ).bind(challenge.vaultId).first<{ verification_jwk: string }>();
  if (!registered || typeof registered.verification_jwk !== "string" ||
      registered.verification_jwk.length > 2048) {
    throw new Error("Unknown or disabled vault.");
  }
  let verifier: CryptoKey;
  try {
    verifier = await importVerificationKeyForTests(
      JSON.parse(registered.verification_jwk) as JsonWebKey
    );
  } catch {
    throw new Error("Invalid registered verification key.");
  }
  if (!await verifyBoundAppendForTests(verifier, challenge, entry, proof)) {
    throw new Error("Invalid append authorization.");
  }
  const requestDigest = await digestAppendIntentForTests(challenge, entry);
  // The COALESCE(...) forces NOT NULL failure if no matching challenge exists.
  // The unique nonce constraint makes replay fail. D1 batch rolls back
  // consumption if the append trigger rejects an incorrect revision.
  const claim = db.prepare(`
    INSERT INTO sandbox_consumed_nonces(nonce, consumed_ms)
    VALUES (
      (SELECT nonce FROM sandbox_challenges
       WHERE nonce = ? AND vault_id = ? AND action = 'append'
         AND issued_ms = ? AND expires_ms = ? AND request_digest = ?
         AND issued_ms <= ? AND expires_ms > ?),
      ?
    )
  `).bind(
    challenge.nonce, challenge.vaultId, challenge.issuedAt,
    challenge.expiresAt, requestDigest, now + 5000, now, now
  );
  const insert = db.prepare(`
    INSERT INTO sandbox_entries(entry_id, vault_id, revision, encrypted_envelope_json, server_received_ms)
    VALUES (?, ?, ?, ?, ?)
  `).bind(
    entry.entryId, challenge.vaultId, entry.revision,
    JSON.stringify(entry.ciphertext), now
  );
  await db.batch([claim, insert]);
}
