/**
 * TEST-ONLY signed deletion request and transactional D1 tombstone.
 *
 * This marks an active vault as deletion_pending; it DOES NOT erase records,
 * backups or provider snapshots. Retention, legal obligations, physical
 * deletion, audit receipts and recovery/appeal policy require independent
 * review. No live API handlers call this module.
 */
import { importVerificationKeyForTests, issueChallengeForTests, type ProofChallengeV1 } from "./access-proof";
import type { PrototypeD1Database } from "./d1-transaction";

const encoder = new TextEncoder();
const vaultPattern = /^[A-Za-z0-9_-]{22}$/;
const noncePattern = /^[A-Za-z0-9_-]{43}$/;
const signaturePattern = /^[A-Za-z0-9_-]{86}$/;

export type DeleteIntentV1 = Readonly<{ version: 1; signature: string }>;

function buffer(data: Uint8Array): ArrayBuffer {
  return Uint8Array.from(data).buffer;
}
function b64url(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function decodeSignature(raw: string): ArrayBuffer {
  if (typeof raw !== "string" || !signaturePattern.test(raw)) {
    throw new Error("Invalid deletion signature.");
  }
  const normalized = raw.replace(/-/g, "+").replace(/_/g, "/") + "==";
  const binary = atob(normalized);
  const data = Uint8Array.from(Array.from(binary, char => char.charCodeAt(0)));
  if (data.length !== 64 || b64url(data) !== raw) throw new Error("Invalid deletion signature.");
  return buffer(data);
}
function deletionPayload(challenge: ProofChallengeV1): ArrayBuffer {
  if (!challenge || challenge.version !== 1 || challenge.action !== "delete" ||
      !vaultPattern.test(challenge.vaultId) || !noncePattern.test(challenge.nonce) ||
      !Number.isSafeInteger(challenge.issuedAt) ||
      !Number.isSafeInteger(challenge.expiresAt) ||
      challenge.expiresAt <= challenge.issuedAt ||
      challenge.expiresAt - challenge.issuedAt > 60_000) {
    throw new Error("Invalid deletion challenge.");
  }
  return buffer(encoder.encode(JSON.stringify([
    "mysafespace:delete-request:v1", "mark-deletion-pending",
    challenge.version, challenge.vaultId, challenge.nonce,
    challenge.issuedAt, challenge.expiresAt
  ])));
}
async function digest(challenge: ProofChallengeV1): Promise<string> {
  return b64url(new Uint8Array(
    await crypto.subtle.digest("SHA-256", deletionPayload(challenge))
  ));
}

export async function signDeletionIntentForTests(
  key: CryptoKey, challenge: ProofChallengeV1
): Promise<DeleteIntentV1> {
  if (key.type !== "private" || !key.usages.includes("sign")) {
    throw new Error("Private signing key required.");
  }
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, key, deletionPayload(challenge)
  );
  return { version: 1, signature: b64url(new Uint8Array(signature)) };
}

export async function issueDeletionChallengeD1ForTests(
  db: PrototypeD1Database, vaultId: string, now: number
): Promise<ProofChallengeV1> {
  const challenge = issueChallengeForTests(vaultId, "delete", now);
  const result = await db.prepare(`
    INSERT INTO sandbox_challenges(nonce,vault_id,action,issued_ms,expires_ms,request_digest)
    SELECT ?,vault_id,'delete',?,?,? FROM sandbox_vaults
    WHERE vault_id = ? AND status = 'active'
  `).bind(challenge.nonce,challenge.issuedAt,challenge.expiresAt,
    await digest(challenge),vaultId).run() as {meta?:{changes?:number}};
  if (result?.meta?.changes !== 1) throw new Error("No active vault available.");
  return challenge;
}

export async function requestVaultDeletionD1ForTests(
  db: PrototypeD1Database,
  challenge: ProofChallengeV1,
  intent: DeleteIntentV1,
  now: number
): Promise<void> {
  deletionPayload(challenge);
  if (!Number.isSafeInteger(now) || now < challenge.issuedAt - 5000 ||
      now >= challenge.expiresAt || !intent || intent.version !== 1) {
    throw new Error("Invalid or expired deletion request.");
  }
  const registered = await db.prepare(
    "SELECT verification_jwk FROM sandbox_vaults WHERE vault_id = ? AND status = 'active'"
  ).bind(challenge.vaultId).first<{verification_jwk:string}>();
  if (!registered || typeof registered.verification_jwk !== "string" ||
      registered.verification_jwk.length > 2048) throw new Error("Vault unavailable.");
  let valid = false;
  try {
    const key = await importVerificationKeyForTests(
      JSON.parse(registered.verification_jwk) as JsonWebKey
    );
    valid = await crypto.subtle.verify(
      {name:"ECDSA",hash:"SHA-256"},key,
      decodeSignature(intent.signature),deletionPayload(challenge)
    );
  } catch {
    valid = false;
  }
  if (!valid) throw new Error("Deletion authorization denied.");

  const claim = db.prepare(`
    INSERT INTO sandbox_consumed_nonces(nonce,consumed_ms)
    VALUES ((SELECT nonce FROM sandbox_challenges
      WHERE nonce = ? AND vault_id = ? AND action = 'delete'
      AND issued_ms = ? AND expires_ms = ? AND request_digest = ?
      AND issued_ms <= ? AND expires_ms > ?),?)
  `).bind(
    challenge.nonce,challenge.vaultId,challenge.issuedAt,
    challenge.expiresAt,await digest(challenge),now+5000,now,now
  );
  // Fail if concurrent deletion has already changed the state; the nonce
  // claim is rolled back together with this check.
  const mark = db.prepare(`
    UPDATE sandbox_vaults SET status = 'deletion_pending'
    WHERE vault_id = ? AND status = 'active'
    RETURNING vault_id
  `).bind(challenge.vaultId);
  const result = await db.batch([claim,mark]) as Array<{
    success?:boolean;results?:Array<{vault_id?:string}>
  }>;
  if (!Array.isArray(result) || result.length !== 2 ||
      result[0]?.success !== true || result[1]?.success !== true ||
      result[1].results?.length !== 1 ||
      result[1].results[0]?.vault_id !== challenge.vaultId) {
    throw new Error("Deletion status transaction not confirmed.");
  }
}
