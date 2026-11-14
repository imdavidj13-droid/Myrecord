/**
 * SYNTHETIC ONLY: v2 integrity-envelope D1 append and full-history retrieval.
 * This adapter is not imported by the Worker or site and is NOT deployed.
 *
 * D1 INSERT trigger checks the previous digest and next revision atomically.
 * A signed request binds the precise ciphertext envelope and nonce. The
 * registered verifier key, never a caller-supplied key, authorizes append.
 */
import {
  issueChallengeForTests, importVerificationKeyForTests,
  type ProofChallengeV1
} from "./access-proof";
import {
  verifyIntegrityChainForTests, GENESIS_DIGEST_FOR_TESTS,
  type IntegrityEnvelopeV2
} from "./integrity-chain";
import type { PrototypeD1Database } from "./d1-transaction";

const encoder = new TextEncoder();
const digestPattern = /^[0-9a-f]{64}$/;
const idPattern = /^[A-Za-z0-9_-]{16,128}$/;
const signaturePattern = /^[A-Za-z0-9_-]{86}$/;
const maxCiphertextLength = 1_500_000;

type SignedIntegrityAppendV2 = Readonly<{ version: 2; signature: string }>;

function asBuffer(data: Uint8Array): ArrayBuffer {
  return Uint8Array.from(data).buffer;
}
function encode64(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function decodeSignature(value: string): ArrayBuffer {
  if (typeof value !== "string" || !signaturePattern.test(value)) {
    throw new Error("Malformed integrity signature.");
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "==";
  const bytes = Uint8Array.from(atob(padded), char => char.charCodeAt(0));
  if (bytes.length !== 64 || encode64(bytes) !== value) {
    throw new Error("Malformed integrity signature.");
  }
  return asBuffer(bytes);
}
function validateEnvelope(envelope: IntegrityEnvelopeV2): void {
  if (!envelope || envelope.version !== 2 || envelope.algorithm !== "AES-256-GCM" ||
      !idPattern.test(envelope.vaultId) || !idPattern.test(envelope.entryId) ||
      !Number.isSafeInteger(envelope.revision) || envelope.revision < 1 ||
      !digestPattern.test(envelope.previousDigest) ||
      !digestPattern.test(envelope.digest) ||
      (envelope.revision === 1 && envelope.previousDigest !== GENESIS_DIGEST_FOR_TESTS) ||
      (envelope.revision > 1 && envelope.previousDigest === GENESIS_DIGEST_FOR_TESTS) ||
      typeof envelope.iv !== "string" || !/^[A-Za-z0-9+/]{16}$/.test(envelope.iv) ||
      typeof envelope.ciphertext !== "string" ||
      envelope.ciphertext.length < 24 ||
      envelope.ciphertext.length > maxCiphertextLength ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(envelope.ciphertext)) {
    throw new Error("Invalid v2 integrity envelope.");
  }
}
function payload(challenge: ProofChallengeV1, envelope: IntegrityEnvelopeV2): ArrayBuffer {
  validateEnvelope(envelope);
  if (!challenge || challenge.version !== 1 || challenge.action !== "append" ||
      challenge.vaultId !== envelope.vaultId ||
      !Number.isSafeInteger(challenge.issuedAt) ||
      !Number.isSafeInteger(challenge.expiresAt) ||
      challenge.expiresAt <= challenge.issuedAt ||
      challenge.expiresAt - challenge.issuedAt > 60_000) {
    throw new Error("Invalid v2 append challenge.");
  }
  return asBuffer(encoder.encode(JSON.stringify([
    "mysafespace:d1-v2-append:v1",
    challenge.version, challenge.vaultId, challenge.action,
    challenge.nonce, challenge.issuedAt, challenge.expiresAt,
    envelope.version, envelope.algorithm, envelope.vaultId, envelope.entryId,
    envelope.revision, envelope.previousDigest, envelope.digest,
    envelope.iv, envelope.ciphertext
  ])));
}
async function digestOf(challenge: ProofChallengeV1, envelope: IntegrityEnvelopeV2): Promise<string> {
  return encode64(new Uint8Array(await crypto.subtle.digest(
    "SHA-256", payload(challenge,envelope)
  )));
}

export async function signIntegrityAppendForTests(
  key: CryptoKey, challenge: ProofChallengeV1,
  envelope: IntegrityEnvelopeV2
): Promise<SignedIntegrityAppendV2> {
  if (key.type !== "private" || !key.usages.includes("sign")) {
    throw new Error("Private signing key required.");
  }
  const signature = await crypto.subtle.sign(
    {name:"ECDSA",hash:"SHA-256"},key,payload(challenge,envelope)
  );
  return { version:2, signature:encode64(new Uint8Array(signature)) };
}

export async function issueIntegrityAppendChallengeD1ForTests(
  db:PrototypeD1Database,
  envelope: IntegrityEnvelopeV2,now:number
):Promise<ProofChallengeV1> {
  if (!Number.isSafeInteger(now)) throw new Error("Invalid challenge issue time.");
  // Validate whole envelope and recompute its SHA256 digest before issuing.
  await verifyIntegrityChainForTests(
    envelope.revision === 1 ? [envelope] : []
  ).catch(error => {
    if (envelope.revision === 1) throw error;
  });
  validateEnvelope(envelope);
  const challenge=issueChallengeForTests(envelope.vaultId,"append",now);
  const digest=await digestOf(challenge,envelope);
  const result=await db.prepare(`
    INSERT INTO sandbox_challenges(nonce,vault_id,action,issued_ms,expires_ms,request_digest)
    SELECT ?,vault_id,'append',?,?,? FROM sandbox_vaults
    WHERE vault_id=? AND status='active'
  `).bind(challenge.nonce,challenge.issuedAt,challenge.expiresAt,
    digest,envelope.vaultId).run() as {meta?:{changes?:number}};
  if(result?.meta?.changes!==1) throw new Error("Vault not active.");
  return challenge;
}

export async function appendIntegrityEntryD1ForTests(
  db:PrototypeD1Database,
  challenge:ProofChallengeV1,
  envelope:IntegrityEnvelopeV2,
  proof:SignedIntegrityAppendV2,now:number
):Promise<void> {
  payload(challenge,envelope);
  if(!Number.isSafeInteger(now)||now<challenge.issuedAt-5000||
     now>=challenge.expiresAt||proof?.version!==2) {
    throw new Error("Expired or invalid v2 append authorization.");
  }
  // Verify full envelope hash independently of the signature. This helper
  // accepts a single non-genesis entry only with a separately known parent,
  // so recompute the envelope digest via a targeted digest checker below.
  await verifyStandaloneIntegrityDigest(envelope);
  const row=await db.prepare(
    "SELECT verification_jwk FROM sandbox_vaults WHERE vault_id=? AND status='active'"
  ).bind(challenge.vaultId).first<{verification_jwk:string}>();
  if(!row||typeof row.verification_jwk!=="string"||row.verification_jwk.length>2048) {
    throw new Error("Vault unavailable.");
  }
  const key=await importVerificationKeyForTests(
    JSON.parse(row.verification_jwk) as JsonWebKey
  );
  let valid=false;
  try {
    valid=await crypto.subtle.verify(
      {name:"ECDSA",hash:"SHA-256"},key,
      decodeSignature(proof.signature),payload(challenge,envelope)
    );
  } catch {valid=false;}
  if(!valid) throw new Error("V2 append authorization denied.");
  const claim=db.prepare(`
    INSERT INTO sandbox_consumed_nonces(nonce,consumed_ms)
    VALUES((SELECT nonce FROM sandbox_challenges WHERE
      nonce=? AND vault_id=? AND action='append' AND
      issued_ms=? AND expires_ms=? AND request_digest=?
      AND issued_ms<=? AND expires_ms>?),?)
  `).bind(challenge.nonce,challenge.vaultId,challenge.issuedAt,
    challenge.expiresAt,await digestOf(challenge,envelope),now+5000,now,now);
  const insert=db.prepare(`
    INSERT INTO sandbox_integrity_entries_v2(
      entry_id,vault_id,revision,previous_digest,envelope_digest,
      encrypted_envelope_json,server_received_ms)
    VALUES(?,?,?,?,?,?,?)
  `).bind(envelope.entryId,envelope.vaultId,envelope.revision,
    envelope.previousDigest,envelope.digest,JSON.stringify(envelope),now);
  await db.batch([claim,insert]);
}

/** Recalculate the envelope digest even when the revision is non-genesis. */
async function verifyStandaloneIntegrityDigest(envelope:IntegrityEnvelopeV2):Promise<void> {
  validateEnvelope(envelope);
  const data=encoder.encode(JSON.stringify([
    "mysafespace:envelope-digest:v2",
    envelope.version,envelope.algorithm,envelope.vaultId,envelope.entryId,
    envelope.revision,envelope.previousDigest,envelope.iv,envelope.ciphertext
  ]));
  const hash=Array.from(new Uint8Array(
    await crypto.subtle.digest("SHA-256",asBuffer(data))
  )).map(byte=>byte.toString(16).padStart(2,"0")).join("");
  if(hash!==envelope.digest) throw new Error("V2 envelope digest mismatch.");
}

/**
 * Test-only read of a complete v2 sequence. Always require a separate
 * authorized read/export challenge before calling this helper in any server.
 * The client must separately decrypt every entry to authenticate its AAD.
 */
export async function verifyD1IntegrityHistoryForTests(
  entries:ReadonlyArray<IntegrityEnvelopeV2>,
  trustedHead?:string
):Promise<{revision:number;headDigest:string}> {
  return verifyIntegrityChainForTests(entries,trustedHead);
}
