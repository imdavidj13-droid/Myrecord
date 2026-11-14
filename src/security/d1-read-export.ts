/**
 * ISOLATED TEST-ONLY D1 ciphertext read/export implementation.
 * No Worker handlers, remote DB calls, plaintext handling, or authentication
 * sessions. Do not expose as a live endpoint.
 *
 * A signed request authenticates exact vault/action/sinceRevision, and the
 * nonce is consumed in the same D1 batch that reads ciphertext. Never allow
 * callers to supply the verification key.
 */
import { importVerificationKeyForTests, issueChallengeForTests, type ProofChallengeV1 } from "./access-proof";
import type { PrototypeD1Database } from "./d1-transaction";
import type { EncryptedStoredEntry, SyntheticVaultBackup } from "./synthetic-vault-store";

export type ReadAction = "read" | "export";
export type SignedReadRequestV1 = Readonly<{ version: 1; signature: string }>;
type ReadResult = Readonly<{
  entries: ReadonlyArray<EncryptedStoredEntry>;
  latestRevision: number;
  backup?: SyntheticVaultBackup;
}>;

const encoder = new TextEncoder();
const vaultIdPattern = /^[A-Za-z0-9_-]{22}$/;
const signaturePattern = /^[A-Za-z0-9_-]{86}$/;

interface D1BatchResult {
  success: boolean;
  results: unknown[];
}
interface EncryptedEntryRow {
  entry_id: string;
  revision: number;
  encrypted_envelope_json: string;
}
interface VaultRow {
  verification_jwk: string;
  latest_revision: number;
  wrapped_backup_json: string;
}

function buffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}
function b64url(input: Uint8Array): string {
  return btoa(String.fromCharCode(...input)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function decodeSignature(input: string): ArrayBuffer {
  if (!signaturePattern.test(input)) throw new Error("Malformed read signature.");
  const base64 = input.replace(/-/g,"+").replace(/_/g,"/") + "==";
  const binary = atob(base64);
  const bytes = Uint8Array.from(Array.from(binary, char => char.charCodeAt(0)));
  if (bytes.length !== 64 || b64url(bytes) !== input) throw new Error("Malformed read signature.");
  return buffer(bytes);
}
function validate(
  challenge: ProofChallengeV1, action: ReadAction, sinceRevision: number
): void {
  if (!challenge || challenge.version !== 1 ||
      !vaultIdPattern.test(challenge.vaultId) || challenge.action !== action ||
      !Number.isSafeInteger(challenge.issuedAt) ||
      !Number.isSafeInteger(challenge.expiresAt) ||
      challenge.expiresAt <= challenge.issuedAt ||
      challenge.expiresAt - challenge.issuedAt > 60_000 ||
      !Number.isSafeInteger(sinceRevision) || sinceRevision < 0 ||
      (action === "export" && sinceRevision !== 0)) {
    throw new Error("Invalid read/export request.");
  }
}
function signedPayload(challenge: ProofChallengeV1, action: ReadAction, sinceRevision: number): ArrayBuffer {
  validate(challenge, action, sinceRevision);
  return buffer(encoder.encode(JSON.stringify([
    "mysafespace:d1-read-export:v1", challenge.version,
    challenge.vaultId, challenge.action, challenge.nonce,
    challenge.issuedAt, challenge.expiresAt, sinceRevision
  ])));
}
async function requestDigest(challenge: ProofChallengeV1, action: ReadAction, sinceRevision: number): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", signedPayload(challenge, action, sinceRevision));
  return b64url(new Uint8Array(digest));
}

export async function signD1ReadRequestForTests(
  privateKey: CryptoKey,
  challenge: ProofChallengeV1,
  action: ReadAction,
  sinceRevision = 0
): Promise<SignedReadRequestV1> {
  if (privateKey.type !== "private" || !privateKey.usages.includes("sign")) {
    throw new Error("Private signing key required.");
  }
  const signature = await crypto.subtle.sign(
    {name:"ECDSA",hash:"SHA-256"},privateKey,signedPayload(challenge,action,sinceRevision)
  );
  return { version: 1, signature: b64url(new Uint8Array(signature)) };
}

export async function issueD1ReadChallengeForTests(
  db: PrototypeD1Database, vaultId: string, action: ReadAction,
  sinceRevision: number, now: number
): Promise<ProofChallengeV1> {
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(sinceRevision) || sinceRevision < 0 ||
      (action === "export" && sinceRevision !== 0)) {
    throw new Error("Invalid challenge parameters.");
  }
  const challenge = issueChallengeForTests(vaultId, action, now);
  const digest = await requestDigest(challenge, action, sinceRevision);
  const result = await db.prepare(`
    INSERT INTO sandbox_challenges(nonce,vault_id,action,issued_ms,expires_ms,request_digest)
    SELECT ?, vault_id, ?, ?, ?, ? FROM sandbox_vaults
    WHERE vault_id = ? AND status = 'active'
  `).bind(
    challenge.nonce, action, challenge.issuedAt, challenge.expiresAt,
    digest, vaultId
  ).run() as { meta?: { changes?: number } };
  if (result?.meta?.changes !== 1) throw new Error("No active vault.");
  return challenge;
}

export async function executeD1ReadForTests(
  db: PrototypeD1Database,
  challenge: ProofChallengeV1,
  action: ReadAction,
  sinceRevision: number,
  proof: SignedReadRequestV1,
  now: number
): Promise<ReadResult> {
  validate(challenge, action, sinceRevision);
  if (!Number.isSafeInteger(now) || now < challenge.issuedAt - 5000 ||
      now >= challenge.expiresAt) throw new Error("Expired read authorization.");
  if (!proof || proof.version !== 1) throw new Error("Invalid read proof.");

  const vault = await db.prepare(`
    SELECT verification_jwk,latest_revision,wrapped_backup_json
    FROM sandbox_vaults WHERE vault_id = ? AND status = 'active'
  `).bind(challenge.vaultId).first<VaultRow>();
  if (!vault || typeof vault.verification_jwk !== "string" ||
      vault.verification_jwk.length > 2048 ||
      !Number.isSafeInteger(vault.latest_revision) || vault.latest_revision < 0) {
    throw new Error("Unknown or malformed vault.");
  }
  let publicKey: CryptoKey;
  try {
    publicKey = await importVerificationKeyForTests(JSON.parse(vault.verification_jwk) as JsonWebKey);
  } catch {
    throw new Error("Invalid registered public key.");
  }
  let verified = false;
  try {
    verified = await crypto.subtle.verify(
      {name:"ECDSA",hash:"SHA-256"}, publicKey,
      decodeSignature(proof.signature), signedPayload(challenge,action,sinceRevision)
    );
  } catch {
    verified = false;
  }
  if (!verified) throw new Error("Read authorization denied.");

  const digest = await requestDigest(challenge,action,sinceRevision);
  const consume = db.prepare(`
    INSERT INTO sandbox_consumed_nonces(nonce,consumed_ms)
    VALUES (
      (SELECT nonce FROM sandbox_challenges
       WHERE nonce = ? AND vault_id = ? AND action = ?
       AND issued_ms = ? AND expires_ms = ? AND request_digest = ?
       AND issued_ms <= ? AND expires_ms > ?), ?
    )
  `).bind(
    challenge.nonce,challenge.vaultId,action,challenge.issuedAt,
    challenge.expiresAt,digest,now+5000,now,now
  );
  const select = db.prepare(`
    SELECT entry_id,revision,encrypted_envelope_json FROM sandbox_entries
    WHERE vault_id = ? AND revision > ?
    ORDER BY revision ASC LIMIT 1001
  `).bind(challenge.vaultId,sinceRevision);
  // D1 batch must return an array of results. If consume fails because the
  // nonce is missing/replayed/expired, the SELECT is rolled back with it.
  const response = await db.batch([consume,select]) as D1BatchResult[];
  if (!Array.isArray(response) || response.length !== 2 ||
      response[0]?.success !== true || response[1]?.success !== true ||
      !Array.isArray(response[1]?.results) || response[1].results.length > 1000) {
    throw new Error("Invalid D1 read transaction response.");
  }
  const entries = response[1].results.map(raw => {
    const row = raw as EncryptedEntryRow;
    if (!row || typeof row.entry_id !== "string" ||
        !Number.isSafeInteger(row.revision) ||
        typeof row.encrypted_envelope_json !== "string" ||
        row.encrypted_envelope_json.length > 1_500_000) {
      throw new Error("Invalid ciphertext row.");
    }
    const ciphertext = JSON.parse(row.encrypted_envelope_json);
    if (!ciphertext || ciphertext.version !== 1 ||
        ciphertext.algorithm !== "AES-256-GCM" ||
        typeof ciphertext.iv !== "string" ||
        typeof ciphertext.ciphertext !== "string") {
      throw new Error("Invalid ciphertext envelope.");
    }
    return {entryId:row.entry_id,revision:row.revision,ciphertext} as EncryptedStoredEntry;
  });
  if (action === "read") return { entries, latestRevision: vault.latest_revision };
  // Fail closed if a purported full export omits records due to LIMIT,
  // concurrent mutation, or a malformed backend response.
  if (entries.length !== vault.latest_revision ||
      entries.some((entry, index) => entry.revision !== index + 1)) {
    throw new Error("Incomplete encrypted vault export.");
  }
  const backup = JSON.parse(vault.wrapped_backup_json) as SyntheticVaultBackup;
  if (!backup || backup.vaultId !== challenge.vaultId ||
      backup.wrappedDataKey?.vaultId !== challenge.vaultId ||
      backup.wrappedSigningKey?.vaultId !== challenge.vaultId) {
    throw new Error("Invalid encrypted vault backup.");
  }
  return { entries,latestRevision:vault.latest_revision,backup };
}
