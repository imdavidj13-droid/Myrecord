/**
 * NON-DEPLOYED registration D1 prototype using synthetic values only.
 * Challenge issuance precedes vault existence; successful registration must
 * claim that challenge and insert vault + v2 head in one D1 batch.
 *
 * This authenticates possession of the registered signing key and binds the
 * exact encrypted backup and recovery locator via a signed intent. It CANNOT
 * prove the locator derives from the recovery words; the client-side
 * consistency preflight remains mandatory but not enforceable server-side.
 */
import {
  issueChallengeForTests, importVerificationKeyForTests,
  type ProofChallengeV1, type SignedProofV1
} from "./access-proof";
import {
  verifyRegistrationIntentForTests,
  type SignedRegistrationIntentV1
} from "./registration-intent";
import {isValidVaultLookupIdForTests} from "./recovery-bootstrap";
import type {SyntheticVaultBackup} from "./synthetic-vault-store";
import type {PrototypeD1Database} from "./d1-transaction";

const encoder=new TextEncoder();
const vaultPattern=/^[A-Za-z0-9_-]{22}$/;
const noncePattern=/^[A-Za-z0-9_-]{43}$/;
const sigPattern=/^[A-Za-z0-9_-]{86}$/;
const maxBackupLength=4096;

function buffer(data:Uint8Array):ArrayBuffer {
  return Uint8Array.from(data).buffer;
}
function b64url(data:Uint8Array):string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function signatureBytes(value:string):ArrayBuffer {
  if(typeof value!=="string"||!sigPattern.test(value)){
    throw new Error("Invalid registration proof encoding.");
  }
  const raw=atob(value.replace(/-/g,"+").replace(/_/g,"/")+"==");
  const data=Uint8Array.from(Array.from(raw,c=>c.charCodeAt(0)));
  if(data.length!==64||b64url(data)!==value){
    throw new Error("Invalid registration proof encoding.");
  }
  return buffer(data);
}
function challengeBytes(challenge:ProofChallengeV1):ArrayBuffer {
  return buffer(encoder.encode([
    "mysafespace:access-proof:v1",challenge.version,challenge.vaultId,
    challenge.action,challenge.nonce,challenge.issuedAt,challenge.expiresAt
  ].join("\n")));
}
function validateChallenge(challenge:ProofChallengeV1):void {
  if(!challenge||challenge.version!==1||challenge.action!=="append"||
     !vaultPattern.test(challenge.vaultId)||!noncePattern.test(challenge.nonce)||
     !Number.isSafeInteger(challenge.issuedAt)||
     !Number.isSafeInteger(challenge.expiresAt)||
     challenge.expiresAt<=challenge.issuedAt||
     challenge.expiresAt-challenge.issuedAt>60_000) {
    throw new Error("Invalid registration challenge.");
  }
}

export async function issueRegistrationChallengeD1ForTests(
  db:PrototypeD1Database,vaultId:string,now:number
):Promise<ProofChallengeV1> {
  if(!vaultPattern.test(vaultId)||!Number.isSafeInteger(now)){
    throw new Error("Invalid registration request.");
  }
  const challenge=issueChallengeForTests(vaultId,"append",now);
  const result=await db.prepare(`
    INSERT INTO sandbox_registration_challenges
      (nonce,vault_id,action,issued_ms,expires_ms)
    VALUES(?,?,'append',?,?)
  `).bind(challenge.nonce,vaultId,challenge.issuedAt,challenge.expiresAt)
    .run() as {meta?:{changes?:number}};
  if(result?.meta?.changes!==1){
    throw new Error("Registration challenge was not saved.");
  }
  return challenge;
}

export async function registerVaultD1ForTests(
  db:PrototypeD1Database,
  backup:SyntheticVaultBackup,
  lookupId:string,
  proof:SignedProofV1,
  intent:SignedRegistrationIntentV1,
  now:number
):Promise<void> {
  if(!backup||!vaultPattern.test(backup.vaultId)||
     !isValidVaultLookupIdForTests(lookupId)||
     !proof||proof.version!==1||!proof.challenge){
    throw new Error("Invalid registration input.");
  }
  const challenge=proof.challenge;
  validateChallenge(challenge);
  if(backup.vaultId!==challenge.vaultId||
     !Number.isSafeInteger(now)||
     now<challenge.issuedAt-5000||now>=challenge.expiresAt||
     backup.wrappedDataKey?.version!==1||
     backup.wrappedDataKey.algorithm!=="HKDF-SHA-256+A256GCM"||
     backup.wrappedDataKey.vaultId!==backup.vaultId||
     backup.wrappedSigningKey?.version!==1||
     backup.wrappedSigningKey.algorithm!=="HKDF-SHA-256+A256GCM-PKCS8-P256"||
     backup.wrappedSigningKey.vaultId!==backup.vaultId||
     backup.verificationKey?.kty!=="EC"||
     backup.verificationKey.crv!=="P-256"||
     backup.verificationKey.d!==undefined||
     backup.verificationKey.x!==backup.wrappedSigningKey.publicKey?.x||
     backup.verificationKey.y!==backup.wrappedSigningKey.publicKey?.y){
    throw new Error("Mismatched registration backup or challenge.");
  }
  const stored=JSON.stringify(backup);
  if(stored.length>maxBackupLength)throw new Error("Registration backup too large.");

  const publicKey=await importVerificationKeyForTests(backup.verificationKey);
  let proofValid=false;
  try {
    proofValid=await crypto.subtle.verify(
      {name:"ECDSA",hash:"SHA-256"},publicKey,
      signatureBytes(proof.signature),challengeBytes(challenge)
    );
  }catch{proofValid=false;}
  if(!proofValid||!await verifyRegistrationIntentForTests(
      publicKey,challenge,backup,lookupId,intent)){
    throw new Error("Registration authorization denied.");
  }

  // Per-attempt unpredictable marker guarantees a stale challenge cannot
  // satisfy this registration transaction, even within the same millisecond.
  const consumeMarker=b64url(crypto.getRandomValues(new Uint8Array(32)));
  // D1 batch runs inside one transaction. Failure at the vault's PK/lookup
  // UNIQUE constraint or the head PK rolls back nonce consumption.
  const claim=db.prepare(`
    UPDATE sandbox_registration_challenges SET consumed_ms=?, consume_marker=?
    WHERE nonce=? AND vault_id=? AND action='append'
      AND issued_ms=? AND expires_ms=? AND consumed_ms IS NULL
      AND issued_ms<=? AND expires_ms>?
  `).bind(now,consumeMarker,challenge.nonce,challenge.vaultId,challenge.issuedAt,
    challenge.expiresAt,now+5000,now);
  const vault=db.prepare(`
    INSERT INTO sandbox_vaults(
      vault_id,lookup_id,verification_jwk,wrapped_backup_json
    ) VALUES (
      (SELECT vault_id FROM sandbox_registration_challenges
        WHERE nonce=? AND vault_id=? AND consumed_ms=? AND consume_marker=?),
      ?,?,?
    )
  `).bind(challenge.nonce,backup.vaultId,now,consumeMarker,lookupId,
    JSON.stringify(backup.verificationKey),stored);
  const head=db.prepare(`
    INSERT INTO sandbox_integrity_heads_v2(vault_id) VALUES(?)
  `).bind(backup.vaultId);
  await db.batch([claim,vault,head]);
  // A zero-row claim cannot pass the vault INSERT's NOT NULL constraint:
  // its fresh marker cannot exist on an older consumed challenge.
}
