/**
 * TEST ONLY: authenticated v2 full-history read/verification.
 *
 * Uses the existing signed read/export proof format, checks the registered
 * public key, consumes the challenge in a D1 batch, then validates the
 * v2 digest chain against the database head and an optional CLIENT-TRUSTED
 * anchor. No Worker routes import this module.
 *
 * This returns ciphertext only; clients must decrypt entries to authenticate
 * AES-GCM AAD. Do not treat server-held head as anti-rollback protection.
 */
import {importVerificationKeyForTests,type ProofChallengeV1} from "./access-proof";
import {verifyD1IntegrityHistoryForTests} from "./d1-v2-integrity";
import {type IntegrityEnvelopeV2} from "./integrity-chain";
import {type PrototypeD1Database} from "./d1-transaction";
import {type SignedReadRequestV1} from "./d1-read-export";

const encoder=new TextEncoder();
const vaultPattern=/^[A-Za-z0-9_-]{22}$/;
const signaturePattern=/^[A-Za-z0-9_-]{86}$/;
const hexPattern=/^[0-9a-f]{64}$/;

function buffer(bytes:Uint8Array):ArrayBuffer{return Uint8Array.from(bytes).buffer;}
function b64url(bytes:Uint8Array):string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function signedBytes(challenge:ProofChallengeV1,action:"read"|"export"):ArrayBuffer {
  if(!challenge||challenge.version!==1||challenge.action!==action||
     !vaultPattern.test(challenge.vaultId)||
     !Number.isSafeInteger(challenge.issuedAt)||
     !Number.isSafeInteger(challenge.expiresAt)||
     challenge.expiresAt<=challenge.issuedAt||
     challenge.expiresAt-challenge.issuedAt>60_000){
    throw new Error("Invalid history challenge.");
  }
  // SAME signing bytes as signD1ReadRequestForTests with sinceRevision=0.
  return buffer(encoder.encode(JSON.stringify([
    "mysafespace:d1-read-export:v1",challenge.version,
    challenge.vaultId,challenge.action,challenge.nonce,
    challenge.issuedAt,challenge.expiresAt,0
  ])));
}
function signatureBytes(raw:string):ArrayBuffer {
  if(typeof raw!=="string"||!signaturePattern.test(raw))throw new Error("Invalid history signature.");
  const normalized=raw.replace(/-/g,"+").replace(/_/g,"/")+"==";
  const bytes=Uint8Array.from(Array.from(atob(normalized), char => char.charCodeAt(0)));
  if(bytes.length!==64||b64url(bytes)!==raw)throw new Error("Invalid history signature.");
  return buffer(bytes);
}
async function requestDigest(challenge:ProofChallengeV1,action:"read"|"export"):Promise<string>{
  return b64url(new Uint8Array(
    await crypto.subtle.digest("SHA-256",signedBytes(challenge,action))
  ));
}

export async function readIntegrityHistoryD1ForTests(
  db:PrototypeD1Database,
  challenge:ProofChallengeV1,
  action:"read"|"export",
  proof:SignedReadRequestV1,
  now:number,
  clientTrustedHead?:string
):Promise<Readonly<{entries:ReadonlyArray<IntegrityEnvelopeV2>;revision:number;headDigest:string}>> {
  const message=signedBytes(challenge,action);
  if(!Number.isSafeInteger(now)||now<challenge.issuedAt-5000||
     now>=challenge.expiresAt||proof?.version!==1)throw new Error("Expired history request.");
  if(clientTrustedHead!==undefined&&!hexPattern.test(clientTrustedHead)){
    throw new Error("Invalid trusted chain head.");
  }
  const vault=await db.prepare(`
    SELECT verification_jwk FROM sandbox_vaults
    WHERE vault_id=? AND status='active'
  `).bind(challenge.vaultId).first<{verification_jwk:string}>();
  if(!vault||typeof vault.verification_jwk!=="string"||
     vault.verification_jwk.length>2048)throw new Error("Vault unavailable.");
  let authorized=false;
  try {
    const key=await importVerificationKeyForTests(
      JSON.parse(vault.verification_jwk) as JsonWebKey
    );
    authorized=await crypto.subtle.verify(
      {name:"ECDSA",hash:"SHA-256"},key,signatureBytes(proof.signature),message
    );
  }catch{authorized=false;}
  if(!authorized)throw new Error("History authorization denied.");

  const claim=db.prepare(`
    INSERT INTO sandbox_consumed_nonces(nonce,consumed_ms)
    VALUES((SELECT nonce FROM sandbox_challenges
      WHERE nonce=? AND vault_id=? AND action=?
      AND issued_ms=? AND expires_ms=? AND request_digest=?
      AND issued_ms<=? AND expires_ms>?),?)
  `).bind(challenge.nonce,challenge.vaultId,action,challenge.issuedAt,
    challenge.expiresAt,await requestDigest(challenge,action),now+5000,now,now);
  const history=db.prepare(`
    SELECT entry_id,revision,previous_digest,envelope_digest,encrypted_envelope_json
    FROM sandbox_integrity_entries_v2 WHERE vault_id=?
    ORDER BY revision ASC LIMIT 1001
  `).bind(challenge.vaultId);
  const head=db.prepare(`
    SELECT latest_revision,head_digest FROM sandbox_integrity_heads_v2
    WHERE vault_id=?
  `).bind(challenge.vaultId);
  const response=await db.batch([claim,history,head]) as Array<{
    success?:boolean;results?:unknown[]
  }>;
  if(!Array.isArray(response)||response.length!==3||
     response.some(x=>x?.success!==true||!Array.isArray(x?.results))||
     response[1].results!.length>1000||response[2].results!.length!==1){
    throw new Error("Invalid v2 history transaction response.");
  }
  const headRow=response[2].results![0] as {latest_revision:number;head_digest:string};
  if(!headRow||!Number.isSafeInteger(headRow.latest_revision)||
     !hexPattern.test(headRow.head_digest)){
    throw new Error("Invalid v2 history head.");
  }
  const entries=response[1].results!.map(raw=>{
    const row=raw as {
      entry_id:string;revision:number;previous_digest:string;
      envelope_digest:string;encrypted_envelope_json:string
    };
    if(!row||typeof row.encrypted_envelope_json!=="string"||
       row.encrypted_envelope_json.length>1_500_000){
      throw new Error("Malformed v2 history row.");
    }
    const envelope=JSON.parse(row.encrypted_envelope_json) as IntegrityEnvelopeV2;
    if(!envelope||envelope.vaultId!==challenge.vaultId||
       row.entry_id!==envelope.entryId||row.revision!==envelope.revision||
       row.previous_digest!==envelope.previousDigest||
       row.envelope_digest!==envelope.digest){
      throw new Error("V2 history metadata mismatch.");
    }
    return envelope;
  });
  const verified=await verifyD1IntegrityHistoryForTests(entries,clientTrustedHead);
  if(verified.revision!==headRow.latest_revision||
     verified.headDigest!==headRow.head_digest){
    throw new Error("V2 chain differs from database head.");
  }
  return {entries,revision:verified.revision,headDigest:verified.headDigest};
}
