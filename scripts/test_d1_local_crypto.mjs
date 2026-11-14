/**
 * REAL Wrangler --local D1 round-trip with FICTIONAL plaintext only.
 *
 * This test uses genuine AES-256-GCM ciphertext and v2 SHA-256 envelope
 * digests, then stores and retrieves those records through a fresh, isolated
 * Wrangler local D1 database. It also exercises SQL replay/immutability.
 *
 * This DOES NOT exercise a deployed Worker or the signed API authorization
 * protocol. No remote flag, production binding, or live testimony is used.
 */
import assert from "node:assert/strict";
import { webcrypto, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const dir = mkdtempSync(join(tmpdir(), "mysafespace-synthetic-d1-"));
const stateDir = join(dir, "state");
const databaseName = "mysafespace-d1-local-test";
const config = resolve(root, "wrangler.d1-test.jsonc");
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const zeros = "0".repeat(64);
const vaultId = randomBytes(16).toString("base64url");
const lookupId = randomBytes(32).toString("base64url");
const registrationNonce = randomBytes(32).toString("base64url");
const registrationMarker = randomBytes(32).toString("base64url");
const appendNonces = [randomBytes(32).toString("base64url"),randomBytes(32).toString("base64url")];
const samples = [
  "FICTIONAL ROUND TRIP ALPHA — NOT TESTIMONY",
  "FICTIONAL ROUND TRIP BETA — NOT TESTIMONY"
];

function sql(value) {
  assert.equal(typeof value,"string");
  return "'" + value.replaceAll("'","''") + "'";
}

function invoke(args, mustSucceed=true) {
  const child = spawnSync("npx",[
    "--yes","wrangler@4.156.2","d1","execute",databaseName,
    "--local","--config",config,"--persist-to",stateDir,"--json","--yes",...args
  ],{cwd:root,encoding:"utf8",maxBuffer:10*1024*1024,timeout:120_000});
  if(child.error) throw child.error;
  if(mustSucceed && child.status!==0) {
    throw new Error("Local Wrangler D1 failed: "+(child.stderr||child.stdout));
  }
  if(!mustSucceed && child.status===0) {
    throw new Error("Expected local D1 constraint failure, but operation succeeded: "+args.join(" "));
  }
  return child.stdout;
}

function executeQuery(query) {
  const output=invoke(["--command",query]);
  const parsed=JSON.parse(output);
  assert.ok(Array.isArray(parsed),"Wrangler must return a JSON result array.");
  const rows=parsed.flatMap(value=>Array.isArray(value?.results)?value.results:[]);
  return rows;
}

async function digest(envelope) {
  const encoded=encoder.encode(JSON.stringify([
    "mysafespace:envelope-digest:v2",
    envelope.version,envelope.algorithm,envelope.vaultId,envelope.entryId,
    envelope.revision,envelope.previousDigest,envelope.iv,envelope.ciphertext
  ]));
  return Buffer.from(await webcrypto.subtle.digest("SHA-256",encoded)).toString("hex");
}

async function encrypt(key, text, entryId, revision, previousDigest) {
  const iv=randomBytes(12);
  const aad=encoder.encode(JSON.stringify([
    "mysafespace:written-evidence:v2",
    vaultId,entryId,revision,previousDigest
  ]));
  const encrypted=await webcrypto.subtle.encrypt(
    {name:"AES-GCM",iv,additionalData:aad,tagLength:128},
    key,encoder.encode(text)
  );
  const input={
    version:2,algorithm:"AES-256-GCM",vaultId,entryId,revision,
    previousDigest,iv:iv.toString("base64"),
    ciphertext:Buffer.from(encrypted).toString("base64")
  };
  return {...input,digest:await digest(input)};
}

async function decrypt(key,envelope) {
  const {digest:claimed,...data}=envelope;
  assert.equal(await digest(data),claimed,"Envelope digest mismatch");
  const aad=encoder.encode(JSON.stringify([
    "mysafespace:written-evidence:v2",
    data.vaultId,data.entryId,data.revision,data.previousDigest
  ]));
  const raw=await webcrypto.subtle.decrypt({
    name:"AES-GCM",iv:Buffer.from(data.iv,"base64"),
    additionalData:aad,tagLength:128
  },key,Buffer.from(data.ciphertext,"base64"));
  return decoder.decode(raw);
}

async function main() {
  const key=await webcrypto.subtle.generateKey(
    {name:"AES-GCM",length:256},false,["encrypt","decrypt"]
  );
  const entries=[];
  for(let i=0;i<samples.length;i++) {
    entries.push(await encrypt(
      key,samples[i],randomBytes(16).toString("base64url"),i+1,
      i===0?zeros:entries[i-1].digest
    ));
  }

  for(const file of [
    "D1_TRANSACTIONAL_PROTOTYPE.sql",
    "D1_V2_INTEGRITY_EXTENSION.sql",
    "D1_REGISTRATION_PROTOTYPE.sql"
  ]) invoke(["--file",resolve(root,"docs",file)]);

  const statements=[
    "INSERT INTO sandbox_registration_challenges(nonce,vault_id,action,issued_ms,expires_ms) "+
      "VALUES("+[registrationNonce,vaultId,"append"].map(sql).join(",")+",1000,61000)",
    "UPDATE sandbox_registration_challenges SET consumed_ms=2000, consume_marker="+
      sql(registrationMarker)+" WHERE nonce="+sql(registrationNonce)+
      " AND consumed_ms IS NULL AND issued_ms<=2000 AND expires_ms>2000",
    "INSERT INTO sandbox_vaults(vault_id,lookup_id,verification_jwk,wrapped_backup_json) "+
      "VALUES("+[vaultId,lookupId,'{"kty":"EC","synthetic":true}','{"synthetic":"encrypted-backup-placeholder"}'].map(sql).join(",")+")",
    "INSERT INTO sandbox_integrity_heads_v2(vault_id) VALUES("+sql(vaultId)+")"
  ];
  for(let i=0;i<entries.length;i++) {
    const e=entries[i];
    statements.push(
      "INSERT INTO sandbox_challenges(nonce,vault_id,action,issued_ms,expires_ms,request_digest) "+
      "VALUES("+[appendNonces[i],vaultId,"append"].map(sql).join(",")+",1000,61000,"+sql("fictional-signed-append-"+i)+")",
      "INSERT INTO sandbox_consumed_nonces(nonce,consumed_ms) VALUES("+sql(appendNonces[i])+","+(2001+i)+")",
      "INSERT INTO sandbox_integrity_entries_v2 "+
      "(entry_id,vault_id,revision,previous_digest,envelope_digest,encrypted_envelope_json,server_received_ms) "+
      "VALUES("+[e.entryId,e.vaultId].map(sql).join(",")+","+e.revision+","+
      [e.previousDigest,e.digest,JSON.stringify(e)].map(sql).join(",")+","+(2001+i)+")"
    );
  }
  const fixture=join(dir,"encrypted-fixture.sql");
  writeFileSync(fixture,statements.join(";\n")+";\n","utf8");
  const source=await import("node:fs").then(fs=>fs.readFileSync(fixture,"utf8"));
  for(const plaintext of samples) {
    assert.equal(source.includes(plaintext),false,"Plaintext leaked into D1 SQL fixture");
  }
  invoke(["--file",fixture]);

  const rows=executeQuery(
    "SELECT entry_id,revision,previous_digest,envelope_digest,encrypted_envelope_json "+
    "FROM sandbox_integrity_entries_v2 WHERE vault_id="+sql(vaultId)+" ORDER BY revision"
  );
  assert.equal(rows.length,2);
  let previous=zeros;
  for(let i=0;i<rows.length;i++){
    const row=rows[i],entry=JSON.parse(row.encrypted_envelope_json);
    assert.equal(row.revision,i+1);
    assert.equal(row.entry_id,entry.entryId);
    assert.equal(row.previous_digest,previous);
    assert.equal(row.envelope_digest,entry.digest);
    assert.equal(entry.previousDigest,previous);
    assert.equal(await decrypt(key,entry),samples[i]);
    previous=entry.digest;
  }
  const heads=executeQuery(
    "SELECT latest_revision,head_digest FROM sandbox_integrity_heads_v2 WHERE vault_id="+sql(vaultId)
  );
  assert.equal(heads.length,1);
  assert.equal(heads[0].latest_revision,2);
  assert.equal(heads[0].head_digest,previous);

  const lookup=executeQuery(
    "SELECT vault_id,lookup_id,wrapped_backup_json FROM sandbox_vaults WHERE lookup_id="+sql(lookupId)
  );
  assert.equal(lookup.length,1);
  assert.equal(lookup[0].vault_id,vaultId);
  assert.equal(lookup[0].lookup_id,lookupId);
  assert.equal(JSON.stringify(lookup).includes(samples[0]),false);

  invoke(["--command",
    "INSERT INTO sandbox_consumed_nonces(nonce,consumed_ms) VALUES("+sql(appendNonces[0])+",3000)"
  ],false);
  invoke(["--command",
    "UPDATE sandbox_integrity_entries_v2 SET envelope_digest="+sql("f".repeat(64))+
    " WHERE vault_id="+sql(vaultId)+" AND revision=1"
  ],false);
  invoke(["--command",
    "DELETE FROM sandbox_integrity_entries_v2 WHERE vault_id="+sql(vaultId)+" AND revision=1"
  ],false);
  invoke(["--command",
    "UPDATE sandbox_registration_challenges SET consumed_ms=3000, consume_marker="+
    sql(randomBytes(32).toString("base64url"))+" WHERE nonce="+sql(registrationNonce)
  ],false);
  invoke(["--command",
    "INSERT INTO sandbox_integrity_entries_v2 "+
    "(entry_id,vault_id,revision,previous_digest,envelope_digest,encrypted_envelope_json,server_received_ms) "+
    "VALUES("+[randomBytes(16).toString("base64url"),vaultId].map(sql).join(",")+
    ",3,"+sql("f".repeat(64))+","+sql("e".repeat(64))+","+sql("{}")+",3000)"
  ],false);

  const unchanged=executeQuery(
    "SELECT latest_revision,head_digest FROM sandbox_integrity_heads_v2 WHERE vault_id="+sql(vaultId)
  );
  assert.deepEqual(unchanged,heads);
  console.log("PASS: genuine AES-GCM fictional ciphertext round-trip through Wrangler local D1; "+
    "two linked revisions verified and decrypted locally; lookup, replay, immutability and "+
    "invalid continuity checks passed. No remote D1 accessed.");
}
try {
  await main();
} finally {
  rmSync(dir,{recursive:true,force:true});
}
