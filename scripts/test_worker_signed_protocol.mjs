/**
 * SYNTHETIC-ONLY browser-crypto -> HTTP -> local Worker -> local D1 lifecycle.
 *
 * Bundles the existing TypeScript browser client using the installed esbuild
 * dependency, then exercises real signed requests and encrypted revision
 * history through a separately configured local Cloudflare Worker.
 *
 * No remote endpoints, actual survivor testimony, or production D1 access.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

const root=resolve(import.meta.dirname,"..");
const temp=mkdtempSync(join(tmpdir(),"mysafespace-signed-worker-"));
const state=join(temp,"d1");
const config=resolve(root,"wrangler.protocol-test.jsonc");
const port=18880;
const base="http://127.0.0.1:"+port;
const d1="mysafespace-d1-local-test";
const networkPayloads=[];
let worker;

function command(program,args) {
  const result=spawnSync(program,args,{
    cwd:root,encoding:"utf8",timeout:120_000,maxBuffer:8*1024*1024
  });
  if(result.error)throw result.error;
  if(result.status!==0) {
    throw new Error("Local test command failed: "+(result.stderr||result.stdout));
  }
}
function setup() {
  for(const name of [
    "docs/D1_TRANSACTIONAL_PROTOTYPE.sql",
    "docs/D1_V2_INTEGRITY_EXTENSION.sql",
    "docs/D1_REGISTRATION_PROTOTYPE.sql"
  ]) {
    command("npx",[
      "--yes","wrangler@4.156.2","d1","execute",d1,
      "--local","--config",config,"--persist-to",state,
      "--file",resolve(root,name),"--yes"
    ]);
  }
  const output=join(temp,"vault-client.mjs");
  const bundler=resolve(root,"node_modules",".bin","esbuild");
  command(bundler,[
    "src/security/browser-vault-session.ts","--bundle","--platform=node",
    "--format=esm","--target=node22","--outfile="+output
  ]);
  return output;
}
async function post(route,payload) {
  const serialized=JSON.stringify(payload);
  networkPayloads.push(serialized);
  const response=await fetch(base+"/__local_protocol__/"+route,{
    method:"POST",headers:{"content-type":"application/json"},
    body:serialized,signal:AbortSignal.timeout(12_000)
  });
  const text=await response.text();
  let body;
  try {body=JSON.parse(text);} catch {throw new Error("Non-JSON Worker response.");}
  if(!response.ok)throw new Error("Worker rejected "+route+" ("+response.status+")");
  return body;
}
function remoteTransport() {
  return {
    issueRegistrationChallenge:vaultId=>post("register-challenge",{vaultId}),
    register:input=>post("register",input).then(()=>undefined),
    lookup:lookupId=>post("lookup",{lookupId}),
    issueReadChallenge:(vaultId,action)=>post("read-challenge",{vaultId,action}),
    read:input=>post("read",input),
    issueAppendChallenge:envelope=>post("append-challenge",{envelope}),
    append:input=>post("append",input).then(()=>undefined)
  };
}
async function run() {
  const bundle=setup();
  worker=spawn("npx",[
    "--yes","wrangler@4.156.2","dev","--local",
    "--config",config,"--persist-to",state,
    "--ip","127.0.0.1","--port",String(port)
  ],{cwd:root,stdio:["ignore","pipe","pipe"],detached:true});
  let stderr="";
  worker.stderr.on("data",part=>{stderr=(stderr+String(part)).slice(-8000);});
  const deadline=Date.now()+75_000;
  let ready=false;
  while(Date.now()<deadline) {
    if(worker.exitCode!==null)throw new Error("Worker terminated: "+stderr);
    try {
      // No GET routes are exposed. A 404 proves Wrangler is reachable.
      const result=await fetch(base+"/__local_protocol__/health",{
        signal:AbortSignal.timeout(1_500)
      });
      if(result.status===404){ready=true;break;}
    } catch {}
    await delay(400);
  }
  if(!ready)throw new Error("Local protocol Worker failed to start: "+stderr);

  const { BrowserVaultSessionForTests }=await import(pathToFileURL(bundle).href);
  // Recovery module is bundled separately so both sides use real test crypto.
  const phraseBundle=join(temp,"recovery.mjs");
  command(resolve(root,"node_modules",".bin","esbuild"),[
    "src/security/recovery.ts","--bundle","--platform=node","--format=esm",
    "--target=node22","--outfile="+phraseBundle
  ]);
  const recovery=await import(pathToFileURL(phraseBundle).href);
  const phrase=recovery.generateRecoveryWords();
  assert.equal(typeof phrase,"string");
  assert.equal(phrase.split(" ").length,12);
  const transport=remoteTransport();
  const session=await BrowserVaultSessionForTests.register(transport,phrase);
  const first=await session.appendSyntheticText("FICTIONAL WRITTEN ENTRY ONE");
  assert.equal(first.latestRevision,1);
  assert.deepEqual(first.entries.map(e=>e.text),["FICTIONAL WRITTEN ENTRY ONE"]);
  const second=await session.appendSyntheticText("FICTIONAL WRITTEN ENTRY TWO");
  assert.equal(second.latestRevision,2);
  assert.equal(second.entries[1].text,"FICTIONAL WRITTEN ENTRY TWO");

  const recovered=await BrowserVaultSessionForTests.recover(
    transport,phrase,second.headDigest
  );
  const exported=await recovered.export(second.headDigest);
  assert.equal(exported.latestRevision,2);
  assert.equal(exported.headDigest,second.headDigest);
  assert.deepEqual(exported.entries,second.entries);

  for(const body of networkPayloads){
    assert.equal(body.includes(phrase),false,"Recovery phrase crossed HTTP boundary");
    assert.equal(body.includes("FICTIONAL WRITTEN ENTRY ONE"),false,
      "First plaintext crossed HTTP boundary");
    assert.equal(body.includes("FICTIONAL WRITTEN ENTRY TWO"),false,
      "Second plaintext crossed HTTP boundary");
  }
  const captured=networkPayloads.map(value=>JSON.parse(value));
  const registration=captured.find(value=>value.backup && value.lookupId && value.intent);
  assert.ok(registration,"Registration request was not captured.");
  const issued=await transport.issueReadChallenge(registration.backup.vaultId,"read");
  let rejected=false;
  try {
    await post("read",{vaultId:registration.backup.vaultId,action:"read",
      challenge:issued,proof:{version:1,signature:"Z".repeat(86)}
    });
  }catch{rejected=true;}
  assert.equal(rejected,true,"Unverified history proof accepted");
  const completedRead=captured.find(value=>
    value.action==="read" && value.challenge && value.proof
  );
  assert.ok(completedRead,"Authenticated read was not captured.");
  rejected=false;
  try {await post("read",completedRead);} catch {rejected=true;}
  assert.equal(rejected,true,"Consumed signed read challenge was replayed");
  rejected=false;
  try {await post("register",registration);} catch {rejected=true;}
  assert.equal(rejected,true,"Consumed signed registration challenge was replayed");
  rejected=false;
  try {
    await post("register",{
      phrase:"fictional-disallowed",lookupId:"X".repeat(43),
      backup:{},proof:{},intent:{}
    });
  }catch{rejected=true;}
  assert.equal(rejected,true,"Plaintext secret field accepted");
  const noPublicRoute=await fetch(base+"/api/v1/vault");
  assert.equal(noPublicRoute.status,404);

  console.log("PASS: signed registration, two encrypted HTTP appends, verified "+
    "D1 history, phrase recovery and authenticated export through isolated "+
    "local Worker; unauthorized requests rejected; no phrase/plaintext in HTTP.");
}
try {
  await run();
} finally {
  if(worker?.pid) {
    try {process.kill(-worker.pid,"SIGTERM");}
    catch {try{worker.kill("SIGTERM");}catch{}}
    await delay(300);
  }
  rmSync(temp,{recursive:true,force:true});
}
