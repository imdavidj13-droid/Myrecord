/**
 * Exercise a genuine Cloudflare Worker + D1 binding in local mode, using
 * fictional fixtures only. Requires Node 22+ and Wrangler in the CI runner.
 * Does not call --remote or touch any live D1 database.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const root=resolve(import.meta.dirname,"..");
const dir=mkdtempSync(join(tmpdir(),"mysafespace-local-worker-"));
const stateDir=join(dir,"d1");
const config=resolve(root,"wrangler.worker-test.jsonc");
const database="mysafespace-d1-local-test";
const port=18879;
const base="http://127.0.0.1:"+port;
let server;

function execWrangler(args) {
  const result=spawnSync("npx",[
    "--yes","wrangler@4.156.2",...args
  ],{cwd:root,encoding:"utf8",timeout:120_000,maxBuffer:8*1024*1024});
  if(result.error)throw result.error;
  if(result.status!==0)throw new Error(
    "Local Wrangler command failed: "+(result.stderr||result.stdout)
  );
}
function prepare() {
  const common=["d1","execute",database,"--local","--config",config,"--persist-to",stateDir,"--yes"];
  for(const name of [
    "docs/D1_TRANSACTIONAL_PROTOTYPE.sql",
    "docs/D1_V2_INTEGRITY_EXTENSION.sql",
    "docs/D1_REGISTRATION_PROTOTYPE.sql",
    "scripts/d1_local_lifecycle_fixture.sql"
  ]) execWrangler([...common,"--file",resolve(root,name)]);
}
async function request(path,options) {
  const result=await fetch(base+path,options);
  const text=await result.text();
  return {status:result.status,headers:result.headers,text,body:JSON.parse(text)};
}
async function run() {
  prepare();
  server=spawn("npx",[
    "--yes","wrangler@4.156.2","dev",
    "--config",config,"--local","--persist-to",stateDir,
    "--ip","127.0.0.1","--port",String(port)
  ],{cwd:root,stdio:["ignore","pipe","pipe"],detached:true});
  let stderr="";
  server.stderr.on("data",chunk=>{stderr+=(String(chunk)).slice(-5000);});
  const timeout=Date.now()+75_000;
  let health;
  while(Date.now()<timeout){
    if(server.exitCode!==null)throw new Error("Local Worker exited early: "+stderr);
    try {
      health=await request("/__local_test__/health");
      break;
    } catch {
      await delay(350);
    }
  }
  if(!health)throw new Error("Local Worker did not start: "+stderr);
  assert.equal(health.status,200);
  assert.deepEqual(health.body,{ok:true,fixture:"synthetic-local-only"});
  assert.equal(health.headers.get("cache-control"),"no-store");
  const missing=await request("/api/v1/vault");
  assert.equal(missing.status,404);
  assert.deepEqual(missing.body,{error:"not_found"});
  const post=await request("/__local_test__/health",{
    method:"POST",headers:{"content-type":"application/json"},
    body:JSON.stringify({recoveryPhrase:"not-a-real-phrase",plaintext:"not-real-data"})
  });
  assert.equal(post.status,404);
  assert.deepEqual(post.body,{error:"not_found"});
  assert.equal(health.text.includes("encrypted_envelope_json"),false);
  assert.equal(health.text.includes("syntheticVault12345678"),false);
  console.log("PASS: local Cloudflare Worker queried isolated fictional D1; "+
    "non-sensitive fixture health returned, and storage/write routes were unavailable.");
}
try {
  await run();
} finally {
  if(server?.pid) {
    try {process.kill(-server.pid,"SIGTERM");} catch {
      try {server.kill("SIGTERM");} catch {}
    }
    await delay(300);
  }
  rmSync(dir,{recursive:true,force:true});
}
