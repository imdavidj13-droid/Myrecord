/**
 * Fail CI if isolated cryptographic/Worker test infrastructure becomes
 * reachable through the production deployment configuration or site bundle.
 * This is a guardrail, not an independent security audit.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root=resolve(import.meta.dirname,"..");
const read=path=>readFileSync(resolve(root,path),"utf8");
const parse=path=>JSON.parse(read(path));
const production=parse("wrangler.jsonc");
const workerConfig=parse("wrangler.worker-test.jsonc");
const protocolConfig=parse("wrangler.protocol-test.jsonc");
const d1Config=parse("wrangler.d1-test.jsonc");
const fakeId="00000000-0000-4000-8000-000000000001";

assert.equal(production.main,undefined,
  "Production config must remain an assets-only Worker.");
assert.equal(production.assets?.directory,"./dist");
assert.ok(Array.isArray(production.d1_databases));
for(const config of [workerConfig,protocolConfig,d1Config]){
  assert.ok(config.d1_databases?.length===1);
  assert.equal(config.d1_databases[0].database_id,fakeId,
    "Test Worker must never refer to a real D1 database UUID.");
  assert.equal(config.d1_databases[0].database_name,"mysafespace-d1-local-test");
}
assert.equal(workerConfig.main,"./scripts/worker-local-test.ts");
assert.equal(protocolConfig.main,"./scripts/worker-protocol-test.ts");

for(const path of ["src/main.tsx","src/App.tsx","src/VaultDashboard.tsx"]){
  const source=read(path);
  assert.equal(/worker-protocol-test|worker-local-test|d1-v2-transport|browser-vault-session/.test(source),false,
    "Public frontend must not import synthetic-only Worker or vault transport: "+path);
}
for(const path of [
  "scripts/test_d1_local_crypto.mjs",
  "scripts/test_worker_local_d1.mjs",
  "scripts/test_worker_signed_protocol.mjs"
]){
  const source=read(path);
  assert.equal(/["\x27]--remote["\x27]/.test(source),false,
    "Synthetic local D1 scripts must not carry Wrangler remote flag.");
  assert.equal(source.includes("3ef2d249-f2a6-4a4e-ba7a-f984aebec177"),false,
    "Synthetic scripts must not reference live D1 ID.");
}
assert.equal(read("index.html").includes("local-workspace-test-main"),false,
  "Production HTML must not contain local browser test entrypoint.");
assert.equal(read("src/main.tsx").includes("local-workspace-test-main"),false,
  "Production React entrypoint must not import local browser test.");
assert.equal(read("vite.config.ts").includes("local-test.html"),false,
  "Normal Vite config must not bundle local browser test HTML.");
const localVite=read("vite.local-test.config.ts");
assert.ok(localVite.includes('host:"127.0.0.1"') &&
  localVite.includes('target:"http://127.0.0.1:18880"'),
  "Test-only Vite config must remain bound to localhost.");
const inBrowserVault=read("src/ephemeral-fictional-vault.ts");
assert.equal(
  ["fetch(", "XMLHttpRequest", "localStorage.", "sessionStorage.", "indexedDB.", "sendBeacon("]
    .some(pattern=>inBrowserVault.includes(pattern)),false,"Fictional browser vault must never access network or persistent browser storage.");
const publicMain=read("src/main.tsx");
assert.ok(publicMain.includes('ExistingSiteTestApp') &&
  !publicMain.includes("worker-protocol-test"),
  "Existing-site test mode must remain disconnected from test Worker and production D1.");
// Enforce public browser hardening as part of every build.
const headers=read("public/_headers");
for(const requirement of [
  "default-src 'none'",
  "script-src 'self'",
  "connect-src 'self'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "Referrer-Policy: no-referrer",
  "X-Content-Type-Options: nosniff",
  "Cache-Control: no-store"
]){
  assert.ok(headers.includes(requirement),
    "Required privacy/security response header is missing: "+requirement);
}
assert.equal(["https://","http://"].some(v=>read("src/ephemeral-fictional-vault.ts").includes(v)),false,
  "No external HTTP destinations belong in the in-memory vault.");
console.log("PASS: test-only Worker configs use fictional D1; public bundle entrypoints and production config are isolated.");
