/**
 * Start both isolated local D1-backed Worker and Vite browser test page.
 * No --remote commands, no deployed endpoints, no production D1 binding.
 * Only synthetic/fictitious content is permitted.
 */
import {spawn,spawnSync} from "node:child_process";
import {mkdtempSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join,resolve} from "node:path";
import {setTimeout as delay} from "node:timers/promises";

const root=resolve(import.meta.dirname,"..");
const temporary=mkdtempSync(join(tmpdir(),"mysafespace-browser-fixture-"));
const state=join(temporary,"d1");
const config=resolve(root,"wrangler.protocol-test.jsonc");
const database="mysafespace-d1-local-test";
const npx=process.platform==="win32"?"npx.cmd":"npx";
const children=[];
let stopping=false;
function command(args){
  const proc=spawnSync(npx,args,{
    cwd:root,encoding:"utf8",timeout:120_000,maxBuffer:10*1024*1024,
    shell:process.platform==="win32"
  });
  if(proc.error)throw proc.error;
  if(proc.status!==0)throw new Error(proc.stderr||proc.stdout||"Local setup failed.");
}
function start(args){
  const child=spawn(npx,args,{
    cwd:root,stdio:"inherit",shell:process.platform==="win32",
    detached:process.platform!=="win32"
  });
  children.push(child);
  child.on("exit",()=>{if(!stopping)void stop(1);});
  return child;
}
async function stop(code=0){
  if(stopping)return;
  stopping=true;
  for(const child of children){
    if(!child.pid)continue;
    try{
      if(process.platform==="win32"){
        spawnSync("taskkill",["/PID",String(child.pid),"/T","/F"],{stdio:"ignore"});
      }else process.kill(-child.pid,"SIGTERM");
    }catch{try{child.kill("SIGTERM");}catch{}}
  }
  await delay(300);
  rmSync(temporary,{recursive:true,force:true});
  process.exitCode=code;
}
process.on("SIGINT",()=>{void stop();});
process.on("SIGTERM",()=>{void stop();});

try{
  for(const file of [
    "docs/D1_TRANSACTIONAL_PROTOTYPE.sql",
    "docs/D1_V2_INTEGRITY_EXTENSION.sql",
    "docs/D1_REGISTRATION_PROTOTYPE.sql"
  ]){
    command([
      "--yes","wrangler@4.156.2","d1","execute",database,
      "--local","--config",config,"--persist-to",state,
      "--file",resolve(root,file),"--yes"
    ]);
  }
  start([
    "--yes","wrangler@4.156.2","dev","--local","--config",config,
    "--persist-to",state,"--ip","127.0.0.1","--port","18880"
  ]);
  const cutoff=Date.now()+45_000;
  let started=false;
  while(Date.now()<cutoff){
    if(stopping)throw new Error("Isolated worker exited.");
    try{
      const response=await fetch("http://127.0.0.1:18880/__local_protocol__/health",{
        signal:AbortSignal.timeout(1500)
      });
      if(response.status===404){started=true;break;}
    }catch{}
    await delay(300);
  }
  if(!started)throw new Error("Isolated Worker did not start.");
  start(["vite","--config","vite.local-test.config.ts"]);
  console.log("\nFICTIONAL LOCAL TEST ONLY: http://127.0.0.1:5176/local-test.html");
  console.log("Never enter real recovery words or personal experiences.");
  console.log("Press Ctrl+C to discard the temporary local test database.\n");
}catch(error){
  console.error("Local fictional browser test could not start:",error);
  await stop(1);
}
