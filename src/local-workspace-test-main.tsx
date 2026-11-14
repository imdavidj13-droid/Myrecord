/**
 * LOCALHOST-ONLY, FICTIONAL-RECORD BROWSER TEST.
 *
 * Deliberately NOT imported by src/main.tsx or the production Vite config.
 * The test environment must run an isolated Wrangler local Worker/D1 alongside
 * Vite on localhost. Never use real testimony or real recovery credentials.
 */
import React,{useCallback,useMemo,useState,useSyncExternalStore} from "react";
import {createRoot} from "react-dom/client";
import App from "./App";
import {VaultWorkspaceController,type WorkspaceSession} from "./vault-workspace";
import {generateRecoveryWords} from "./security/recovery";
import {BrowserVaultSessionForTests,type VaultTransportForTests} from "./security/browser-vault-session";
import "./style.css";
import "./local-workspace-test.css";

const prefix="/__local_protocol__/";
async function send<T>(route:string,payload:unknown):Promise<T>{
  const response=await fetch(prefix+route,{
    method:"POST",
    headers:{"content-type":"application/json"},
    credentials:"omit",
    cache:"no-store",
    body:JSON.stringify(payload)
  });
  const data=await response.json().catch(()=>null) as unknown;
  if(!response.ok)throw new Error("The isolated local Worker rejected this request.");
  return data as T;
}
const transport:VaultTransportForTests={
  issueRegistrationChallenge:vaultId=>send("register-challenge",{vaultId}),
  register:input=>send("register",input),
  lookup:lookupId=>send("lookup",{lookupId}),
  issueReadChallenge:(vaultId,action)=>send("read-challenge",{vaultId,action}),
  read:input=>send("read",input),
  issueAppendChallenge:envelope=>send("append-challenge",{envelope}),
  append:input=>send("append",input),
  issueDeletionChallenge:vaultId=>send("deletion-challenge",{vaultId}),
  markDeletionPending:(challenge,intent)=>send("mark-deletion-pending",{challenge,intent})
};
function LocalTestApp(){
  const controller=useMemo(()=>new VaultWorkspaceController(),[]);
  const snapshot=useSyncExternalStore(
    controller.subscribe,controller.getSnapshot,controller.getSnapshot
  );
  const [phrase,setPhrase]=useState("");
  const [visible,setVisible]=useState(false);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState<string|null>(null);
  const canCreate=snapshot.phase==="locked"||snapshot.phase==="closed";
  const create=async()=>{
    if(busy || !canCreate)return;
    setBusy(true);setError(null);setPhrase("");setVisible(false);
    let session:WorkspaceSession|undefined;
    try{
      const words=generateRecoveryWords();
      session=await BrowserVaultSessionForTests.register(transport,words);
      await controller.unlock(session);
      // Only display the generated fictional phrase after registration succeeds.
      setPhrase(words);setVisible(true);
    }catch{
      session?.close?.();
      setError("Could not create the fictional local vault. Check that the local Worker is running.");
    }finally{setBusy(false);}
  };
  const recover=useCallback(async(words:string):Promise<WorkspaceSession>=>{
    return BrowserVaultSessionForTests.recover(transport,words);
  },[]);
  const close=()=>{
    controller.close();setPhrase("");setVisible(false);setError(null);
  };
  return <div>
    <aside className="local-workspace-test-banner" aria-label="Isolated local browser test controls">
      <div>
        <strong>LOCAL FICTIONAL TEST · NOT THE PUBLIC WEBSITE</strong>
        <p>Only use invented text. Entries are stored in a temporary local D1 test database, not mysafespace-db. This is not approved for real testimony.</p>
      </div>
      <div className="local-workspace-test-buttons">
        <button type="button" disabled={busy||!canCreate} onClick={()=>void create()}>
          {busy?"Registering…":"Create fictional vault"}
        </button>
        <button type="button" disabled={busy||!canCreate} onClick={()=>{
          window.history.pushState({screen:"return"},"","/return");
          window.dispatchEvent(new PopStateEvent("popstate"));
        }}>Test recovery</button>
        <button type="button" disabled={busy} onClick={close}>Close and clear test session</button>
      </div>
      {error&&<p role="alert" className="local-workspace-test-error">{error}</p>}
      {phrase&&<section className="local-workspace-test-phrase">
        <strong>Fictional recovery words for this local test</strong>
        <p>{visible?phrase:"Twelve fictional words concealed"}</p>
        <button type="button" onClick={()=>setVisible(!visible)}>{visible?"Conceal":"Reveal"}</button>
        <button type="button" onClick={()=>{setPhrase("");setVisible(false);}}>Discard displayed words</button>
        <small>Record these test words before closing if you want to check recovery. Closing clears them from this page.</small>
      </section>}
    </aside>
    <App workspace={controller} recoverFictional={recover}/>
  </div>;
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode><LocalTestApp/></React.StrictMode>
);
