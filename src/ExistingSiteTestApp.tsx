/**
 * Explicitly labelled fictional-only test controls on the existing site.
 * This DOES NOT connect to Cloudflare D1, issue recovery credentials, or
 * allow genuine testimony storage. Refresh/close loses all test records.
 */
import {useMemo,useState,useSyncExternalStore} from "react";
import {ShieldAlert,LockKeyhole} from "lucide-react";
import App from "./App";
import {VaultWorkspaceController} from "./vault-workspace";
import {EphemeralFictionalVault} from "./ephemeral-fictional-vault";

export default function ExistingSiteTestApp(){
  const workspace=useMemo(()=>new VaultWorkspaceController(),[]);
  const snapshot=useSyncExternalStore(
    workspace.subscribe,workspace.getSnapshot,workspace.getSnapshot
  );
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState<string|null>(null);
  const unlocked=snapshot.phase!=="closed"&&snapshot.phase!=="locked";
  const start=async()=>{
    if(busy || unlocked)return;
    setBusy(true);setError(null);
    let vault:EphemeralFictionalVault|undefined;
    try{
      vault=await EphemeralFictionalVault.create();
      await workspace.unlock(vault);
    }catch{
      vault?.close();
      setError("Could not start the fictional in-browser test. Try again.");
    }finally{setBusy(false);}
  };
  const close=()=>{
    workspace.close();setError(null);
  };
  return <div className="existing-site-test-shell">
    <div className="existing-site-test-controls" role="region" aria-label="Fictional browser-only record test">
      <div className="existing-site-test-description">
        <ShieldAlert size={20} aria-hidden="true"/>
        <div>
          <strong>Fictional test mode — not a secure records service</strong>
          <p>Test saving and reopening invented text on this website. Data is encrypted in this tab only; refresh, closing the tab or ending the session destroys it. Do not enter real experiences, names or identifying details. No database or recovery words are used.</p>
        </div>
      </div>
      <div className="existing-site-test-actions">
        {!unlocked?
          <button type="button" onClick={()=>void start()} disabled={busy}>{busy?"Starting…":"Start fictional test"}</button>:
          <>
            <span role="status">Fictional vault active · {snapshot.revision} saved {snapshot.revision===1?"entry":"entries"}</span>
            <button type="button" onClick={close}><LockKeyhole size={15}/> End test and erase this tab's records</button>
          </>
        }
      </div>
      {error&&<p role="alert">{error}</p>}
    </div>
    <App workspace={workspace}/>
  </div>;
}
