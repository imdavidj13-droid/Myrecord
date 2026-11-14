/**
 * Explicitly labelled fictional-only test controls on the existing site.
 * This DOES NOT connect to Cloudflare D1, issue recovery credentials, or
 * allow genuine testimony storage. Refresh/close loses all test records.
 */
import {useMemo,useState,useSyncExternalStore} from "react";
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
  return <App
    workspace={workspace}
    onStartTest={()=>{void start();}}
    onEndTest={close}
    testBusy={busy}
    testError={error}
  />;
}
