/**
 * Only rendered when an isolated synthetic recovery adapter is explicitly
 * injected into App. The public website never mounts this component.
 * Recovery words remain inside this form for the duration of the operation.
 */
import {useEffect,useRef,useState} from "react";
import {KeyRound,ShieldAlert} from "lucide-react";
import type {WorkspaceSession} from "./vault-workspace";
import {isValidRecoveryWords,normalizeRecoveryWords} from "./security/recovery";

type Props = {
  recoverFictional: (words:string)=>Promise<WorkspaceSession>;
  onRecovered:(session:WorkspaceSession)=>Promise<void>;
  onCancel:()=>void;
};

export default function VaultRecoveryTestControls({recoverFictional,onRecovered,onCancel}:Props) {
  const [phrase,setPhrase]=useState("");
  const [error,setError]=useState<string|null>(null);
  const [busy,setBusy]=useState(false);
  const alive=useRef(true);
  const submitted=useRef(false);
  useEffect(()=>{
    alive.current=true;
    return ()=>{alive.current=false;};
  },[]);
  const recover=async()=>{
    if(submitted.current)return;
    const words=normalizeRecoveryWords(phrase);
    if(!isValidRecoveryWords(words)) {
      setError("Enter twelve valid fictional test recovery words in order.");
      return;
    }
    submitted.current=true;setBusy(true);setError(null);
    // Remove the words from React state before the first asynchronous action.
    setPhrase("");
    let session:WorkspaceSession|undefined;
    try {
      session=await recoverFictional(words);
      if(!alive.current){session.close?.();return;}
      await onRecovered(session);
    }catch{
      // No cryptographic details or recovery words appear in error messages.
      if(session)session.close?.();
      if(alive.current)setError("Fictional vault recovery failed. No session was opened.");
    }finally{
      submitted.current=false;
      if(alive.current)setBusy(false);
    }
  };
  return <div className="vault-recovery-test">
    <div className="mini-alert"><ShieldAlert size={17}/>
      Isolated fictional recovery test only. Never enter real recovery words or personal information.
    </div>
    <label htmlFor="fictional-recovery-words" className="field-label">Twelve fictional recovery words</label>
    <textarea id="fictional-recovery-words" value={phrase}
      rows={3} disabled={busy} spellCheck={false} autoComplete="off"
      autoCorrect="off" autoCapitalize="off"
      placeholder="Fictional test words only"
      onChange={event=>{setPhrase(event.target.value);setError(null);}}/>
    <div className="experience-actions">
      <button type="button" className="button" disabled={busy||!phrase.trim()}
        onClick={()=>void recover()}><KeyRound size={17}/> {busy?"Verifying fictional vault…":"Recover fictional vault"}</button>
      <button type="button" className="button button-outline" disabled={busy} onClick={()=>{setPhrase("");onCancel();}}>Cancel</button>
    </div>
    {error&&<p className="vault-workspace-error" role="alert">{error}</p>}
  </div>;
}
