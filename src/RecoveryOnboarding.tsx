/**
 * Browser-only onboarding implementation gate.
 *
 * This performs genuine CSPRNG BIP39 word generation and local confirmation,
 * but it deliberately creates NO vault and NO account. Recovery words never
 * leave this React component, are never persisted, and are cleared on exit.
 *
 * The product must not accept real testimony before the reviewed backend,
 * privacy and security controls are complete.
 */
import { useState } from "react";
import { CheckCircle2, Eye, EyeOff, KeyRound, ShieldAlert } from "lucide-react";
import { generateRecoveryWords, normalizeRecoveryWords } from "./security/recovery";

type Props = {
  phase: "generate" | "confirm";
  onConfirm: () => void;
  onStart: () => void;
  onBack: () => void;
  onClear: () => void;
  phrase: string;
  onPhrase: (phrase: string) => void;
};
export default function RecoveryOnboarding({
  phase,onConfirm,onStart,onBack,onClear,phrase,onPhrase
}: Props) {
  const [visible,setVisible]=useState(false);
  const [acknowledged,setAcknowledged]=useState(false);
  const [confirmation,setConfirmation]=useState("");
  const [error,setError]=useState("");
  const words=phrase ? phrase.split(" ") : [];
  const generate=()=>{
    setError("");setConfirmation("");setVisible(false);setAcknowledged(false);
    try { onPhrase(generateRecoveryWords()); }
    catch { setError("Secure recovery word generation is unavailable on this device."); }
  };
  const confirm=()=>{
    if(!phrase || normalizeRecoveryWords(confirmation)!==phrase) {
      setError("The words do not match. Check the original order and try again.");
      return;
    }
    setConfirmation("");setVisible(false);setError("");
    onConfirm();
  };
  return <div className="recovery-live-panel">
    <div className="recovery-live-note"><ShieldAlert size={19}/>
      <div><strong>Development-stage onboarding — no private vault is created.</strong>
        <p>These are genuine randomly generated words, but this website cannot recover or store a record with them yet. Do not treat them as credentials for a live account.</p>
      </div>
    </div>
    {phase==="generate"?<>
      <div className="recovery-live-controls">
        <button className="button" type="button" onClick={()=>{onStart();generate();}}><KeyRound size={17}/>{phrase?"Generate a new phrase":"Generate 12 recovery words"}</button>
        {phrase&&<button className="text-link" type="button" onClick={()=>setVisible(!visible)}>{visible?<EyeOff size={15}/>:<Eye size={15}/>} {visible?"Conceal":"Reveal"} words</button>}
      </div>
      {phrase&&<div className="experience-word-grid recovery-live-words" aria-label="Generated recovery words">
        {words.map((word,i)=><div className="word-placeholder" key={i}><small>{String(i+1).padStart(2,"0")}</small><span>{visible?word:"••••••••"}</span></div>)}
      </div>}
      {phrase&&<label className="acknowledge">
        <input type="checkbox" checked={acknowledged} onChange={event=>setAcknowledged(event.target.checked)}/>
        I understand no account has been created and these words are not connected to any saved record.
      </label>}
      {phrase&&<div className="experience-actions">
        <button className="button" disabled={!acknowledged} onClick={()=>{setVisible(false);onBack();}}>Continue to word confirmation</button>
        <button className="button button-outline" onClick={()=>{setVisible(false);setAcknowledged(false);onClear();}}>Discard these words</button>
      </div>}
    </>:<>
      <p className="recovery-live-explanation">Enter the same 12 words in order. This checks the local recovery-phrase confirmation interface only; it does not register a vault.</p>
      <label className="field-label" htmlFor="confirm-recovery-phrase">12 recovery words, in their original order</label>
      <textarea id="confirm-recovery-phrase" rows={3} value={confirmation}
        onChange={event=>{setConfirmation(event.target.value);setError("");}}
        autoComplete="off" autoCorrect="off" autoCapitalize="off" spellCheck={false}
        placeholder="Type the 12 words in order…" />
      <div className="experience-actions">
        <button className="button" disabled={!phrase||!confirmation.trim()} onClick={confirm}><CheckCircle2 size={16}/> Confirm locally</button>
        <button className="button button-outline" onClick={()=>{setConfirmation("");onBack();}}>Return to recovery words</button>
      </div>
    </>}
    {error&&<p className="recovery-live-error" role="alert">{error}</p>}
  </div>;
}
