import type { WorkspaceSnapshot } from "./vault-workspace";
/**
 * Actual MySafeSpace dashboard shell.
 *
 * No fabricated records, local persistence, user identities or network access.
 * Future audited vault services can supply the real state after authentication.
 */
import { ArrowRight, BookOpen, Download, FileText, KeyRound, LockKeyhole, PenLine, ShieldAlert } from "lucide-react";

type Props = {
  locallyConfirmed: boolean;
  workspace?: WorkspaceSnapshot;
  onRefresh?: () => void;
  onClose?: () => void;
  onWrite: () => void;
  onExport: () => void;
  onRecover: () => void;
  onStart: () => void;
};

export default function VaultDashboard({ locallyConfirmed, workspace, onRefresh, onClose, onWrite, onExport, onRecover, onStart }: Props) {
  return <section className="vault-dashboard" aria-label="Private space dashboard">
    <div className="vault-dashboard-head">
      <div>
        <span className="eyebrow">MYSAFESPACE / PRIVATE SPACE</span>
        <h1>A place to return<br/><em>whenever you're ready.</em></h1>
        <p>Your writing, history and export tools will be here once secure vault storage is available.</p>
      </div>
      <div className="vault-dashboard-status"><ShieldAlert size={22}/>
        <div><strong>{workspace && workspace.phase!=="locked" && workspace.phase!=="closed" ? "Isolated test session" : "Storage not available yet"}</strong><span>{workspace && workspace.phase!=="ready" && workspace.phase!=="locked" && workspace.phase!=="closed" ? "Integration session — fictional records only." : "No production account or private vault is active."}</span></div>
      </div>
    </div>
    {locallyConfirmed&&<div className="vault-dashboard-notice" role="status">
      <KeyRound size={19}/>
      <span>Recovery words were confirmed locally and then discarded. No account was created; those words cannot recover a record.</span>
    </div>}
    <div className="vault-dashboard-grid">
      <div className="vault-dashboard-main">
        <div className="vault-dashboard-section-heading">
          <div><span className="eyebrow">YOUR RECORD</span><h2>Record history</h2></div>
          <span className="vault-dashboard-unavailable"><LockKeyhole size={15}/> {workspace?.phase==="ready"?"Test session": "Not connected"}</span>
        </div>
        {workspace?.phase==="loading"&&<p role="status" className="vault-workspace-state">Verifying encrypted history…</p>}
        {workspace?.phase==="saving"&&<p role="status" className="vault-workspace-state">Encrypting and checking the saved revision…</p>}
        {workspace?.phase==="error"&&<p role="alert" className="vault-workspace-error">{workspace.error ?? "Record operation failed."}</p>}
        {workspace?.entries.length ? <div className="vault-workspace-history" aria-label="Verified fictional record history">
          {workspace.entries.map(entry=><article key={entry.entryId} className="vault-workspace-entry">
            <span className="eyebrow">FICTIONAL ENTRY {entry.revision.toString().padStart(2,"0")}</span>
            <p>{entry.text}</p>
          </article>)}
          <div className="vault-workspace-footer"><span>Verified revision {workspace.revision}</span>
          {onRefresh&&<button className="text-link" onClick={onRefresh} disabled={workspace.phase!=="ready"}>Refresh history</button>}
          {onClose&&<button className="text-link" onClick={onClose}>Close test session</button>}</div>
        </div> : <div className="vault-dashboard-empty">
          <div className="vault-dashboard-empty-icon"><BookOpen size={29}/></div>
          <h3>No stored entries</h3>
          <p>{workspace?.phase==="ready" ? "No fictional entries have been added to this isolated vault." : "MySafeSpace isn't accepting or saving private records at this stage. Once audited storage is enabled, your original writing and later additions will appear here in order."}</p>
          <button className="button button-outline" onClick={onWrite}><PenLine size={16}/> View writing modes <ArrowRight size={16}/></button>
        </div>}
      </div>
      <aside className="vault-dashboard-side">
        <div className="vault-dashboard-side-card">
          <span className="eyebrow">YOUR SPACE</span>
          <h3>Where would you like to go?</h3>
          <button onClick={onWrite}><PenLine size={20}/><span><strong>Writing space</strong><small>Free, journal, guided and focus</small></span><ArrowRight size={17}/></button>
          <button onClick={onExport}><Download size={20}/><span><strong>Export & deletion</strong><small>View planned controls</small></span><ArrowRight size={17}/></button>
          <button onClick={onRecover}><KeyRound size={20}/><span><strong>Return to a record</strong><small>Recovery is not enabled yet</small></span><ArrowRight size={17}/></button>
        </div>
        <div className="vault-dashboard-info">
          <FileText size={20}/>
          <div><strong>Nothing has been saved.</strong>
            <p>There are no sample entries or hidden local records. Your personal information should not be entered until the service is independently reviewed.</p>
          </div>
        </div>
        <button className="vault-dashboard-start" onClick={onStart}>Read how MySafeSpace will work <ArrowRight size={16}/></button>
      </aside>
    </div>
  </section>;
}
