/**
 * P3 UI controls for an explicitly injected, isolated test vault.
 * Never mounted on the public site without an injected session.
 * Exports contain readable fictional text and should be handled locally.
 */
import {useEffect,useRef,useState} from "react";
import {Download, LockKeyhole, ShieldAlert, Trash2} from "lucide-react";
import type {VaultWorkspaceController, WorkspaceSnapshot} from "./vault-workspace";
import {serializeVerifiedExportForTests,serializeReadableExportForTests} from "./security/verified-export";

type Props={
  controller:VaultWorkspaceController;
  snapshot:WorkspaceSnapshot;
  ephemeral?:boolean;
};
const confirmation="MARK FICTIONAL VAULT PENDING";
export default function VaultRecordControls({controller,snapshot,ephemeral=false}:Props) {
  const [exportJson,setExportJson]=useState<string|null>(null);
  const [exportText,setExportText]=useState<string|null>(null);
  const exportGeneration=useRef(0);
  const [pending,setPending]=useState(false);
  const [confirmText,setConfirmText]=useState("");
  const [error,setError]=useState<string|null>(null);
  const [notice,setNotice]=useState<string|null>(null);
  const busy=["loading","saving","exporting","deleting"].includes(snapshot.phase);
  const ready=snapshot.phase==="ready";
  // A prepared readable copy must not survive revision changes, session
  // closure, or a replacement vault session.
  useEffect(()=>{
    exportGeneration.current++;
    setExportJson(null);setExportText(null);
    setNotice(null);
  },[snapshot.headDigest,snapshot.revision,snapshot.phase==="closed"||snapshot.phase==="locked"]);
  const prepareExport=async()=>{
    setError(null);setNotice(null);setExportJson(null);setExportText(null);
    const generation=++exportGeneration.current;
    const previousHead=snapshot.headDigest;
    try {
      const result=await controller.exportVerifiedHistory();
      if(generation!==exportGeneration.current || controller.getSnapshot().phase!=="ready" ||
         controller.getSnapshot().headDigest!==previousHead) return;
      setExportJson(serializeVerifiedExportForTests(result));
      setExportText(serializeReadableExportForTests(result));
      setNotice("A complete fictional test export is prepared locally. Download only if you intend to keep a readable file.");
    }catch(e) {setError(e instanceof Error?e.message:"Export failed.");}
  };
  const download=(content:string|null,filename:string,mime:string)=>{
    if(!content || !ready || controller.getSnapshot().phase!=="ready" ||
       controller.getSnapshot().headDigest!==snapshot.headDigest) return;
    const url=URL.createObjectURL(new Blob([content],{type:mime}));
    try{
      const anchor=document.createElement("a");
      anchor.href=url;anchor.download=filename;
      anchor.rel="noopener";anchor.click();
    }finally{setTimeout(()=>URL.revokeObjectURL(url),1000);}
  };
  const deletion=async()=>{
    if(confirmText!==(ephemeral?"ERASE FICTIONAL TEST":confirmation) || !ready || busy)return;
    exportGeneration.current++;
    setExportJson(null);setExportText(null);
    setError(null);
    try {
      if(ephemeral) await controller.eraseEphemeralVault();
      else await controller.markDeletionPending();
      setExportJson(null);setExportText(null);setConfirmText("");setPending(false);
      setNotice(ephemeral
        ? "This tab’s fictional test vault has been cleared and closed. Any downloaded export remains on your device."
        : "The fictional vault was marked deletion-pending and this test session was closed. This does not establish that data or backups were erased.");
    }catch(e){setError(e instanceof Error?e.message:"Deletion request failed.");}
  };
  return <section className="vault-record-controls" aria-label="Isolated fictional vault controls">
    <div className="mini-alert"><ShieldAlert size={17}/>
      This section operates only on an injected fictional test vault. It is not a production records service.
    </div>
    <div className="vault-record-control"><h3>Verified record export</h3>
      <p>Verify and decrypt the entire fictional history before preparing a readable JSON export. Nothing downloads automatically.</p>
      <button className="button button-outline" disabled={!ready||busy}
        onClick={()=>void prepareExport()}><Download size={16}/> Prepare fictional export</button>
      {exportJson&&<div className="vault-export-ready">
        <p role="status">Verified export prepared. It contains readable fictional text and a revision digest.</p>
        <button className="button" onClick={()=>download(exportJson,"mysafespace-fictional-record-export.json","application/json;charset=utf-8")}><Download size={16}/> Download JSON</button>
        <button className="button button-outline" onClick={()=>download(exportText,"mysafespace-fictional-record-export.txt","text/plain;charset=utf-8")}><Download size={16}/> Download readable text</button>
        <button className="text-link" onClick={()=>{setExportJson(null);setExportText(null);setNotice(null);}}>
          Discard prepared export
        </button>
      </div>}
    </div>
    <div className="vault-record-control"><h3>{ephemeral?"Erase this fictional test vault":"Request deletion-pending status"}</h3>
      <p>{ephemeral
        ?"Erase the records held in this browser tab and close the test session. This cannot delete copies you downloaded."
        :"This requests a signed status change in the synthetic database. It does not physically erase ciphertext, backups or snapshots."}</p>
      {!pending?
        <button className="button button-outline" disabled={!ready||busy}
          onClick={()=>setPending(true)}><Trash2 size={16}/> {ephemeral?"Erase fictional records":"Review test deletion"}</button>
        :<div className="vault-delete-confirm">
          <label htmlFor="vault-delete-phrase">To proceed, type: <strong>{ephemeral?"ERASE FICTIONAL TEST":confirmation}</strong></label>
          <input id="vault-delete-phrase" value={confirmText}
            onChange={e=>setConfirmText(e.target.value)} autoComplete="off"/>
          <button className="button" disabled={!ready||busy||confirmText!==(ephemeral?"ERASE FICTIONAL TEST":confirmation)}
            onClick={()=>void deletion()}><LockKeyhole size={16}/> {ephemeral?"Erase and close test":"Mark pending and close test session"}</button>
          <button className="text-link" onClick={()=>{setPending(false);setConfirmText("");}}>Cancel</button>
        </div>}
    </div>
    {notice&&<p role="status" className="vault-workspace-state">{notice}</p>}
    {error&&<p role="alert" className="vault-workspace-error">{error}</p>}
  </section>;
}
