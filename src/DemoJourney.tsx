import { useState } from "react";
import {
  ArrowRight, BookOpen, CheckCircle2, Download, EyeOff,
  Feather, FileText, Focus, Heart, KeyRound, LockKeyhole, PenLine,
  RotateCcw, ShieldAlert, Sparkles
} from "lucide-react";

type Stage = "welcome" | "phrase" | "confirmation" | "dashboard" | "writer" | "history" | "export";
type WritingMode = "free" | "journal" | "guided" | "focus";
type DemoEntry = Readonly<{ id: number; title: string; body: string; label: string; mode: WritingMode }>;

const examples: ReadonlyArray<{title:string;body:string;label:string}> = [
  {
    title: "A fictional first entry",
    body: "This is an example of a private record. Everything on this page is invented to demonstrate the layout and how a record might appear over time.",
    label: "Example day one"
  },
  {
    title: "Adding another detail",
    body: "In this fictional example, I remembered another detail later. It is recorded as a new entry instead of changing the original writing.",
    label: "Example day two"
  },
  {
    title: "A further reflection",
    body: "This is a third made-up entry, showing that a record can grow over time without needing to be completed all at once.",
    label: "Example day three"
  }
];
const modes: ReadonlyArray<{id:WritingMode;title:string;description:string}> = [
  {id:"free",title:"Free writing",description:"A blank, spacious page"},
  {id:"journal",title:"Journal",description:"A familiar, dated notebook"},
  {id:"guided",title:"Guided writing",description:"Optional gentle prompts"},
  {id:"focus",title:"Focus mode",description:"A quiet, distraction-free page"}
];
const sampleWords = Array.from({length:12},(_,i)=>"Example "+String(i+1).padStart(2,"0"));

function initialEntries(): DemoEntry[] {
  return [{id:1,...examples[0],mode:"journal"}];
}

export default function DemoJourney({exit}:{exit:()=>void}) {
  const [stage,setStage]=useState<Stage>("welcome");
  const [mode,setMode]=useState<WritingMode>("free");
  const [entries,setEntries]=useState<DemoEntry[]>(initialEntries);
  const [sampleIndex,setSampleIndex]=useState(1);
  const [selected,setSelected]=useState(1);
  const [confirmed,setConfirmed]=useState(false);
  const [phraseSeen,setPhraseSeen]=useState(false);
  const [notice,setNotice]=useState("");

  const navigate=(next:Stage)=>{
    setNotice("");
    setStage(next);
  };
  const reset=()=>{
    setEntries(initialEntries());setStage("welcome");setMode("free");
    setSampleIndex(1);setSelected(1);setConfirmed(false);setPhraseSeen(false);
    setNotice("");
  };
  const addFictionalEntry=()=>{
    const sample=examples[sampleIndex % examples.length];
    const next:DemoEntry={...sample,id:entries.length+1,mode};
    setEntries(previous=>[...previous,next]);
    setSelected(next.id);
    setSampleIndex(value=>value+1);
    setNotice("Fictional entry added to this browser tab only. No information was saved or transmitted.");
    setStage("history");
  };
  const activeEntry=entries.find(entry=>entry.id===selected)??entries[0];
  const exportPreview=JSON.stringify({
    demoOnly:true,
    warning:"Fictional interface demonstration only. Not an evidence record or integrity certificate.",
    storage:"React memory only; disappears on page refresh.",
    entries:entries.map(entry=>({revision:entry.id,title:entry.title,body:entry.body,mode:entry.mode,label:entry.label}))
  },null,2);

  return <section className="demo-journey" aria-label="MySafeSpace interactive demonstration">
    <div className="demo-journey-top">
      <span className="demo-kicker"><ShieldAlert size={15}/> INTERACTIVE FICTIONAL DEMO — NO REAL INFORMATION</span>
      <button className="demo-exit" onClick={exit}><EyeOff size={16}/> Leave demonstration</button>
    </div>
    <div className="demo-shell">
      <aside className="demo-sidebar" aria-label="Demonstration journey">
        <div className="demo-sidebar-brand"><LockKeyhole size={22}/> My private space <small>INTERFACE PREVIEW</small></div>
        <p className="demo-sidebar-help">Explore the intended experience using prepared, fictional examples.</p>
        <div className="demo-nav">
          {([
            ["welcome","Welcome"],
            ["phrase","Recovery words"],
            ["confirmation","Confirmation"],
            ["dashboard","My dashboard"],
            ["writer","Writing space"],
            ["history","Record history"],
            ["export","Export preview"]
          ] as Array<[Stage,string]>).map(([id,label],i)=>
            <button key={id} className={stage===id?"active":""} onClick={()=>navigate(id)}>
              <span>{String(i+1).padStart(2,"0")}</span>{label}
            </button>
          )}
        </div>
        <div className="demo-sidebar-bottom">
          <LockKeyhole size={18}/>
          <p><strong>Nothing is stored.</strong> Entries are fictional and disappear when you refresh or leave the page.</p>
          <button onClick={reset}><RotateCcw size={14}/> Restart demo</button>
        </div>
      </aside>
      <div className="demo-main">
        {notice&&<div className="demo-notice" role="status"><CheckCircle2 size={17}/>{notice}</div>}
        {stage==="welcome"&&<div className="demo-page demo-welcome">
          <span className="demo-eyebrow">WELCOME TO YOUR SPACE</span>
          <h1>A private place for<br/><em>your own words.</em></h1>
          <p className="demo-lead">This guided demonstration shows how MySafeSpace will work, from keeping recovery words through writing and exporting your record.</p>
          <div className="demo-soft-card">
            <Heart size={22}/><div><h3>At your pace, with no pressure.</h3>
              <p>There is no required format, no public profile and no automatic police reporting in the intended service.</p>
            </div>
          </div>
          <div className="demo-actions"><button className="button" onClick={()=>navigate("phrase")}>Explore recovery words <ArrowRight size={17}/></button></div>
        </div>}
        {stage==="phrase"&&<div className="demo-page">
          <span className="demo-eyebrow">STEP 01 / PRIVATE ACCESS</span>
          <h1>Your way back to<br/><em>your private record.</em></h1>
          <p className="demo-lead">The finished system will generate twelve secure words on your device. These are <strong>numbered placeholders, not a recovery phrase</strong>.</p>
          <div className="demo-words">
            {sampleWords.map((word,i)=><div key={word}><small>{String(i+1).padStart(2,"0")}</small><span>{phraseSeen?word:"••••••••"}</span></div>)}
          </div>
          <div className="demo-inline">
            <button className="demo-text-button" onClick={()=>setPhraseSeen(value=>!value)}>{phraseSeen?"Hide":"Reveal"} example labels</button>
            <span><ShieldAlert size={15}/> No secret has been generated.</span>
          </div>
          <div className="demo-actions"><button className="button" onClick={()=>navigate("confirmation")}>Continue <ArrowRight size={17}/></button></div>
        </div>}
        {stage==="confirmation"&&<div className="demo-page">
          <span className="demo-eyebrow">STEP 02 / IMPORTANT SAFEGUARD</span>
          <h1>Keep your words<br/><em>somewhere safe.</em></h1>
          <p className="demo-lead">In the completed service, you would confirm your recovery words before writing. This demonstration does not ask you for real words.</p>
          <div className="demo-soft-card"><KeyRound size={26}/><div>
            <h3>Recovery phrase confirmation</h3><p>Real confirmation will require the original twelve words, in order. For this preview, acknowledge the demonstration instead.</p>
          </div></div>
          <label className="demo-check"><input type="checkbox" checked={confirmed} onChange={e=>setConfirmed(e.target.checked)}/> I understand that this is a fictional demonstration and does not create an account.</label>
          <div className="demo-actions"><button className="button" disabled={!confirmed} onClick={()=>navigate("dashboard")}>Enter sample dashboard <ArrowRight size={17}/></button></div>
        </div>}
        {stage==="dashboard"&&<div className="demo-page">
          <span className="demo-eyebrow">YOUR PRIVATE SPACE / DEMONSTRATION</span>
          <h1>Welcome back<br/><em>to your space.</em></h1>
          <p className="demo-lead">A calm overview of the entries you've chosen to keep. All content shown here is fictional.</p>
          <div className="demo-stats">
            <div><FileText size={23}/><strong>{entries.length}</strong><span>Sample {entries.length===1?"entry":"entries"}</span></div>
            <div><BookOpen size={23}/><strong>{entries.length}</strong><span>Revision {entries.length===1?"":"s"} in history</span></div>
            <div><KeyRound size={23}/><strong>Demo</strong><span>Not connected to a vault</span></div>
          </div>
          <div className="demo-panel">
            <span className="demo-eyebrow">WHERE WOULD YOU LIKE TO GO?</span>
            <div className="demo-choice-grid">
              <button onClick={()=>navigate("writer")}><PenLine/><strong>Start writing</strong><span>Explore four writing styles</span><ArrowRight size={18}/></button>
              <button onClick={()=>navigate("history")}><BookOpen/><strong>View history</strong><span>See how revisions are presented</span><ArrowRight size={18}/></button>
              <button onClick={()=>navigate("export")}><Download/><strong>Prepare export</strong><span>Inspect a fictional export</span><ArrowRight size={18}/></button>
            </div>
          </div>
        </div>}
        {stage==="writer"&&<div className="demo-page demo-writer-page">
          <span className="demo-eyebrow">STEP 03 / CHOOSE HOW TO WRITE</span>
          <h1>Begin where<br/><em>you feel comfortable.</em></h1>
          <p className="demo-lead">Switch between all four writing layouts. This demo uses prepared sample text rather than collecting private information.</p>
          <div className="demo-mode-tabs" role="group" aria-label="Writing style">
            {modes.map(item=><button key={item.id} aria-pressed={mode===item.id} className={mode===item.id?"active":""} onClick={()=>setMode(item.id)}>
              {item.id==="free"?<PenLine size={16}/>:item.id==="journal"?<BookOpen size={16}/>:item.id==="guided"?<Sparkles size={16}/>:<Focus size={16}/>}
              {item.title}
            </button>)}
          </div>
          <div className={"demo-paper mode-"+mode}>
            <div className="demo-paper-top"><Feather size={17}/><span>{modes.find(item=>item.id===mode)?.description}</span><span className="demo-sample-label">FICTIONAL SAMPLE</span></div>
            {mode==="guided"&&<div className="demo-guide"><Sparkles size={17}/><strong>What would you like to remember?</strong><span>This question is optional in the intended writing experience.</span></div>}
            {mode==="journal"&&<div className="demo-journal-label">A page from your example journal</div>}
            <h3>{examples[sampleIndex%examples.length].title}</h3>
            <p>{examples[sampleIndex%examples.length].body}</p>
            {mode==="focus"&&<small>Only your writing would be shown here in focus mode.</small>}
          </div>
          <div className="demo-actions">
            <button className="button" onClick={addFictionalEntry}>Add this fictional entry <ArrowRight size={17}/></button>
            <button className="button button-outline" onClick={()=>navigate("history")}>View history</button>
          </div>
        </div>}
        {stage==="history"&&<div className="demo-page">
          <span className="demo-eyebrow">STEP 04 / YOUR RECORD OVER TIME</span>
          <h1>Every entry,<br/><em>in its place.</em></h1>
          <p className="demo-lead">Entries appear in the order they were added. Later additions don't overwrite the earlier examples.</p>
          <div className="demo-history-layout">
            <div className="demo-history-list">
              {entries.map(entry=><button key={entry.id} className={entry.id===selected?"active":""} onClick={()=>setSelected(entry.id)}>
                <span>REVISION {String(entry.id).padStart(2,"0")}</span><strong>{entry.title}</strong><small>{entry.label}</small>
              </button>)}
            </div>
            <article className="demo-history-detail">
              <span className="demo-eyebrow">FICTIONAL RECORD · {activeEntry.label}</span>
              <h3>{activeEntry.title}</h3><p>{activeEntry.body}</p>
              <div className="demo-history-meta"><LockKeyhole size={16}/> Example only · No actual integrity attestation or timestamp</div>
            </article>
          </div>
          <div className="demo-actions"><button className="button" onClick={()=>navigate("writer")}>Add sample entry <ArrowRight size={17}/></button><button className="button button-outline" onClick={()=>navigate("export")}>See export preview</button></div>
        </div>}
        {stage==="export"&&<div className="demo-page">
          <span className="demo-eyebrow">STEP 05 / KEEP OR SHARE A COPY</span>
          <h1>A record that's<br/><em>yours to decide.</em></h1>
          <p className="demo-lead">This is an illustrative export showing record order. It is not a certified evidence file, an independent timestamp, or a copy of actual encrypted D1 data.</p>
          <div className="demo-export-summary">
            <div><Download size={24}/><strong>{entries.length} fictional {entries.length===1?"entry":"entries"}</strong><span>Readable sample JSON below</span></div>
            <div><LockKeyhole size={24}/><strong>No backend access</strong><span>Everything remains in browser memory</span></div>
          </div>
          <pre className="demo-export-code" aria-label="Fictional export example">{exportPreview}</pre>
          <div className="demo-actions"><button className="button" onClick={()=>navigate("dashboard")}>Return to dashboard <ArrowRight size={17}/></button><button className="button button-outline" onClick={reset}><RotateCcw size={16}/> Restart demonstration</button></div>
          <p className="demo-disclaimer">A real voluntary export would require local decryption, full record verification and explicit user action. Nothing is automatically shared with police or anyone else.</p>
        </div>}
        <div className="demo-bottom"><span><ShieldAlert size={15}/> Demonstration only. Do not use for real experiences.</span><button onClick={()=>navigate(stage==="welcome"?"phrase":"dashboard")}>{stage==="welcome"?"Next step":"Sample dashboard"} <ArrowRight size={14}/></button></div>
      </div>
    </div>
  </section>;
}
