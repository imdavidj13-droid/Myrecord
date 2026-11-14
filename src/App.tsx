import SupportPage from "./SupportPage";
import VaultRecoveryTestControls from "./VaultRecoveryTestControls";
import type {WorkspaceSession} from "./vault-workspace";
import VaultRecordControls from "./VaultRecordControls";
import { useSyncExternalStore } from "react";
import type { VaultWorkspaceController, WorkspaceSnapshot } from "./vault-workspace";
import VaultDashboard from "./VaultDashboard";
import RecoveryOnboarding from "./RecoveryOnboarding";
import { useEffect, useState } from "react";
import { ArrowRight, CheckCircle2, FileText, Info, Scale, UserRoundX, UsersRound, BookOpen, ChevronDown, Download, EyeOff, Feather, Focus, Heart, KeyRound, LockKeyhole, Menu, PenLine, ShieldCheck, ShieldAlert, Sparkles, Trash2, X } from "lucide-react";

type Screen = "home" | "before" | "recovery" | "confirm" | "write" | "vault" | "return" | "export" | "support";
type Mode = "free" | "journal" | "guided" | "focus";
const routes: Record<Screen, string> = {
  home: "/", before: "/before-you-begin", recovery: "/recovery-words",
  confirm: "/confirm-recovery", write: "/write", vault: "/vault",
  return: "/return", export: "/export", support:"/support"
};
const screenFromPath = (path: string): Screen => {
  const normalized = path.replace(/\/+$/, "") || "/";
  return (Object.keys(routes) as Screen[]).find(screen => routes[screen] === normalized) ?? "home";
};
const prompts = ["What would you like to remember?", "Is there a particular moment you want to describe?", "Would it help to note when or where this happened?", "Is there anything you might want to add another time?"];
const reassurances = [
  {title:"There is no right way to begin.", body:"You can start anywhere, with whatever feels important."},
  {title:"This is your space.", body:"You can write as much or as little as you wish."},
  {title:"You can take your time.", body:"There is no deadline and no expectation to finish today."},
  {title:"Your words are enough.", body:"You don't have to make your writing perfect."}
];
function Botanical({className=""}:{className?:string}) {return <div className={`botanical ${className}`} aria-hidden="true"><span className="stem"/>{Array.from({length:7},(_,i)=><span key={i} className={`leaf leaf-${i+1}`}/>)}</div>}
const unavailableWorkspace: WorkspaceSnapshot = {
  phase:"locked",entries:[],revision:0,headDigest:null,error:null
};
const subscribeUnavailable=()=>()=>{};
const getUnavailable=()=>unavailableWorkspace;
type AppProps = { workspace?: VaultWorkspaceController; recoverFictional?: (words:string)=>Promise<WorkspaceSession>; onStartTest?:()=>void; onEndTest?:()=>void; testBusy?:boolean; testError?:string|null };
export default function App({workspace,recoverFictional,onStartTest,onEndTest,testBusy=false,testError}:AppProps){
  const [screen,setScreen]=useState<Screen>(()=>screenFromPath(window.location.pathname));
  const vault=useSyncExternalStore(workspace?.subscribe ?? subscribeUnavailable,workspace?.getSnapshot ?? getUnavailable,workspace?.getSnapshot ?? getUnavailable);
  const sessionReady=Boolean(workspace && vault.phase==="ready");
  const sessionBusy=Boolean(workspace && ["loading","saving","exporting","deleting"].includes(vault.phase));
  const [writerError,setWriterError]=useState<string|null>(null);
  const saveFictional=async()=>{
    if(!workspace || !sessionReady) return;
    const original=writing;
    setWriterError(null);
    try {
      await workspace.saveFictionalText(original);
      setWriting(current=>current===original?"":current);
      go("vault");
    } catch(error) {
      setWriterError(error instanceof Error?error.message:"Saving failed.");
    }
  };
  const [mode,setMode]=useState<Mode>("free");
  const [writing,setWriting]=useState("");
  const [support,setSupport]=useState(true);
  const [promptOpen,setPromptOpen]=useState(true);
  const [message,setMessage]=useState(0);
  const [recoveryPhrase,setRecoveryPhrase]=useState("");
  const [onboardingConfirmed,setOnboardingConfirmed]=useState(false);
  const [mobileMenu,setMobileMenu]=useState(false);
  useEffect(() => {
    const onPopState = () => {
      const nextScreen=screenFromPath(window.location.pathname);
      if(nextScreen!=="recovery" && nextScreen!=="confirm") setRecoveryPhrase("");
      setScreen(nextScreen);
      setMobileMenu(false);
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);
  useEffect(()=>{
    if(!workspace)return;
    const onPageHide=()=>{
      workspace.close();
      setWriting("");
      setRecoveryPhrase("");
      setOnboardingConfirmed(false);
    };
    window.addEventListener("pagehide",onPageHide);
    return ()=>window.removeEventListener("pagehide",onPageHide);
  },[workspace]);
  const go=(page:Screen)=>{
    // Do not retain recovery words when leaving the onboarding screens.
    if(page!=="recovery" && page!=="confirm") setRecoveryPhrase("");
    if(window.location.pathname !== routes[page]) window.history.pushState({screen:page},"",routes[page]);
    setScreen(page);
    setMobileMenu(false);
  };
  // When the user deliberately activates the fictional tab vault on the
  // homepage, open the existing writing interface directly.
  useEffect(()=>{
    if(sessionReady && screen==="home")go("write");
  },[sessionReady]);
  const quit=()=>{workspace?.close();setWriting("");setRecoveryPhrase("");setOnboardingConfirmed(false);window.location.replace("about:blank");};
  const modeNames:Record<Mode,string>={free:"Free writing",journal:"Journal",guided:"Guided writing",focus:"Focus mode"};
  return <div className={`site screen-${screen} ${mode==="focus"&&screen==="write"?"focus-site":""}`}>
    {!onStartTest&&<div className="demo-strip"><ShieldAlert size={15}/><strong>DESIGN PROTOTYPE</strong><span>Not encrypted or saved. Do not enter real experiences or identifying details.</span></div>}
    <header className="site-header">
      <button className="brand" onClick={()=>go("home")} aria-label="MySafeSpace home"><span className="brand-icon"><LockKeyhole size={27} strokeWidth={1.7}/></span><span>MySafeSpace</span></button>
      <nav className={mobileMenu?"open":""} aria-label="Main navigation">
        <button onClick={()=>go("before")}>How it works</button>
        <button onClick={()=>go("write")}>Writing space</button>
        <button onClick={()=>go("vault")}>My vault</button>
        <button onClick={()=>go("export")}>Export</button>
        <button onClick={()=>go("support")}>Support</button>
      </nav>
      <div className="header-actions">{onStartTest&&<div className="header-test-controls">{sessionReady?<span className="header-test-status">{vault.revision} fictional {vault.revision===1?"entry":"entries"}</span>:null}<button type="button" className="header-test-button" disabled={testBusy||sessionBusy} onClick={sessionReady?onEndTest:onStartTest}>{sessionReady?"End test":"Start test"}</button></div>}<button className="quiet" onClick={quit}><EyeOff size={16}/> Quick exit</button><button className="menu-button" aria-label="Toggle menu" onClick={()=>setMobileMenu(!mobileMenu)}>{mobileMenu?<X/>:<Menu/>}</button></div>
    </header>
    {testError&&<p className="header-test-error" role="alert">{testError}</p>}
    <main>
    {screen==="home"&&<section className="home-screen">
  <div className="home-hero-replica">
    <div className="home-photo" aria-hidden="true"><div className="photo-plant"><Botanical/></div><div className="photo-table"/><div className="photo-cup"><div className="coffee"/><div className="cup-handle"/></div><div className="photo-book"><div className="book-pages"/><div className="book-ribbon"/></div><div className="photo-pen"/></div>
    <div className="home-hero-content">
      <div className="eyebrow">A PRIVATE SPACE IN DEVELOPMENT <span className="eyebrow-line"/></div>
      <h1>Document your experience<br/>in your own time</h1>
      <p>A private place to write and keep a record of what happened.<br/>Your words, your choices, and your own pace.</p>
      <div className="home-cta">
        <button className="button" onClick={()=>go("write")}><PenLine size={21}/> Open writing space <ArrowRight size={20}/></button>
        <button className="button button-outline" onClick={()=>go("vault")}><KeyRound size={21}/> View my vault <ArrowRight size={20}/></button>
      </div>
      <div className="home-trust"><span><CheckCircle2 size={19}/> Privacy-first design</span><span><CheckCircle2 size={19}/> No account registration planned</span><span><CheckCircle2 size={19}/> No public posts</span></div>
    </div>
  </div>
  <div className="home-feature-rail">
    <Feature icon={<LockKeyhole/>} title="Your words, encrypted" body="The finished service will encrypt your writing on your device."/>
    <Feature icon={<UserRoundX/>} title="No registration" body="No name or email address needed to create a record."/>
    <Feature icon={<FileText/>} title="A record over time" body="Return to add more whenever you need to."/>
    <Feature icon={<Download/>} title="In your control" body="Export or delete your record when you choose."/>
  </div>
  <div className="home-lower">
    <div className="how-block"><h2>How it works</h2><div className="how-steps">
      <div><span className="how-icon"><PenLine/></span><h3>Write</h3><p>Record what you want to remember, in your own words.</p></div>
      <ArrowRight className="how-arrow"/><div><span className="how-icon"><LockKeyhole/></span><h3>Encrypt</h3><p>In the completed service, writing will be encrypted on your device.</p></div>
      <ArrowRight className="how-arrow"/><div><span className="how-icon"><KeyRound/></span><h3>Keep your 12 words</h3><p>In the completed service, your recovery phrase will restore access.</p></div>
      <ArrowRight className="how-arrow"/><div><span className="how-icon"><BookOpen/></span><h3>Return anytime</h3><p>Access and export will be available after launch.</p></div>
    </div></div>
    <div className="important-block"><h2>Important to know</h2><div className="important-items">
      <span><Info/> This is a private record, not a police report.</span>
      <span><UsersRound/> There are no public posts or discussions.</span>
      <span><EyeOff/> We cannot reset lost recovery words in the intended design.</span>
      <span><Scale/> Lawful preservation or disclosure requests may apply.</span>
    </div><button className="text-link" onClick={()=>go("before")}>Read the privacy limitations <ArrowRight size={15}/></button></div>
  </div>
</section>}
    {screen==="before"&&<section className="experience-page">
  <div className="experience-main">
    <div className="experience-intro"><Step count="01" label="BEFORE YOU BEGIN"/><span className="eyebrow">YOUR WORDS, YOUR OWN TIME <span className="eyebrow-line"/></span><h1>A gentle place to begin,<br/><em>on your terms.</em></h1><p className="lead">You don't need to tell us who you are. Before writing, here's what matters about your privacy and returning later.</p></div>
    <div className="experience-details">
      <Detail icon={<LockKeyhole/>} title="Written privately" body="The intended service will encrypt writing in your browser before it is stored. This preview cannot do that yet."/>
      <Detail icon={<KeyRound/>} title="Keep your recovery words" body="Your 12 words will be essential for returning. If you lose them, we won't be able to restore your access."/>
      <Detail icon={<Heart/>} title="You decide what comes next" body="Nothing is posted publicly or sent to the police automatically. You choose what to share."/>
    </div>
    <div className="experience-actions"><div className="mini-alert"><ShieldAlert size={17}/> Prototype only. Please don't enter real testimony.</div><button className="button" onClick={()=>go("recovery")}>Continue to recovery preview <ArrowRight size={18}/></button><button className="text-link" onClick={()=>go("write")}>Explore writing <ArrowRight size={16}/></button></div>
  </div>
  <aside className="experience-scene" aria-hidden="true"><div className="scene-light"/><Botanical className="experience-botanical"/><div className="scene-journal"><div className="scene-journal-ribbon"/><div className="scene-journal-lines"/></div><div className="scene-cup"/><div className="scene-note"><span className="quote-mark">“</span><p>You can take this one step at a time.</p></div></aside>
</section>}
    {(screen==="recovery"||screen==="confirm")&&<section className="experience-page">
  <div className="experience-main">
    <div className="experience-intro">
      <Step count={screen==="recovery"?"02":"03"} label={screen==="recovery"?"RECOVERY WORDS":"CONFIRM YOUR WORDS"}/>
      <span className="eyebrow">THE KEY BELONGS TO YOU <span className="eyebrow-line"/></span>
      <h1>{screen==="recovery"?"A way back to":"Keep your words"}<br/><em>{screen==="recovery"?"your private words.":"somewhere safe."}</em></h1>
      <p className="lead">This browser-only onboarding stage generates and checks a recovery phrase locally. No vault is created and nothing is stored on a server yet.</p>
    </div>
    <RecoveryOnboarding
      key={screen}
      phase={screen==="recovery"?"generate":"confirm"}
      phrase={recoveryPhrase}
      onPhrase={setRecoveryPhrase}
      onStart={()=>setOnboardingConfirmed(false)}
      onBack={()=>go(screen==="recovery"?"confirm":"recovery")}
      onClear={()=>{setRecoveryPhrase("");setOnboardingConfirmed(false);}}
      onConfirm={()=>{
        setRecoveryPhrase("");
        setOnboardingConfirmed(true);
        go("vault");
      }}
    />
    {screen==="recovery"&&<button className="text-link" onClick={()=>{setRecoveryPhrase("");go("before");}}>Go back <ArrowRight size={16}/></button>}
  </div>
  <aside className="experience-scene" aria-hidden="true"><div className="scene-light"/><Botanical className="experience-botanical"/><div className="scene-journal"><div className="scene-journal-ribbon"/><div className="scene-journal-lines"/></div><div className="scene-cup"/><div className="scene-note"><span className="quote-mark">“</span><p>Your privacy is part of every step.</p></div></aside>
</section>}
    {screen==="write"&&<section className="writer-page"><div className="writer-head"><div><div className="eyebrow"><span className="eyebrow-line"/> YOUR PRIVATE WRITING SPACE</div><h1>What would you like<br/><em>to remember?</em></h1><p>You can begin wherever feels right. There is no perfect way to put something into words.</p></div><div className="writer-privacy"><ShieldCheck size={19}/><div><strong>{sessionReady?"In-browser test vault":"Preview only"}</strong><span>{sessionReady?"Fictional entries only · lost on refresh":"Not encrypted or saved"}</span></div></div></div><div className="mode-bar"><div className="mode-tabs" role="group" aria-label="Writing mode">{(["free","journal","guided","focus"] as Mode[]).map(m=><button className={mode===m?"selected":""} aria-pressed={mode===m} onClick={()=>{setMode(m);if(m==="focus")setSupport(false);else setSupport(true)}} key={m}>{m==="free"?<PenLine size={16}/>:m==="journal"?<BookOpen size={16}/>:m==="guided"?<Sparkles size={16}/>:<Focus size={16}/>} {modeNames[m]}</button>)}</div>{mode!=="focus"&&<button className="subtle-button" onClick={()=>setSupport(!support)}>{support?"Hide":"Show"} encouragement <ChevronDown size={15}/></button>}</div><div className={`writing-layout ${!support||mode==="focus"?"solo":""}`}><section className={`writing-card ${mode==="journal"?"journal-card":""}`}><div className="editor-top"><span><Feather size={17}/> A PAGE OF YOUR OWN</span><span className="unsaved-dot"/> {sessionReady?"Fictional test session · not production":"Unsaved · this page only"}</div>{mode==="guided"&&<div className="guide-in-editor"><span className="eyebrow">A GENTLE PLACE TO START</span><h3>You can begin with what you remember.</h3><p>If it helps, think about what you most want to put into words today.</p></div>}<label className="sr-only" htmlFor="record-entry">Your writing</label><textarea id="record-entry" spellCheck={false} value={writing} onChange={e=>setWriting(e.target.value)} placeholder="You can begin here, in your own words...\n\nThere's no rush. Write as much or as little as you wish."/><div className="editor-bottom"><span>{writing.trim()?writing.trim().split(/\s+/).length:0} words · {sessionReady?"Only saved after confirmation":"Unsaved"}</span><div><button className="text-link" onClick={()=>{if(writing.trim()&&window.confirm("Clear this unsaved fictional draft?"))setWriting("");}}>Clear sample</button>{sessionReady?<button className="button" onClick={()=>void saveFictional()} disabled={sessionBusy||!writing.trim()}>Save fictional entry <ArrowRight size={16}/></button>:<button className="button" onClick={()=>go("vault")}>View vault preview <ArrowRight size={16}/></button>}</div></div>{writerError&&<p role="alert" className="vault-workspace-error">{writerError}</p>}</section>{support&&mode!=="focus"&&<aside className="support-column"><div className="encouragement-card"><span className="eyebrow"><Heart size={14}/> A GENTLE REMINDER</span><span className="quote-mark">“</span><h3>{reassurances[message].title}</h3><p>{reassurances[message].body}</p><button className="quiet-next" onClick={()=>setMessage((message+1)%reassurances.length)}>Another gentle reminder <ArrowRight size={15}/></button><Botanical className="support-botanical"/></div><div className="prompt-card"><button className="prompt-header" onClick={()=>setPromptOpen(!promptOpen)} aria-expanded={promptOpen}><span><Sparkles size={18}/> Optional writing prompts</span><ChevronDown size={17}/></button>{promptOpen&&<><p>Only if they feel helpful. You can ignore every one of them.</p>{prompts.map((prompt,i)=><div className="prompt-line" key={i}><span>{String(i+1).padStart(2,"0")}</span>{prompt}</div>)}</>}</div><div className="privacy-mini"><LockKeyhole size={18}/> {sessionReady?"Only fictional text may be saved in this isolated encrypted test vault.":"This prototype does not save, transmit or encrypt your writing."}</div></aside>}</div></section>}
    {screen==="vault"&&<VaultDashboard
      locallyConfirmed={onboardingConfirmed}
      workspace={workspace?vault:undefined}
      onRefresh={workspace?()=>{void workspace.refresh().catch(()=>{});}:undefined}
      onClose={workspace?()=>{workspace.close();setWriting("");}:undefined}
      onWrite={()=>go("write")}
      onExport={()=>go("export")}
      onRecover={()=>go("return")}
      onStart={()=>go("before")}
    />}
    {screen==="return"&&<section className="experience-page">
  <div className="experience-main">
    <div className="experience-intro"><span className="eyebrow">WELCOME BACK <span className="eyebrow-line"/></span><h1>Return to your<br/><em>private record.</em></h1><p className="lead">When the secure vault launches, enter the 12 recovery words you kept to decrypt your writing on this device.</p></div>
    <div className="experience-recovery">
      <div className="experience-word-grid">{Array.from({length:12},(_,i)=><div className="word-placeholder" key={i}><small>{String(i+1).padStart(2,"0")}</small><span>Word</span></div>)}</div>
      <div className="mini-alert"><ShieldAlert size={18}/> Recovery is disabled in this preview. Do not enter an actual recovery phrase.</div>
    </div>
    {workspace && recoverFictional && (vault.phase==="locked"||vault.phase==="closed") && <VaultRecoveryTestControls
      recoverFictional={recoverFictional}
      onRecovered={async session=>{
        await workspace.unlock(session);
        go("vault");
      }}
      onCancel={()=>go("vault")}
    />}
    <div className="experience-actions"><button className="button" disabled><LockKeyhole size={18}/> Unlock my record</button><button className="text-link" onClick={()=>go("before")}>Start a new record preview <ArrowRight size={16}/></button></div>
  </div>
  <aside className="experience-scene" aria-hidden="true"><div className="scene-light"/><Botanical className="experience-botanical"/><div className="scene-journal"><div className="scene-journal-ribbon"/><div className="scene-journal-lines"/></div><div className="scene-cup"/><div className="scene-note"><span className="quote-mark">“</span><p>Come back when the time is right for you.</p></div></aside>
</section>}
    {screen==="support"&&<SupportPage onExit={quit}/>}
    {screen==="export"&&<section className="experience-page">
  <div className="experience-main">
    <div className="experience-intro"><span className="eyebrow">IN YOUR HANDS <span className="eyebrow-line"/></span><h1>Decide what happens<br/><em>to your record.</em></h1><p className="lead">The finished service will let you prepare a complete readable account, or request deletion. Nothing is shared with the police automatically.</p></div>
    {!sessionReady&&<div className="export-choices"><div className="export-choice"><span className="choice-icon"><Download size={26}/></span><div><h3>A copy to keep</h3><p>Start a fictional test and save an entry to try a readable export.</p></div><button className="button button-outline" onClick={()=>go("write")}>Open writing</button></div><div className="export-choice"><span className="choice-icon"><Trash2 size={26}/></span><div><h3>Erase this tab's test</h3><p>Fictional records exist only in memory, and are lost when you close the tab.</p></div><button className="button button-outline" disabled>No active vault</button></div></div>}
    {workspace && vault.phase!=="locked" && vault.phase!=="closed" && <VaultRecordControls controller={workspace} snapshot={vault} ephemeral={Boolean(onStartTest)}/>}
    <div className="experience-actions"><div className="mini-alert"><ShieldAlert size={18}/> A readable export could be visible to others with access to your device.</div><button className="button" onClick={()=>go("vault")}>Back to vault preview <ArrowRight size={18}/></button></div>
  </div>
  <aside className="experience-scene" aria-hidden="true"><div className="scene-light"/><Botanical className="experience-botanical"/><div className="scene-journal"><div className="scene-journal-ribbon"/><div className="scene-journal-lines"/></div><div className="scene-cup"/><div className="scene-note"><span className="quote-mark">“</span><p>Only you decide when you're ready to share.</p></div></aside>
</section>}
    </main>
  </div>;
}
function Feature({icon,title,body}:{icon:React.ReactNode,title:string,body:string}){return <article className="feature"><div className="feature-icon">{icon}</div><h3>{title}</h3><p>{body}</p></article>}
function Detail({icon,title,body}:{icon:React.ReactNode,title:string,body:string}){return <div className="detail"><span className="detail-icon">{icon}</span><div><h3>{title}</h3><p>{body}</p></div></div>}
function Step({count,label}:{count:string,label:string}){return <div className="step-tag"><span>{count}</span>{label}</div>}
