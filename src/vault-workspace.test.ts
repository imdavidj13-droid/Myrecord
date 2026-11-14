import { describe, expect, it, vi } from "vitest";
import { VaultWorkspaceController, type WorkspaceHistory, type WorkspaceSession } from "./vault-workspace";
import { packageVerifiedExportForTests, serializeVerifiedExportForTests, serializeReadableExportForTests } from "./security/verified-export";

const zero="0".repeat(64);
const digest="a".repeat(64);
function history(texts:string[]):WorkspaceHistory {
  return {
    entries:texts.map((text,i)=>({
      entryId:"syntheticEntryId_"+String(i).padStart(16,"0"),revision:i+1,text
    })),
    latestRevision:texts.length,
    headDigest:texts.length?digest:zero
  };
}
function fake() {
  let values:string[]=[];
  let rejectSave=false;
  let rejectRead=false;
  const closed=vi.fn();
  const session:WorkspaceSession={
    async read() {if(rejectRead)throw new Error("Read unavailable");return history(values);},
    async appendSyntheticText(value) {
      if(rejectSave)throw new Error("Encrypted write rejected");
      values=[...values,value];return history(values);
    },
    async export() {return history(values);},
    close:closed,
    async requestDeletionForTests() {}
  };
  return {session,closed,failSave:()=>{rejectSave=true;},
    failRead:()=>{rejectRead=true;}};
}
describe("P2 controller wiring on actual UI state contract",()=>{
  it("unlocks, saves fictional entries, verifies history, exports, and closes",async()=>{
    const app=new VaultWorkspaceController(),f=fake();
    const phases:string[]=[];
    const stop=app.subscribe(()=>phases.push(app.getSnapshot().phase));
    await app.unlock(f.session);
    await app.saveFictionalText("Fictional writing only");
    expect(app.getSnapshot().entries[0].text).toBe("Fictional writing only");
    expect(app.getSnapshot().revision).toBe(1);
    await app.refresh();
    const exported=await app.exportVerifiedHistory();
    expect(exported.entries).toHaveLength(1);
    expect(serializeVerifiedExportForTests(exported)).toContain("Fictional writing only");
    expect(phases).toContain("loading");
    expect(phases).toContain("saving");
    expect(phases).toContain("exporting");
    app.close();
    expect(app.getSnapshot().entries).toHaveLength(0);
    expect(app.getSnapshot().headDigest).toBeNull();
    expect(app.getSnapshot().phase).toBe("closed");
    expect(f.closed).toHaveBeenCalledTimes(1);
    await expect(app.refresh()).rejects.toThrow("No unlocked");
    stop();
  });
  it("rejects failed writes without reporting success or losing previous history",async()=>{
    const app=new VaultWorkspaceController(),f=fake();
    await app.unlock(f.session);
    await app.saveFictionalText("First fictional entry");
    f.failSave();
    await expect(app.saveFictionalText("Second fictional entry")).rejects.toThrow("rejected");
    expect(app.getSnapshot().phase).toBe("error");
    expect(app.getSnapshot().entries.map(e=>e.text)).toEqual(["First fictional entry"]);
  });
  it("fails closed if initial read fails",async()=>{
    const app=new VaultWorkspaceController(),f=fake();
    f.failRead();
    await expect(app.unlock(f.session)).rejects.toThrow("could not be unlocked");
    expect(app.getSnapshot().phase).toBe("closed");
    expect(f.closed).toHaveBeenCalledTimes(1);
  });
  it("blocks concurrent operations and closes during an unfinished read",async()=>{
    const app=new VaultWorkspaceController();
    let finish:(value:WorkspaceHistory)=>void=()=>{};
    const session:WorkspaceSession={
      read:()=>new Promise(resolve=>{finish=resolve;}),
      appendSyntheticText:async()=>history([]),
      export:async()=>history([])
    };
    const pending=app.unlock(session);
    await expect(app.refresh()).rejects.toThrow("in progress");
    app.close();
    finish(history(["Fictional entry after closure"]));
    await expect(pending).rejects.toThrow();
    expect(app.getSnapshot().entries).toHaveLength(0);
    expect(app.getSnapshot().phase).toBe("closed");
  });
  it("does not allow a stale failed unlock to close a newer session",async()=>{
    const app=new VaultWorkspaceController();
    let rejectOld:(error:Error)=>void=()=>{};
    const oldClose=vi.fn();
    const newClose=vi.fn();
    const old:WorkspaceSession={
      read:()=>new Promise((_resolve,reject)=>{rejectOld=reject;}),
      appendSyntheticText:async()=>history([]),export:async()=>history([]),
      close:oldClose
    };
    const next:WorkspaceSession={
      read:async()=>history(["Fictional replacement session"]),
      appendSyntheticText:async()=>history([]),export:async()=>history([]),
      close:newClose
    };
    const pending=app.unlock(old);
    app.close();
    await app.unlock(next);
    rejectOld(new Error("Delayed failure from previous session"));
    await expect(pending).rejects.toThrow("could not be unlocked");
    expect(app.getSnapshot().phase).toBe("ready");
    expect(app.getSnapshot().entries[0].text).toBe("Fictional replacement session");
    expect(oldClose).toHaveBeenCalledOnce();
    expect(newClose).not.toHaveBeenCalled();
  });
  it("never exposes a late export after closing an in-flight session",async()=>{
    const app=new VaultWorkspaceController();
    let finish:(value:WorkspaceHistory)=>void=()=>{};
    const close=vi.fn();
    const session:WorkspaceSession={
      read:async()=>history(["Fictional"]),
      appendSyntheticText:async()=>history([]),
      export:()=>new Promise(resolve=>{finish=resolve;}),
      close
    };
    await app.unlock(session);
    const pending=app.exportVerifiedHistory();
    expect(app.getSnapshot().phase).toBe("exporting");
    app.close();
    finish(history(["Fictional"]));
    await expect(pending).rejects.toThrow("closed");
    expect(app.getSnapshot().entries).toHaveLength(0);
    expect(app.getSnapshot().phase).toBe("closed");
    expect(close).toHaveBeenCalledOnce();
  });
  it("marks deletion pending through explicit signed-session operation and clears UI",async()=>{
    const app=new VaultWorkspaceController(),f=fake();
    await app.unlock(f.session);
    await app.saveFictionalText("Fictional history to mark pending");
    await app.markDeletionPending();
    expect(app.getSnapshot().phase).toBe("closed");
    expect(app.getSnapshot().entries).toHaveLength(0);
    expect(f.closed).toHaveBeenCalledOnce();
  });
  it("does not claim deletion works without a deletion-capable vault service",async()=>{
    const app=new VaultWorkspaceController();
    await app.unlock({
      read:async()=>history([]),appendSyntheticText:async()=>history([]),
      export:async()=>history([])
    });
    await expect(app.markDeletionPending()).rejects.toThrow("not configured");
    expect(app.getSnapshot().phase).toBe("ready");
  });
});
describe("P3 explicit fictional export formatting",()=>{
  it("includes all revisions, identity fields and a non-certification warning",()=>{
    const result=packageVerifiedExportForTests(history(["One","Two"]));
    expect(result.latestRevision).toBe(2);
    expect(result.entries.map(e=>e.revision)).toEqual([1,2]);
    expect(result.warning).toContain("NOT A FORENSIC");
    expect(result.headDigest).toBe(digest);
  });
  it("includes all fictional text and checked history metadata in readable export",()=>{
    const readable=serializeReadableExportForTests(history(["Fictional first","Fictional second"]));
    expect(readable).toContain("NOT A FORENSIC CERTIFICATION");
    expect(readable).toContain("REVISION 1");
    expect(readable).toContain("REVISION 2");
    expect(readable).toContain("Fictional first");
    expect(readable).toContain("Fictional second");
    expect(readable).toContain("Head digest (SHA-256): "+digest);
  });
  it("rejects missing revisions and mismatched metadata",()=>{
    expect(()=>packageVerifiedExportForTests({...history(["One"]),latestRevision:2})).toThrow();
    expect(()=>packageVerifiedExportForTests({...history(["One"]),headDigest:"invalid"})).toThrow();
    expect(()=>packageVerifiedExportForTests({
      ...history(["One"]),entries:[{entryId:"syntheticEntryId_0000000000000000",
        revision:2,text:"One"}]
    })).toThrow();
  });
});
