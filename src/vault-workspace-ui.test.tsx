import {describe,expect,it} from "vitest";
import {createElement} from "react";
import {renderToStaticMarkup} from "react-dom/server";
import VaultDashboard from "./VaultDashboard";
import VaultRecordControls from "./VaultRecordControls";
import {VaultWorkspaceController, type WorkspaceSession} from "./vault-workspace";
const zero="0".repeat(64);
const digest="b".repeat(64);
describe("P2/P3 actual React screen integration — fictional test state only",()=>{
  it("renders real dashboard history from an injected validated session",async()=>{
    const controller=new VaultWorkspaceController();
    const session:WorkspaceSession={
      read:async()=>({entries:[{
        entryId:"syntheticEntry000000000001",revision:1,
        text:"FICTIONAL UI TEST ENTRY"
      }],latestRevision:1,headDigest:digest}),
      appendSyntheticText:async()=>{throw new Error("Not needed");},
      export:async()=>({entries:[],latestRevision:0,headDigest:zero})
    };
    await controller.unlock(session);
    const markup=renderToStaticMarkup(createElement(VaultDashboard,{
      locallyConfirmed:false,
      workspace:controller.getSnapshot(),
      onWrite:()=>{},onExport:()=>{},onRecover:()=>{},onStart:()=>{},
      onRefresh:()=>{},onClose:()=>{}
    }));
    expect(markup).toContain("FICTIONAL UI TEST ENTRY");
    expect(markup).toContain("Verified revision 1");
    expect(markup).toContain("Isolated test session");
    expect(markup).not.toContain("No stored entries");
  });
  it("shows real export/delete controls only when test workspace is injected",()=>{
    const controller=new VaultWorkspaceController();
    const markup=renderToStaticMarkup(createElement(VaultRecordControls,{
      controller,snapshot:controller.getSnapshot()
    }));
    expect(markup).toContain("Prepare fictional export");
    expect(markup).toContain("Review test deletion");
    expect(markup).toContain("disabled");
    expect(markup).toContain("does not physically erase");
  });
  it("keeps the public dashboard's record history empty without an injected session",()=>{
    const markup=renderToStaticMarkup(createElement(VaultDashboard,{
      locallyConfirmed:false,onWrite:()=>{},onExport:()=>{},
      onRecover:()=>{},onStart:()=>{}
    }));
    expect(markup).toContain("No stored entries");
    expect(markup).toContain("Storage not available yet");
    expect(markup).not.toContain("FICTIONAL UI TEST ENTRY");
  });
});
