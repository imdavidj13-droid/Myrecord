import {describe,expect,it,vi} from "vitest";
import {createElement} from "react";
import {renderToStaticMarkup} from "react-dom/server";
import App from "./App";
import {VaultWorkspaceController, type WorkspaceSession} from "./vault-workspace";

describe("P2 actual App route wiring — no public storage session",()=>{
  it("keeps the public writer unsaved and never advertises active saving",()=>{
    vi.stubGlobal("window",{location:{pathname:"/write"}});
    try {
      const markup=renderToStaticMarkup(createElement(App));
      expect(markup).toContain("Unsaved · this page only");
      expect(markup).toContain("View vault preview");
      expect(markup).not.toContain("Save fictional entry");
      expect(markup).toContain("Not encrypted or saved");
    } finally {vi.unstubAllGlobals();}
  });
  it("allows a fictional save action only through an explicitly injected unlocked session",async()=>{
    const controller=new VaultWorkspaceController();
    const session:WorkspaceSession={
      read:async()=>({entries:[],latestRevision:0,headDigest:"0".repeat(64)}),
      appendSyntheticText:async()=>({entries:[],latestRevision:0,headDigest:"0".repeat(64)}),
      export:async()=>({entries:[],latestRevision:0,headDigest:"0".repeat(64)})
    };
    await controller.unlock(session);
    vi.stubGlobal("window",{location:{pathname:"/write"}});
    try {
      const markup=renderToStaticMarkup(createElement(App,{workspace:controller}));
      expect(markup).toContain("Save fictional entry");
      expect(markup).toContain("Fictional test session");
      expect(markup).not.toContain("View vault preview");
    } finally {controller.close();vi.unstubAllGlobals();}
  });
});
