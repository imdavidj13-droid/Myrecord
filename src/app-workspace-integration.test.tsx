import ExistingSiteTestApp from "./ExistingSiteTestApp";
import {describe,expect,it,vi} from "vitest";
import {createElement} from "react";
import {renderToStaticMarkup} from "react-dom/server";
import App from "./App";
import {VaultWorkspaceController, type WorkspaceSession} from "./vault-workspace";

describe("Existing-site header and fictional test controls",()=>{
  it("renders the actual site with a compact header control and no test banner",()=>{
    vi.stubGlobal("window",{location:{pathname:"/write"}});
    try{
      const markup=renderToStaticMarkup(createElement(ExistingSiteTestApp));
      expect(markup).toContain('class="site screen-write');
      expect(markup).toContain('class="header-test-controls"');
      expect(markup).toContain("Start test");
      expect(markup).not.toContain('class="existing-site-test-controls"');
      expect(markup).toContain("Your writing");
      expect(markup).not.toContain("ISOLATED TEST SESSION");
      expect(markup).not.toContain("Fictional test mode — not a secure records service");
    }finally{vi.unstubAllGlobals();}
  });
});
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
  it("keeps public recovery unavailable and only renders fictional recovery with explicit injection",()=>{
    vi.stubGlobal("window",{location:{pathname:"/return"}});
    try {
      const publicMarkup=renderToStaticMarkup(createElement(App));
      expect(publicMarkup).toContain("Recovery is disabled in this preview");
      expect(publicMarkup).not.toContain("fictional-recovery-words");
      const controller=new VaultWorkspaceController();
      const testMarkup=renderToStaticMarkup(createElement(App,{
        workspace:controller,
        recoverFictional:async()=>({
          read:async()=>({entries:[],latestRevision:0,headDigest:"0".repeat(64)}),
          appendSyntheticText:async()=>({entries:[],latestRevision:0,headDigest:"0".repeat(64)}),
          export:async()=>({entries:[],latestRevision:0,headDigest:"0".repeat(64)})
        })
      }));
      expect(testMarkup).toContain("fictional-recovery-words");
      expect(testMarkup).toContain("Recover fictional vault");
      controller.close();
    }finally{vi.unstubAllGlobals();}
  });

});
