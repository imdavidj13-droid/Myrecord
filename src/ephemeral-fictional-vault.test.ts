import {describe,it,expect} from "vitest";
import {EphemeralFictionalVault} from "./ephemeral-fictional-vault";
import {VaultWorkspaceController} from "./vault-workspace";

describe("Existing-site fictional encrypted vault: no database or persistence",()=>{
  it("saves, rereads and exports two encrypted fictional entries in the same tab",async()=>{
    const session=await EphemeralFictionalVault.create();
    const workspace=new VaultWorkspaceController();
    await workspace.unlock(session);
    await workspace.saveFictionalText("FICTIONAL EVENT ALPHA");
    await workspace.saveFictionalText("FICTIONAL EVENT BETA");
    expect(workspace.getSnapshot().entries.map(x=>x.text))
      .toEqual(["FICTIONAL EVENT ALPHA","FICTIONAL EVENT BETA"]);
    expect(workspace.getSnapshot().revision).toBe(2);
    const exported=await workspace.exportVerifiedHistory();
    expect(exported.entries).toHaveLength(2);
    expect(exported.headDigest).toMatch(/^[0-9a-f]{64}$/);
    workspace.close();
    expect(workspace.getSnapshot().entries).toHaveLength(0);
    await expect(session.read()).rejects.toThrow("closed");
  });
  it("does not offer recovery or deletion against nonpersistent fictional storage",async()=>{
    const session=await EphemeralFictionalVault.create();
    const workspace=new VaultWorkspaceController();
    await workspace.unlock(session);
    await expect(workspace.markDeletionPending()).rejects.toThrow("not configured");
    expect(workspace.getSnapshot().phase).toBe("ready");
    workspace.close();
  });
  it("does not expose key material or browser storage APIs",async()=>{
    const session=await EphemeralFictionalVault.create();
    expect(session).not.toHaveProperty("transport");
    expect(session).not.toHaveProperty("recoveryPhrase");
    session.close();
  });
});
