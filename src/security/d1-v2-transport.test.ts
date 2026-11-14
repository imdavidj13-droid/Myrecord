import { describe, expect, it } from "vitest";
import { generateRecoveryWords } from "./recovery";
import { createWrappedVaultKeyForTests } from "./key-wrapping";
import { createWrappedSigningCredentialForTests } from "./signing-recovery";
import { deriveVaultLookupIdForTests } from "./recovery-bootstrap";
import { createD1VaultTransportForTests } from "./d1-v2-transport";
import type { PrototypeD1Database, PrototypeD1Statement } from "./d1-transaction";
import type { SyntheticVaultBackup } from "./synthetic-vault-store";

async function fixture() {
  const phrase=generateRecoveryWords();
  const data=await createWrappedVaultKeyForTests(phrase);
  const signing=await createWrappedSigningCredentialForTests(phrase,data.envelope.vaultId);
  const backup:SyntheticVaultBackup={
    vaultId:data.envelope.vaultId,
    wrappedDataKey:data.envelope,
    wrappedSigningKey:signing.envelope,
    verificationKey:signing.envelope.publicKey
  };
  return {phrase,backup,lookupId:await deriveVaultLookupIdForTests(phrase)};
}
function mockDatabase() {
  let rows:unknown[]=[];
  const calls:Array<{sql:string;args:Array<string|number>}>=[];
  const db:PrototypeD1Database={
    prepare(sql) {
      const statement:PrototypeD1Statement={
        bind(...args) {calls.push({sql,args});return this;},
        async first<T>() {return null as T|null;},
        async run() {return {meta:{changes:1}};}
      };
      return statement;
    },
    async batch(statements) {
      expect(statements).toHaveLength(1);
      return [{success:true,results:rows}];
    }
  };
  return {db,calls,setRows:(value:unknown[])=>{rows=value;}};
}
describe("test-only D1 v2 transport lookup boundary",()=>{
  it("returns encrypted backup metadata without recovery words or private keys",async()=>{
    const f=await fixture(),store=mockDatabase();
    store.setRows([{
      vault_id:f.backup.vaultId,
      lookup_id:f.lookupId,
      wrapped_backup_json:JSON.stringify(f.backup)
    }]);
    const transport=createD1VaultTransportForTests(store.db,()=>Date.now());
    const result=await transport.lookup(f.lookupId);
    expect(result).toEqual(f.backup);
    expect(result).not.toHaveProperty("phrase");
    expect(JSON.stringify(store.calls)).not.toContain(f.phrase);
    expect(store.calls[0].sql).toContain("sandbox_vaults");
    expect(store.calls[0].args).toEqual([f.lookupId]);
  });
  it("returns null for missing lookup without inventing a record",async()=>{
    const f=await fixture(),store=mockDatabase();
    const transport=createD1VaultTransportForTests(store.db,()=>Date.now());
    expect(await transport.lookup(f.lookupId)).toBeNull();
  });
  it("rejects substituted vault IDs, malformed JSON and ambiguous lookup",async()=>{
    const f=await fixture(),store=mockDatabase();
    const transport=createD1VaultTransportForTests(store.db,()=>Date.now());
    const row={
      vault_id:f.backup.vaultId,
      lookup_id:f.lookupId,
      wrapped_backup_json:JSON.stringify(f.backup)
    };
    store.setRows([{...row,vault_id:"wrong"}]);
    await expect(transport.lookup(f.lookupId)).rejects.toThrow();
    store.setRows([{...row,wrapped_backup_json:"{broken"}]);
    await expect(transport.lookup(f.lookupId)).rejects.toThrow();
    store.setRows([row,row]);
    await expect(transport.lookup(f.lookupId)).rejects.toThrow();
  });
  it("rejects replaced public verification keys and damaged encrypted backup",async()=>{
    const f=await fixture(),store=mockDatabase();
    const transport=createD1VaultTransportForTests(store.db,()=>Date.now());
    const forged={
      ...f.backup,
      verificationKey:{...f.backup.verificationKey,x:"invalid"}
    };
    store.setRows([{
      vault_id:f.backup.vaultId,
      lookup_id:f.lookupId,
      wrapped_backup_json:JSON.stringify(forged)
    }]);
    await expect(transport.lookup(f.lookupId)).rejects.toThrow();
  });
  it("rejects invalid recovery locators before any D1 query",async()=>{
    const store=mockDatabase();
    const transport=createD1VaultTransportForTests(store.db,()=>Date.now());
    await expect(transport.lookup("invalid")).rejects.toThrow();
    expect(store.calls).toHaveLength(0);
  });
});
