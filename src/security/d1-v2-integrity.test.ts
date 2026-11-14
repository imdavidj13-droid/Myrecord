import {describe,expect,it} from "vitest";
import {generateRecoveryWords} from "./recovery";
import {createWrappedVaultKeyForTests} from "./key-wrapping";
import {createWrappedSigningCredentialForTests} from "./signing-recovery";
import {encryptIntegrityEntryForTests, decryptIntegrityEntryForTests,GENESIS_DIGEST_FOR_TESTS} from "./integrity-chain";
import {
  signIntegrityAppendForTests,appendIntegrityEntryD1ForTests,
  initializeIntegrityHeadD1ForTests,
  issueIntegrityAppendChallengeD1ForTests,verifyD1IntegrityHistoryForTests
} from "./d1-v2-integrity";
import {issueChallengeForTests} from "./access-proof";
import type {PrototypeD1Database,PrototypeD1Statement} from "./d1-transaction";

const now=1_783_000_000_000;
async function fixture(){
  const phrase=generateRecoveryWords();
  const data=await createWrappedVaultKeyForTests(phrase);
  const signing=await createWrappedSigningCredentialForTests(phrase,data.envelope.vaultId);
  const first=await encryptIntegrityEntryForTests(data.key,"Fictional entry 1",
    data.envelope.vaultId,"fictionalEntry_12345678",1,GENESIS_DIGEST_FOR_TESTS);
  const second=await encryptIntegrityEntryForTests(data.key,"Fictional entry 2",
    data.envelope.vaultId,"fictionalEntry_98765432",2,first.digest);
  return {data,signing,first,second};
}
function dbMock(jwk:JsonWebKey){
  const statements:Array<{sql:string;params:Array<number|string>}>=[];
  let batches=0;
  let throwOnBatch=false;
  const db:PrototypeD1Database={
    prepare(sql:string):PrototypeD1Statement{
      const statement={
        bind(...args:Array<number|string>):PrototypeD1Statement{
          statements.push({sql,params:args});
          return this;
        },
        async first<T>():Promise<T|null>{
          return {verification_jwk:JSON.stringify(jwk)} as T;
        },
        async run(){return {meta:{changes:1}};}
      };
      return statement;
    },
    async batch(list:PrototypeD1Statement[]){
      expect(list).toHaveLength(2);
      batches++;
      if(throwOnBatch) throw new Error("SQLite trigger rejected digest continuity");
      return [{success:true,results:[]},{success:true,results:[]}];
    }
  };
  return {db,statements,batches:()=>batches,fail:()=>{throwOnBatch=true;}};
}
describe("isolated v2 integrity D1 adapter",()=>{
  it("creates a digest-bound challenge and atomic append of a version-2 envelope",async()=>{
    const f=await fixture(),mock=dbMock(f.signing.envelope.publicKey);
    const challenge=await issueIntegrityAppendChallengeD1ForTests(mock.db,f.first,now);
    const proof=await signIntegrityAppendForTests(f.signing.privateKey,challenge,f.first);
    await appendIntegrityEntryD1ForTests(mock.db,challenge,f.first,proof,now+1);
    expect(mock.batches()).toBe(1);
    expect(mock.statements.some(x=>x.sql.includes("sandbox_integrity_entries_v2"))).toBe(true);
    expect(mock.statements.some(x=>x.params.includes(f.first.previousDigest))).toBe(true);
    expect(mock.statements.some(x=>x.params.includes(f.first.digest))).toBe(true);
    expect(JSON.stringify(mock.statements)).not.toContain("Fictional entry 1");
  });

  it("initializes a v2 chain head for an existing registered test vault",async()=>{
    const f=await fixture(),mock=dbMock(f.signing.envelope.publicKey);
    await initializeIntegrityHeadD1ForTests(mock.db,f.data.envelope.vaultId);
    expect(mock.statements.some(x=>x.sql.includes("sandbox_integrity_heads_v2"))).toBe(true);
    expect(mock.batches()).toBe(0);
  });

  it("accepts a correctly chained second record at signature and validation layer",async()=>{
    const f=await fixture(),mock=dbMock(f.signing.envelope.publicKey);
    const challenge=issueChallengeForTests(f.data.envelope.vaultId,"append",now);
    const proof=await signIntegrityAppendForTests(f.signing.privateKey,challenge,f.second);
    await appendIntegrityEntryD1ForTests(mock.db,challenge,f.second,proof,now+1);
    expect(mock.batches()).toBe(1);
    const head=await verifyD1IntegrityHistoryForTests([f.first,f.second],f.second.digest);
    expect(head.revision).toBe(2);
    expect(await decryptIntegrityEntryForTests(f.data.key,f.second)).toBe("Fictional entry 2");
  });

  it("rejects changed ciphertext, wrong signing key and wrong action before D1 writes",async()=>{
    const f=await fixture(),mock=dbMock(f.signing.envelope.publicKey);
    const challenge=issueChallengeForTests(f.data.envelope.vaultId,"append",now);
    const proof=await signIntegrityAppendForTests(f.signing.privateKey,challenge,f.first);
    const altered={...f.first,ciphertext:"AAAAAAAAAAAAAAAAAAAAAAAA"};
    await expect(appendIntegrityEntryD1ForTests(mock.db,challenge,altered,proof,now+1)).rejects.toThrow();
    const other=await createWrappedSigningCredentialForTests(generateRecoveryWords(),f.data.envelope.vaultId);
    const forged=await signIntegrityAppendForTests(other.privateKey,challenge,f.first);
    await expect(appendIntegrityEntryD1ForTests(mock.db,challenge,f.first,forged,now+1)).rejects.toThrow();
    expect(mock.batches()).toBe(0);
  });

  it("propagates D1 rejection and detects incomplete or rolled-back chains",async()=>{
    const f=await fixture(),mock=dbMock(f.signing.envelope.publicKey);
    const challenge=issueChallengeForTests(f.data.envelope.vaultId,"append",now);
    const proof=await signIntegrityAppendForTests(f.signing.privateKey,challenge,f.second);
    mock.fail();
    await expect(appendIntegrityEntryD1ForTests(mock.db,challenge,f.second,proof,now+1)).rejects.toThrow("continuity");
    await expect(verifyD1IntegrityHistoryForTests([f.second])).rejects.toThrow();
    await expect(verifyD1IntegrityHistoryForTests([f.first],f.second.digest)).rejects.toThrow();
  });
});
