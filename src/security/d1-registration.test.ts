import {describe,expect,it} from "vitest";
import {generateRecoveryWords} from "./recovery";
import {createWrappedVaultKeyForTests} from "./key-wrapping";
import {createWrappedSigningCredentialForTests} from "./signing-recovery";
import {deriveVaultLookupIdForTests} from "./recovery-bootstrap";
import {signChallengeForTests} from "./access-proof";
import {signRegistrationIntentForTests} from "./registration-intent";
import {
  issueRegistrationChallengeD1ForTests,registerVaultD1ForTests
} from "./d1-registration";
import type {PrototypeD1Database,PrototypeD1Statement} from "./d1-transaction";

const now=1_783_000_000_000;
async function fixture(){
  const phrase=generateRecoveryWords();
  const wrapped=await createWrappedVaultKeyForTests(phrase);
  const signing=await createWrappedSigningCredentialForTests(phrase,wrapped.envelope.vaultId);
  const lookupId=await deriveVaultLookupIdForTests(phrase);
  const backup={
    vaultId:wrapped.envelope.vaultId,
    wrappedDataKey:wrapped.envelope,
    wrappedSigningKey:signing.envelope,
    verificationKey:signing.envelope.publicKey
  };
  return {phrase,backup,lookupId,signing};
}
function recorder(){
  const sqls:Array<{sql:string;args:Array<string|number>}>=[];
  let batches=0;
  let rejected=false;
  let issued=1;
  const db:PrototypeD1Database={
    prepare(sql:string):PrototypeD1Statement{
      return {
        bind(...args:Array<string|number>):PrototypeD1Statement{
          sqls.push({sql,args});
          return this;
        },
        async first<T>():Promise<T|null>{return null;},
        async run(){return {meta:{changes:issued}};}
      };
    },
    async batch(statements:PrototypeD1Statement[]){
      expect(statements).toHaveLength(3);
      batches++;
      if(rejected)throw new Error("D1 rollback from unique constraint");
      return [{success:true},{success:true},{success:true}];
    }
  };
  return {
    db,sqls,batches:()=>batches,
    reject:()=>{rejected=true;},
    stopIssuing:()=>{issued=0;}
  };
}
async function signed(f:Awaited<ReturnType<typeof fixture>>,challenge:Awaited<ReturnType<typeof issueRegistrationChallengeD1ForTests>>){
  return {
    proof:await signChallengeForTests(f.signing.privateKey,challenge),
    intent:await signRegistrationIntentForTests(
      f.signing.privateKey,challenge,f.backup,f.lookupId
    )
  };
}
describe("isolated atomic D1 registration",()=>{
  it("creates pre-vault challenge and atomically inserts vault and v2 head",async()=>{
    const f=await fixture(),recorded=recorder();
    const challenge=await issueRegistrationChallengeD1ForTests(
      recorded.db,f.backup.vaultId,now
    );
    const {proof,intent}=await signed(f,challenge);
    await registerVaultD1ForTests(recorded.db,f.backup,f.lookupId,proof,intent,now+1);
    expect(recorded.batches()).toBe(1);
    expect(recorded.sqls.some(x=>x.sql.includes("sandbox_registration_challenges"))).toBe(true);
    expect(recorded.sqls.some(x=>x.sql.includes("INSERT INTO sandbox_vaults"))).toBe(true);
    expect(recorded.sqls.some(x=>x.sql.includes("sandbox_integrity_heads_v2"))).toBe(true);
    expect(JSON.stringify(recorded.sqls)).not.toContain(f.phrase);
  });
  it("rejects altered recovery locator and encrypted backup",async()=>{
    const f=await fixture(),recorded=recorder();
    const challenge=await issueRegistrationChallengeD1ForTests(
      recorded.db,f.backup.vaultId,now
    );
    const {proof,intent}=await signed(f,challenge);
    const other=await fixture();
    await expect(registerVaultD1ForTests(
      recorded.db,f.backup,other.lookupId,proof,intent,now+1
    )).rejects.toThrow("denied");
    await expect(registerVaultD1ForTests(
      recorded.db,{...f.backup,wrappedDataKey:{
        ...f.backup.wrappedDataKey,wrappedKey:"AAAAAAAA"
      }},f.lookupId,proof,intent,now+1
    )).rejects.toThrow("denied");
    expect(recorded.batches()).toBe(0);
  });
  it("rejects expired or wrongly signed registration and never writes",async()=>{
    const f=await fixture(),recorded=recorder(),other=await fixture();
    const challenge=await issueRegistrationChallengeD1ForTests(
      recorded.db,f.backup.vaultId,now
    );
    const {proof,intent}=await signed(f,challenge);
    const forged=await signChallengeForTests(other.signing.privateKey,challenge);
    await expect(registerVaultD1ForTests(
      recorded.db,f.backup,f.lookupId,forged,intent,now+1
    )).rejects.toThrow("denied");
    await expect(registerVaultD1ForTests(
      recorded.db,f.backup,f.lookupId,proof,intent,now+60_000
    )).rejects.toThrow();
    expect(recorded.batches()).toBe(0);
  });
  it("fails closed if challenge issuance inserts no row",async()=>{
    const f=await fixture(),recorded=recorder();
    recorded.stopIssuing();
    await expect(issueRegistrationChallengeD1ForTests(
      recorded.db,f.backup.vaultId,now
    )).rejects.toThrow("not saved");
  });
  it("propagates failed registration batch instead of claiming success",async()=>{
    const f=await fixture(),recorded=recorder();
    const challenge=await issueRegistrationChallengeD1ForTests(
      recorded.db,f.backup.vaultId,now
    );
    const {proof,intent}=await signed(f,challenge);
    recorded.reject();
    await expect(registerVaultD1ForTests(
      recorded.db,f.backup,f.lookupId,proof,intent,now+1
    )).rejects.toThrow("rollback");
  });
});
